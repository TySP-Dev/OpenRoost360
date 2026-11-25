"""Notifications: email, ntfy push, signed webhooks and Matrix, routed by the settings.

Routing (Settings -> Notifications -> What goes where): routing[kind] = [email, push, matrix, webhook].
Contacts get messages by tier: distress (panic, hostage PIN, fire) by email and Matrix DM, ignoring quiet
hours; alarms (intrusion, leak); info (everything else). Urgent alerts repeat every repeatMin minutes
until someone acknowledges them in the app.
"""
import datetime, email.message, hashlib, hmac, json, os, queue, re, smtplib, ssl, threading, time, urllib.parse, urllib.request, uuid

from . import emails, mxcrypto

URGENT = ('intrusion', 'fire', 'panic', 'duress', 'leak')
TIER = {'panic': 'distress', 'duress': 'distress', 'fire': 'distress', 'intrusion': 'alarms', 'leak': 'alarms'}
ROUTE_ALIAS = {'missing': 'lowbat'}
NTFY_PRIO = {'crit': 'urgent', 'warn': 'high', 'info': 'default'}
TIMEOUT = 10


class NotifyError(Exception):
    pass


class _KeepMethod(urllib.request.HTTPRedirectHandler):
    """urllib turns a redirected POST/PUT into a GET without its body, which servers answer with a confusing
    "method not supported". Refuse instead, naming where the server wanted to send us."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if req.get_method() in ('GET', 'HEAD'): return super().redirect_request(req, fp, code, msg, headers, newurl)
        raise NotifyError(f'{req.full_url.split("?")[0]} redirects to {newurl.split("?")[0]}: use that address instead')


_opener = urllib.request.build_opener(_KeepMethod)


def _http(method, url, body=None, headers=None):
    data = body if isinstance(body, (bytes, type(None))) else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method, headers={'User-Agent': 'OpenRoost360', **(headers or {})})
    if data is not None and 'Content-Type' not in req.headers: req.add_header('Content-Type', 'application/json')
    try:
        with _opener.open(req, timeout=TIMEOUT) as r:
            raw = r.read(); return r.status, (json.loads(raw) if raw[:1] in (b'{', b'[') else raw.decode(errors='replace'))
    except urllib.error.HTTPError as e:
        raw = e.read()[:500].decode(errors='replace')
        raise NotifyError(f'{url.split("?")[0]} answered {e.code}: {raw}') from None
    except (urllib.error.URLError, OSError) as e:
        raise NotifyError(f'Couldn\'t reach {urllib.parse.urlsplit(url).netloc}: {getattr(e, "reason", e)}') from None


def in_quiet_hours(spec, tzname):
    m = re.fullmatch(r'\s*(\d{1,2}):(\d{2})\s*[–-]\s*(\d{1,2}):(\d{2})\s*', spec or '')
    if not m: return False
    try:
        from zoneinfo import ZoneInfo
        now = datetime.datetime.now(ZoneInfo(tzname)) if tzname else datetime.datetime.now()
    except Exception:
        now = datetime.datetime.now()
    a, b, t = int(m[1]) * 60 + int(m[2]), int(m[3]) * 60 + int(m[4]), now.hour * 60 + now.minute
    return (a <= t < b) if a < b else (t >= a or t < b)


class Notifier:
    def __init__(self, store, log=print):
        self.store, self.log = store, log
        self.crypto = mxcrypto.MatrixCrypto(store, log)
        self.esc = None                           # emergency countdown (attach())
        self._joined = set()
        self.q = queue.Queue()
        self.repeats = {}                         # kind -> next send time, count
        threading.Thread(target=self._worker, daemon=True, name='notify').start()
        threading.Thread(target=self._repeater, daemon=True, name='notify-repeat').start()

    def attach(self, bus):
        """Start the emergency countdown and the Matrix reader (needs the live-update bus)."""
        from .escalate import Escalations
        from .mxsync import MatrixSync
        self.esc = Escalations(self.store, self, bus, self.log)
        self.sync = MatrixSync(self.store, self, self.esc.on_matrix, self.log)

    # ---------------------------------------------------------------- entry points
    def dispatch(self, kind, title, detail, sev='info'):
        if self.esc and self.esc.applies(kind, self.store.get_settings()):
            try: self.esc.start(kind, title, detail, sev)
            except Exception as e: self.log(f'notify: countdown failed, telling contacts now: {e!r}')
        self.q.put((kind, title, detail, sev, False))
        if kind in URGENT:
            mins = int(self.store.get_settings().get('repeatMin') or 0)
            if mins: self.repeats[kind] = {'next': time.time() + mins * 60, 'count': 0, 'title': title, 'detail': detail, 'sev': sev}

    def acknowledged(self, kind):
        self.repeats.pop(kind, None)

    def test(self, channel, to=None):
        """Send a test through one channel right away; raises NotifyError with a readable reason."""
        st = self.store.get_settings(); site = st.get('siteName') or 'Home'
        title, detail = f'[{site}] Test from OpenRoost360', 'If you can read this, alerts will reach you here.'
        if channel == 'email':
            rcpts = [to] if to else self._email_list(st)
            if not rcpts: raise NotifyError('Add at least one recipient first.')
            text, html = emails.test(site)
            return self.send_email(st, rcpts, title, text, html)
        if channel == 'ntfy': return self.send_ntfy(st, title, detail, 'info')
        if channel == 'webhook': return self.send_webhook(st, 'test', title, detail, 'info')
        if channel == 'matrix': return self.send_matrix(st, title, detail)
        if channel == 'matrixdm':
            if not to or not re.fullmatch(r'@[^:\s]+:[^\s]+', to): raise NotifyError('Enter a Matrix ID like @name:example.org')
            room, how = self.send_matrix_dm(st, to, f'{title}\nThis is a direct message test: emergency contacts get distress alerts like this.', report=True)
            return f'Direct message sent to {to}' + (' (end-to-end encrypted)' if how == 'encrypted' else '') + '. They may need to accept the invite first.'
        raise NotifyError('Unknown channel')

    # ---------------------------------------------------------------- workers
    def _worker(self):
        while True:
            kind, title, detail, sev, repeat = self.q.get()
            try: self._deliver(kind, title, detail, sev, repeat)
            except Exception as e: self.log(f'notify: {kind} failed: {e!r}')

    def _repeater(self):
        while True:
            time.sleep(15)
            now, mins = time.time(), int(self.store.get_settings().get('repeatMin') or 0)
            for kind, r in list(self.repeats.items()):
                if not mins or r['count'] >= 12: self.repeats.pop(kind, None); continue
                if r['next'] <= now:
                    r['count'] += 1; r['next'] = now + mins * 60
                    self.q.put((kind, r['title'] + ' (still active)', r['detail'], r['sev'], True))

    def _deliver(self, kind, title, detail, sev, repeat):
        st = self.store.get_settings()
        site = st.get('siteName') or 'Home'
        subject = (st.get('smtpSubject') or '[{site}] {alert} — {time}').replace('{site}', site).replace('{alert}', title) \
            .replace('{sensor}', detail).replace('{time}', time.strftime('%H:%M'))
        urgent = kind in URGENT
        quiet = not urgent and in_quiet_hours(st.get('quiet'), st.get('tz'))
        route = (st.get('routing') or {}).get(ROUTE_ALIAS.get(kind, kind)) or [1, 1, 1, 1] if urgent else (st.get('routing') or {}).get(ROUTE_ALIAS.get(kind, kind), [0, 0, 0, 0])
        errors = []

        def attempt(fn, *a):
            try: fn(*a)
            except NotifyError as e: errors.append(str(e))

        link = (st.get('publicUrl') or '').rstrip('/') or None
        when = time.strftime('%A %d %B, %H:%M')
        text, html = emails.alert(site, kind, title, detail, sev, when, link)
        if not quiet:
            if route[0] and self._email_ready(st): attempt(self.send_email, st, self._email_list(st), subject, text, html)
            if route[1] and st.get('ntfyUrl'): attempt(self.send_ntfy, st, f'[{site}] {title}', detail, sev)
            counting = bool(self.esc and not repeat and self.esc.pending(kind) and (st.get('esc') or {}).get('room', True))
            if route[2] and st.get('mxOn') and st.get('mxHs') and not counting:   # a countdown already went to the room
                attempt(self.send_matrix, st, f'{title}: {detail}', None, urgent)
            if route[3] and st.get('hookUrl'): attempt(self.send_webhook, st, kind, title, detail, sev)
        if not self.esc or self.esc.contacts_allowed(kind):           # a pending or cancelled countdown holds them back
            errors += self._contacts(st, kind, title, detail, sev, quiet)
        if errors:
            self.log('notify: ' + ' | '.join(errors))
            self.store.add_event(time.time(), 'system', 'warn', 'Notification failed', '; '.join(errors)[:400])

    def _contacts(self, st, kind, title, detail, sev, quiet=False, told=None):
        """Family & emergency contacts by tier. Returns error strings; `told` collects (name, [channels]) that worked."""
        site = st.get('siteName') or 'Home'; errors = []; told = told if told is not None else []
        subject = (st.get('smtpSubject') or '[{site}] {alert} — {time}').replace('{site}', site).replace('{alert}', title) \
            .replace('{sensor}', detail).replace('{time}', time.strftime('%H:%M'))
        when = time.strftime('%A %d %B, %H:%M')
        tier = TIER.get(kind, 'info')
        for c in st.get('contacts') or []:
            if not (c.get('tiers') or {}).get(tier): continue
            if quiet and tier != 'distress': continue
            ok = []
            try:
                if c.get('email') and self._email_ready(st):
                    ct, ch = emails.alert(site, kind, title, detail, sev, when, None, f'You get this because {site} lists you as an emergency contact.')
                    self.send_email(st, [c['email']], subject, ct, ch); ok.append('email')
            except NotifyError as e: errors.append(f"{c.get('name') or c.get('email')}: {e}")
            try:
                if c.get('mx') and st.get('mxHs') and (tier == 'distress' or kind in ('intrusion',)): self.send_matrix_dm(st, c['mx'], f'{title}: {detail}'); ok.append('Matrix')
            except NotifyError as e: errors.append(f"{c.get('name') or c.get('mx')}: {e}")
            if ok: told.append((c.get('name') or c.get('email') or c.get('mx'), ok))
        return errors

    def send_contacts(self, kind, title, detail, sev='crit'):
        """The emergency countdown ran out: tell the contacts now. Returns (who was told, errors)."""
        told = []; errors = self._contacts(self.store.get_settings(), kind, title, detail, sev, told=told)
        return told, errors

    # ---------------------------------------------------------------- channels
    def _email_ready(self, st):
        m = st.get('mail') or {}
        return m.get('mode') in ('account', 'relay-existing', 'relay-start')

    @staticmethod
    def _email_list(st):
        return [x for x in re.split(r'\s+', st.get('smtpTo') or '') if '@' in x]

    def send_email(self, st, rcpts, subject, body, html=None):
        m = st.get('mail') or {}
        if m.get('mode') == 'account':
            prov = {'gmail': ('smtp.gmail.com', 587, 'starttls'), 'icloud': ('smtp.mail.me.com', 587, 'starttls')}.get(m.get('prov'))
            host, port, sec = prov if prov else (m.get('host'), int(m.get('port') or 587), m.get('sec') or 'starttls')
            user, pw = m.get('user'), self.store.get_secret('mail.pass')
        elif m.get('mode') == 'relay-existing':
            host, port, sec = m.get('host'), int(m.get('port') or 25), m.get('sec') or 'none'
            user, pw = (m.get('user'), self.store.get_secret('mail.pass')) if m.get('auth') else (None, None)
        elif m.get('mode') == 'relay-start':
            relay = os.environ.get('OPENROOST_BUNDLED_RELAY', '')
            if not relay: raise NotifyError('OpenRoost\'s mail relay isn\'t running. Start it with: docker compose --profile mailrelay up -d')
            host, _, port = relay.rpartition(':'); port, sec, user, pw = int(port), 'none', None, None
        else:
            raise NotifyError('Email is off.')
        if not host: raise NotifyError('No mail server set.')
        sender = m.get('from') or m.get('user')
        if not sender: raise NotifyError('No From address set.')
        msg = email.message.EmailMessage()
        msg['From'], msg['To'], msg['Subject'] = sender, ', '.join(rcpts), subject
        msg['Message-ID'] = f'<{uuid.uuid4()}@openroost360>'
        msg.set_content(body)
        if html: msg.add_alternative(html, subtype='html')
        ctx = ssl.create_default_context()
        try:
            if sec == 'tls': s = smtplib.SMTP_SSL(host, port, timeout=TIMEOUT, context=ctx)
            else:
                s = smtplib.SMTP(host, port, timeout=TIMEOUT)
                if sec == 'starttls': s.starttls(context=ctx)
            with s:
                if user and pw: s.login(user, pw)
                refused = s.send_message(msg)
            if refused: raise NotifyError(f'Some recipients were refused: {", ".join(refused)}')
            return f'Accepted by {host}:{port}'
        except smtplib.SMTPAuthenticationError:
            raise NotifyError(f'{host} refused the sign-in. Check the username and app password.') from None
        except (smtplib.SMTPException, OSError, ssl.SSLError) as e:
            raise NotifyError(f'{host}:{port}: {e}') from None

    def send_ntfy(self, st, title, body, sev):
        prio = st.get('ntfyPrio') or NTFY_PRIO.get(sev, 'default')
        if sev == 'crit': prio = 'urgent'
        _http('POST', st['ntfyUrl'], body.encode(), {'Title': title.encode('ascii', 'replace').decode(), 'Priority': str(prio), 'Tags': 'rotating_light' if sev == 'crit' else 'house', 'Content-Type': 'text/plain'})
        return 'Sent to ntfy'

    def send_webhook(self, st, kind, title, detail, sev):
        body = json.dumps({'event': kind, 'title': title, 'detail': detail, 'severity': sev, 't': int(time.time()), 'site': st.get('siteName') or 'Home'}, separators=(',', ':')).encode()
        h = {'Content-Type': 'application/json'}
        secret = self.store.get_secret('hookSecret')
        if secret: h['X-OpenRoost-Signature'] = 'sha256=' + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        _http('POST', st['hookUrl'], body, h)
        return 'Webhook accepted'

    # ---- Matrix (client-server API). Encrypted rooms are detected and handled by mxcrypto.
    def _mx(self, st):
        hs, tok = (st.get('mxHs') or '').rstrip('/'), self.store.get_secret('mxToken')
        if not hs or not tok: raise NotifyError('Set the homeserver and sign the bot in first.')
        return hs, {'Authorization': 'Bearer ' + tok}

    ROOMS_FILTER = json.dumps({'presence': {'not_types': ['*']}, 'account_data': {'not_types': ['*']},
                               'room': {'timeline': {'limit': 0}, 'ephemeral': {'not_types': ['*']}, 'account_data': {'not_types': ['*']},
                                        'state': {'types': ['m.room.name', 'm.room.canonical_alias', 'm.room.encryption', 'm.room.member'], 'lazy_load_members': True}}},
                              separators=(',', ':'))

    def mx_rooms(self, st=None, hs=None, tok=None):
        """The rooms the bot is in or invited to: [{id, name, alias, encrypted, invited}]. One filtered /sync."""
        if hs is None: hs, h = self._mx(st or self.store.get_settings())
        else: h = {'Authorization': 'Bearer ' + tok}
        me = (st or self.store.get_settings()).get('mxUser') or ''
        _, r = _http('GET', f'{hs}/_matrix/client/v3/sync?' + urllib.parse.urlencode({'filter': self.ROOMS_FILTER, 'timeout': '0'}), headers=h)
        out = []
        for kind, key in (('join', 'state'), ('invite', 'invite_state')):
            for rid, room in ((r.get('rooms') or {}).get(kind) or {}).items():
                ev = (room.get(key) or {}).get('events', [])
                get = lambda t: next((e.get('content') or {} for e in ev if e.get('type') == t), {})
                name, alias = get('m.room.name').get('name'), get('m.room.canonical_alias').get('alias')
                if not name:                                    # unnamed (e.g. a DM): name it after the other people
                    others = [e.get('content', {}).get('displayname') or e.get('state_key') for e in ev
                              if e.get('type') == 'm.room.member' and e.get('state_key') != me and (e.get('content') or {}).get('membership') in ('join', 'invite')]
                    name = ', '.join(o for o in others if o)[:80] or None
                out.append({'id': rid, 'name': name or alias or rid, 'alias': alias, 'encrypted': bool(get('m.room.encryption')), 'invited': kind == 'invite'})
        return sorted(out, key=lambda x: (x['invited'], (x['name'] or '').lower()))

    def mx_room_id(self, st, hs, h, join=True):
        room = (st.get('mxRoom') or '').strip()
        if not room: raise NotifyError('No Matrix room set.')
        if room.startswith('#'):
            code, r = mxcrypto.req('GET', f'{hs}/_matrix/client/v3/directory/room/{urllib.parse.quote(room)}', None, h)
            if code == 404:
                raise NotifyError(f'No room has the address {room}. A room\'s name isn\'t an address: pick the room from the list '
                                  '(Choose a room), or give it a published address in Element (Room settings → General).')
            if code >= 300: raise NotifyError(f'Looking up {room} failed ({r.get("errcode", code)}: {r.get("error", "")})')
            room = r['room_id']
        elif not room.startswith('!'):                          # a room name: find it among the bot's rooms
            hits = [x for x in self.mx_rooms(st, hs, h['Authorization'][7:]) if (x['name'] or '').lower() == room.lower()]
            if len(hits) != 1:
                raise NotifyError(f'The bot isn\'t in or invited to a room called “{room}”. Invite it first, then pick the room from the list.'
                                  if not hits else f'The bot is in {len(hits)} rooms called “{room}”: pick one from the list.')
            room = hits[0]['id']
        if join: self.mx_join(hs, h, room)
        return room

    def mx_join(self, hs, h, room):
        """Join (or accept the invite to) a room once; already being in it is fine."""
        if room in self._joined: return
        code, r = mxcrypto.req('POST', f'{hs}/_matrix/client/v3/join/{urllib.parse.quote(room)}', {}, h)
        if code >= 300:
            raise NotifyError(f'The bot couldn\'t join {room} ({r.get("errcode", code)}). Invite it to the room first.')
        self._joined.add(room)

    _mx_room = mx_room_id

    def _mx_send(self, hs, h, room, text):
        content = {'msgtype': 'm.text', 'body': text}
        try:
            if self.crypto.room_encrypted(hs, h, room):
                self.crypto.send(hs, h, room, content); return 'encrypted'
        except mxcrypto.CryptoError as e:
            raise NotifyError(str(e)) from None
        _http('PUT', f'{hs}/_matrix/client/v3/rooms/{urllib.parse.quote(room)}/send/m.room.message/{uuid.uuid4().hex}', content, h)
        return 'plain'

    def send_matrix(self, st, title, detail=None, mention=False):
        hs, h = self._mx(st)
        room = self._mx_room(st, hs, h)
        text = title if detail is None else f'{title}\n{detail}'
        if mention and st.get('mxMention'): text = '@room ' + text
        how = self._mx_send(hs, h, room, text)
        return 'Sent to the Matrix room' + (' (end-to-end encrypted)' if how == 'encrypted' else '')

    def send_matrix_text(self, st, text, room=None):
        """Send plain text to the household room (or a given room). Returns the room id."""
        hs, h = self._mx(st)
        room = room or self.mx_room_id(st, hs, h)
        self._mx_send(hs, h, room, text); return room

    def send_matrix_dm(self, st, mxid, text, report=False):
        hs, h = self._mx(st)
        dms = self.store.kv('mxdm', {})
        room = dms.get(mxid)
        if room:                                              # the old DM may be gone (they left it): start a new one
            code, r = mxcrypto.req('GET', f'{hs}/_matrix/client/v3/rooms/{urllib.parse.quote(room)}/members', None, h)
            members = {e.get('state_key'): (e.get('content') or {}).get('membership') for e in r.get('chunk', [])} if code < 300 else {}
            if code >= 300 or members.get(mxid) not in ('join', 'invite'):
                dms.pop(mxid, None); self.store.set_kv('mxdm', dms); room = None
        if not room:
            body = {'invite': [mxid], 'is_direct': True, 'preset': 'trusted_private_chat'}
            if st.get('mxE2ee', True) and mxcrypto.available() and self.crypto.status().get('ready'):
                body['initial_state'] = [{'type': 'm.room.encryption', 'state_key': '', 'content': {'algorithm': mxcrypto.MEGOLM}}]
            _, r = _http('POST', f'{hs}/_matrix/client/v3/createRoom', body, h)
            room = r['room_id']; dms[mxid] = room; self.store.set_kv('mxdm', dms)
            if 'initial_state' in body: self.crypto.mark_encrypted(room)
        how = self._mx_send(hs, h, room, text)
        return (room, how) if report else room

    @staticmethod
    def matrix_base(hs):
        """The homeserver's client API address. People type their server name (https://example.org), but the server
        often lives elsewhere (https://matrix.example.org), announced in /.well-known/matrix/client (Matrix spec,
        client discovery)."""
        hs = (hs or '').strip().rstrip('/')
        if hs and '://' not in hs: hs = 'https://' + hs
        if not re.match(r'^https?://[^/\s]+', hs): raise NotifyError('Enter the homeserver as a web address, e.g. https://matrix.example.org')
        root = '/'.join(hs.split('/')[:3])
        try:
            _, wk = _http('GET', root + '/.well-known/matrix/client')
            base = ((wk or {}).get('m.homeserver') or {}).get('base_url') if isinstance(wk, dict) else None
            if base and re.match(r'^https?://', base): hs = base.rstrip('/')
        except NotifyError: pass                                  # no delegation: the address is the homeserver itself
        try: _http('GET', hs + '/_matrix/client/versions')
        except NotifyError as e:
            if 'answered' not in str(e): raise                    # unreachable; any HTTP answer means it's there
        return hs

    def matrix_login(self, hs, user, password):
        """Sign the bot in (a new device) and set up its encryption keys. Returns (access token, note or None, the
        homeserver's real address). The password is used here only (and for cross-signing) and never stored."""
        hs = self.matrix_base(hs)
        try: _, flows = _http('GET', f'{hs}/_matrix/client/v3/login')
        except NotifyError: flows = {}
        types = [f.get('type') for f in (flows or {}).get('flows', [])] if isinstance(flows, dict) else []
        if types and 'm.login.password' not in types:
            raise NotifyError(f'{hs} doesn\'t allow password sign-in for bots (it offers {", ".join(types)}).')
        try:
            _, r = _http('POST', f'{hs}/_matrix/client/v3/login', {'type': 'm.login.password', 'identifier': {'type': 'm.id.user', 'user': user},
                                                                    'password': password, 'initial_device_display_name': 'OpenRoost360'})
        except NotifyError as e:
            if 'M_FORBIDDEN' in str(e):
                why = re.search(r'"error"\s*:\s*"([^"]{1,200})"', str(e))
                raise NotifyError(f'The homeserver refused the bot\'s user name or password{": " + why.group(1) if why else "."}') from None
            raise
        tok, note = r['access_token'], None
        self.store.set_kv('mxdm', {})                       # direct-message rooms were the old device's; start fresh
        if not mxcrypto.available():
            self.crypto.forget(); note = 'Encrypted rooms need vodozemac on this server (included in the Docker image).'
        else:
            try: note = self.crypto.setup(hs, tok, r.get('user_id') or user, r['device_id'], password)
            except mxcrypto.CryptoError as e:
                self.crypto.forget(); note = f'Signed in, but encryption couldn\'t be set up: {e}. Unencrypted rooms still work.'
        return tok, note, hs
