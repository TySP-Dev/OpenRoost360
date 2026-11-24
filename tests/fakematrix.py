"""TEST TOOL ONLY: a minimal Matrix homeserver with the client-server calls OpenRoost uses: login, room alias lookup,
joining (sending to a room you haven't joined is refused, like a real server), members, room state, sending (plain and
encrypted), DMs, /sync (timeline, invites, to-device, key counts), and the end-to-end key endpoints (upload, query,
claim, cross-signing with password auth, signature upload, to-device). Cross-signing signatures are checked for real.
Records everything it receives. Not used by the app."""
import base64, json, threading, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BOT, BOT_PW, BOT_TOKEN = '@openroost:test.local', 'bot-password', 'syt_test_token'
SENT, TODEVICE, ROOMS, ENCRYPTED = [], [], {'#alerts:test.local': '!alerts:test.local'}, set()
MEMBERS = {'!alerts:test.local': {'@ty:test.local'}}
INVITES = {'!alerts:test.local': {BOT}}          # the bot is invited to the alert room and has to join it
TIMELINE, INBOX = [], []                         # room events (room, event) and to-device messages for the bot (device, event)
DEVICE_KEYS, OTKS, XSIGN, SIG_UPLOADS, LOGINS, FALLBACK, REPLENISHED = {}, {}, {}, [], [], {}, []
TOKENS = {BOT_TOKEN: BOT}


def canonical(o): return json.dumps(o, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
def unb64(s): return base64.b64decode(s + '=' * (-len(s) % 4))


def verify(pub_b64, obj, sig_b64):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    o = {k: v for k, v in obj.items() if k not in ('signatures', 'unsigned')}
    Ed25519PublicKey.from_public_bytes(unb64(pub_b64)).verify(unb64(sig_b64), canonical(o))


def post(room, sender, etype, content):
    """A family member's message in a room (shows up in the bot's /sync)."""
    TIMELINE.append((room, {'type': etype, 'sender': sender, 'content': content, 'event_id': f'$t{len(TIMELINE)}', 'origin_server_ts': int(time.time() * 1000)}))


def to_bot(device, sender, etype, content):
    INBOX.append((device, {'type': etype, 'sender': sender, 'content': content}))


def add_device(user, device, dk, otks):
    """Test receivers register their keys directly."""
    DEVICE_KEYS.setdefault(user, {})[device] = dk; OTKS.setdefault(user, {})[device] = dict(otks)


def run(port):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def handle(self):
            try: super().handle()
            except (BrokenPipeError, ConnectionResetError): pass      # a long poll the client gave up on

        def reply(self, code, obj):
            b = json.dumps(obj).encode(); self.send_response(code); self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)

        def body(self):
            n = int(self.headers.get('Content-Length') or 0); return json.loads(self.rfile.read(n) or b'{}')

        def who(self): return TOKENS.get((self.headers.get('Authorization') or '')[7:])

        def do_POST(self):
            b, p, u = self.body(), urllib.parse.urlsplit(self.path).path, self.who()
            if p == '/_matrix/client/v3/login':
                if b.get('identifier', {}).get('user') != BOT or b.get('password') != BOT_PW:
                    return self.reply(403, {'errcode': 'M_FORBIDDEN', 'error': 'Invalid password'})
                LOGINS.append(1); dev = f'BOTDEV{len(LOGINS)}'
                return self.reply(200, {'access_token': BOT_TOKEN, 'user_id': BOT, 'device_id': dev})
            if not u: return self.reply(401, {'errcode': 'M_MISSING_TOKEN'})
            if p.startswith('/_matrix/client/v3/join/'):
                room = urllib.parse.unquote(p.rsplit('/', 1)[1]); room = ROOMS.get(room, room)
                if u in MEMBERS.get(room, set()) or u in INVITES.get(room, set()):
                    MEMBERS.setdefault(room, set()).add(u); INVITES.get(room, set()).discard(u); return self.reply(200, {'room_id': room})
                return self.reply(403, {'errcode': 'M_FORBIDDEN', 'error': 'You are not invited to this room.'})
            if p == '/_matrix/client/v3/createRoom':
                rid = f'!dm{len(ROOMS)}:test.local'; ROOMS[rid] = rid; MEMBERS[rid] = {u, *b.get('invite', [])}
                if any(s.get('type') == 'm.room.encryption' for s in b.get('initial_state', [])): ENCRYPTED.add(rid)
                return self.reply(200, {'room_id': rid})
            if p == '/_matrix/client/v3/keys/upload':
                dk = b.get('device_keys')
                if dk:
                    did = dk['device_id']; verify(dk['keys'][f'ed25519:{did}'], dk, dk['signatures'][u][f'ed25519:{did}'])
                    DEVICE_KEYS.setdefault(u, {})[did] = dk
                    OTKS.setdefault(u, {}).setdefault(did, {}).update(b.get('one_time_keys') or {})
                elif b.get('one_time_keys') or b.get('fallback_keys'):
                    did = sorted(DEVICE_KEYS[u])[-1]
                    for kid, o in (b.get('one_time_keys') or {}).items():
                        verify(DEVICE_KEYS[u][did]['keys'][f'ed25519:{did}'], o, o['signatures'][u][f'ed25519:{did}'])
                    OTKS.setdefault(u, {}).setdefault(did, {}).update(b.get('one_time_keys') or {})
                    if b.get('fallback_keys'): FALLBACK[(u, did)] = b['fallback_keys']; REPLENISHED.append(len(b.get('one_time_keys') or {}))
                return self.reply(200, {'one_time_key_counts': {'signed_curve25519': len(b.get('one_time_keys') or {})}})
            if p == '/_matrix/client/v3/keys/query':
                users = b.get('device_keys', {})
                res = {'device_keys': {x: DEVICE_KEYS.get(x, {}) for x in users}, 'master_keys': {}, 'self_signing_keys': {}}
                for x in users:
                    if x in XSIGN: res['master_keys'][x] = XSIGN[x]['master_key']; res['self_signing_keys'][x] = XSIGN[x]['self_signing_key']
                return self.reply(200, res)
            if p == '/_matrix/client/v3/keys/device_signing/upload':
                auth = b.get('auth')
                if not auth: return self.reply(401, {'session': 'uia1', 'flows': [{'stages': ['m.login.password']}], 'params': {}})
                if auth.get('session') != 'uia1' or auth.get('password') != BOT_PW: return self.reply(401, {'errcode': 'M_FORBIDDEN', 'error': 'Invalid password', 'session': 'uia1'})
                mk = list(b['master_key']['keys'].values())[0]
                for k in ('self_signing_key', 'user_signing_key'): verify(mk, b[k], b[k]['signatures'][u][f'ed25519:{mk}'])
                XSIGN[u] = b; return self.reply(200, {})
            if p == '/_matrix/client/v3/keys/signatures/upload':
                failures = {}
                ssk = list(XSIGN[u]['self_signing_key']['keys'].values())[0] if u in XSIGN else None
                for did, obj in b.get(u, {}).items():
                    try:
                        verify(ssk, obj, obj['signatures'][u][f'ed25519:{ssk}'])
                        assert {k: v for k, v in obj.items() if k != 'signatures'} == {k: v for k, v in DEVICE_KEYS[u][did].items() if k != 'signatures'}
                        DEVICE_KEYS[u][did]['signatures'][u][f'ed25519:{ssk}'] = obj['signatures'][u][f'ed25519:{ssk}']
                        SIG_UPLOADS.append((u, did))
                    except Exception as e:
                        failures.setdefault(u, {})[did] = {'errcode': 'M_INVALID_SIGNATURE', 'error': str(e)}
                return self.reply(200, {'failures': failures})
            if p == '/_matrix/client/v3/keys/claim':
                out = {}
                for x, devs in b.get('one_time_keys', {}).items():
                    for did in devs:
                        pool = OTKS.get(x, {}).get(did, {})
                        if pool: kid = next(iter(pool)); out.setdefault(x, {})[did] = {kid: pool.pop(kid)}
                return self.reply(200, {'one_time_keys': out, 'failures': {}})
            self.reply(404, {'errcode': 'M_UNRECOGNIZED'})

        def do_GET(self):
            p = urllib.parse.urlsplit(self.path).path
            u = self.who()
            if not u: return self.reply(401, {'errcode': 'M_MISSING_TOKEN'})
            if p == '/_matrix/client/v3/sync':
                q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                since = q.get('since', [None])[0]; t0, ti = (int(x) for x in since[1:].split('_')) if since else (0, 0)
                device = next((d for d in DEVICE_KEYS.get(u, {}) if d.startswith('BOTDEV')), None)
                end = time.time() + min(int(q.get('timeout', ['0'])[0]) / 1000, 1.0)
                while since and len(TIMELINE) == t0 and len(INBOX) == ti and time.time() < end: time.sleep(0.05)
                tl, ib = list(TIMELINE), list(INBOX)
                join = {}
                for room, ev in tl[t0:] if since else []:
                    if u in MEMBERS.get(room, set()): join.setdefault(room, {'timeline': {'events': []}})['timeline']['events'].append(ev)
                return self.reply(200, {'next_batch': f's{len(tl)}_{len(ib)}',
                                        'rooms': {'join': join, 'invite': {r: {} for r, us in INVITES.items() if u in us}},
                                        'to_device': {'events': [ev for d, ev in ib[ti:] if d == device]},
                                        'device_one_time_keys_count': {'signed_curve25519': len(OTKS.get(u, {}).get(device, {}))},
                                        'device_unused_fallback_key_types': ['signed_curve25519'] if FALLBACK.get((u, device)) else []})
            if p.startswith('/_matrix/client/v3/directory/room/'):
                alias = urllib.parse.unquote(p.rsplit('/', 1)[1])
                return self.reply(200, {'room_id': ROOMS[alias]}) if alias in ROOMS else self.reply(404, {'errcode': 'M_NOT_FOUND'})
            if '/rooms/' in p:
                room, rest = urllib.parse.unquote(p.split('/rooms/')[1].split('/')[0]), p.split('/rooms/')[1].split('/', 1)[1]
                if rest == 'state/m.room.encryption':
                    return self.reply(200, {'algorithm': 'm.megolm.v1.aes-sha2'}) if room in ENCRYPTED else self.reply(404, {'errcode': 'M_NOT_FOUND'})
                if rest == 'members':
                    return self.reply(200, {'chunk': [{'type': 'm.room.member', 'state_key': m, 'content': {'membership': 'join'}} for m in sorted(MEMBERS.get(room, ()))]})
            self.reply(404, {})

        def do_PUT(self):
            p, u = urllib.parse.urlsplit(self.path).path, self.who()
            if not u: return self.reply(401, {'errcode': 'M_UNKNOWN_TOKEN'})
            b = self.body()
            if '/sendToDevice/' in p:
                TODEVICE.append({'type': p.split('/sendToDevice/')[1].split('/')[0], 'sender': u, 'messages': b.get('messages', {})}); return self.reply(200, {})
            if '/send/' in p:
                room = urllib.parse.unquote(p.split('/rooms/')[1].split('/')[0]); etype = p.split('/send/')[1].split('/')[0]
                if u not in MEMBERS.get(room, set()): return self.reply(403, {'errcode': 'M_FORBIDDEN', 'error': f'User {u} not in room {room}'})
                SENT.append({'room': room, 'type': etype, **b}); post(room, u, etype, b); return self.reply(200, {'event_id': f'$e{len(SENT)}'})
            self.reply(404, {})

    srv = ThreadingHTTPServer(('127.0.0.1', port), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv
