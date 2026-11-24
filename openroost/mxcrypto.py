"""Matrix end-to-end encryption for the alert bot (send-only), on vodozemac: Matrix.org's audited Rust
implementation of Olm and Megolm, the same one Element uses. OpenRoost does none of the cryptography itself.

What it does:
* When the bot signs in: creates an Olm account for the bot's new device, uploads its device keys and one-time
  keys, and sets up cross-signing (or re-uses the bot's own cross-signing keys) so the device is verified by its
  own account. Clients that hide messages from unverified devices therefore still show the bot's.
* Sending to an encrypted room: one Megolm session per room, rotated after 100 messages, a week, or when someone
  who had the key leaves. The key goes to every device of every joined or invited member over Olm (to-device
  messages); then the message itself is Megolm-encrypted.
* Devices are pinned on first sight: if a device's signing key changes, it gets no more keys (logged).

* Reading replies (for the emergency countdown, "N" to cancel): decrypts Olm to-device messages to the bot, keeps the
  Megolm room keys they carry (only from devices whose keys check out against their account), and decrypts room
  messages with them. Keeps one-time keys and a fallback key topped up so phones can always start a session.

State (Olm account, sessions, cross-signing keys) is one AES-256-GCM secret, "mxCrypto", so backups and master-key
rotation cover it. Not handled: key backup, interactive verification.
"""
import base64, json, secrets, threading, time, urllib.parse, urllib.request, uuid

try:
    import vodozemac as vz
except ImportError:  # optional: without it, encrypted rooms are reported as unsupported
    vz = None

OLM, MEGOLM = 'm.olm.v1.curve25519-aes-sha2', 'm.megolm.v1.aes-sha2'
ROTATE_MSGS, ROTATE_SECS = 100, 7 * 86400
OTK_COUNT = 20
TIMEOUT = 15


class CryptoError(Exception):
    pass


def available():
    return vz is not None


def canonical(o):
    return json.dumps(o, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def b64(b):
    return base64.b64encode(b).decode().rstrip('=')


def unb64(s):
    return base64.b64decode(s + '=' * (-len(s) % 4))


def signable(o):
    return {k: v for k, v in o.items() if k not in ('signatures', 'unsigned')}


def req(method, url, body=None, headers=None, timeout=TIMEOUT):
    """(status, json) — HTTP errors are returned, not raised, so callers can read Matrix's errcode."""
    data = None if body is None else json.dumps(body).encode()
    r = urllib.request.Request(url, data=data, method=method, headers={'User-Agent': 'OpenRoost360', 'Content-Type': 'application/json', **(headers or {})})
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            raw = resp.read(); return resp.status, (json.loads(raw) if raw[:1] == b'{' else {})
    except urllib.error.HTTPError as e:
        raw = e.read()[:2000]
        try: return e.code, json.loads(raw)
        except ValueError: return e.code, {'error': raw.decode(errors='replace')}
    except (urllib.error.URLError, OSError) as e:
        raise CryptoError(f'Couldn\'t reach {urllib.parse.urlsplit(url).netloc}: {getattr(e, "reason", e)}') from None


def ok(method, url, body=None, headers=None):
    code, js = req(method, url, body, headers)
    if code >= 300: raise CryptoError(f'{url.split("/_matrix/")[-1].split("?")[0]} answered {code}: {js.get("errcode", "")} {js.get("error", "")}'.strip())
    return js


class MatrixCrypto:
    def __init__(self, store, log=print):
        self.store, self.log, self.lock = store, log, threading.RLock()
        self._encrypted = {}                                    # room -> (encrypted?, checked at)

    # ---- state
    def _load(self):
        raw = self.store.get_secret('mxCrypto'); return json.loads(raw) if raw else None

    def _save(self, s):
        self.store.set_secret('mxCrypto', json.dumps(s, separators=(',', ':')))

    def status(self):
        s = self._load()
        if not available(): return {'available': False}
        if not s: return {'available': True, 'ready': False}
        acct = vz.Account.from_pickle(s['account'], unb64(s['pk']))
        return {'available': True, 'ready': True, 'device': s['device'], 'crossSigned': bool(s.get('crossSigned')),
                'fingerprint': acct.ed25519_key.to_base64(), 'rooms': len(s['groups']), 'devices': len(s['devices'])}

    def forget(self):
        with self.lock: self.store.set_secret('mxCrypto', None); self._encrypted.clear()

    # ---- sign-in: new device keys + cross-signing
    def setup(self, hs, token, user_id, device_id, password=None):
        """Called right after the bot signs in (a new device). Returns a note if cross-signing couldn't be set up."""
        if not available(): raise CryptoError('Encryption support (vodozemac) isn\'t installed on this server.')
        hs = hs.rstrip('/'); h = {'Authorization': 'Bearer ' + token}
        with self.lock:
            old = self._load() or {}
            pk = secrets.token_bytes(32); acct = vz.Account()
            dk = {'user_id': user_id, 'device_id': device_id, 'algorithms': [OLM, MEGOLM],
                  'keys': {f'curve25519:{device_id}': acct.curve25519_key.to_base64(), f'ed25519:{device_id}': acct.ed25519_key.to_base64()}}
            dk['signatures'] = {user_id: {f'ed25519:{device_id}': acct.sign(canonical(dk)).to_base64()}}
            acct.generate_one_time_keys(OTK_COUNT)
            otks = {}
            for kid, key in acct.one_time_keys.items():
                o = {'key': key.to_base64()}
                o['signatures'] = {user_id: {f'ed25519:{device_id}': acct.sign(canonical(o)).to_base64()}}
                otks[f'signed_curve25519:{kid}'] = o
            ok('POST', f'{hs}/_matrix/client/v3/keys/upload', {'device_keys': dk, 'one_time_keys': otks}, h)
            acct.mark_keys_as_published()
            s = {'user': user_id, 'device': device_id, 'pk': b64(pk), 'account': acct.pickle(pk), 'dk': dk,
                 'olm': {}, 'groups': {}, 'devices': {}, 'xsign': old.get('xsign') if old.get('user') == user_id else None, 'crossSigned': False}
            self._save(s); self._encrypted.clear()
            note = None
            try:
                self._cross_sign(hs, h, s, password); s['crossSigned'] = True
            except CryptoError as e:
                note = f'Encryption is set up, but cross-signing isn\'t ({e}). Element may mark the bot\'s messages as from an unverified device.'
            self._save(s)
            return note

    def _cross_sign(self, hs, h, s, password):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        u = s['user']
        load = lambda x: Ed25519PrivateKey.from_private_bytes(unb64(x))
        pub = lambda k: b64(k.public_key().public_bytes_raw())
        sign = lambda k, o: b64(k.sign(canonical(signable(o))))
        r = ok('POST', f'{hs}/_matrix/client/v3/keys/query', {'device_keys': {u: []}}, h)
        on_server = list(((r.get('master_keys') or {}).get(u) or {}).get('keys', {}).values())
        x = s.get('xsign')
        if x and on_server == [pub(load(x['master']))]:
            ssk = load(x['self'])                               # the bot's cross-signing keys are still current: just sign the new device
        else:
            if not password: raise CryptoError('the bot\'s password is needed to set up cross-signing')
            msk, ssk, usk = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
            key = lambda k, usage: {'user_id': u, 'usage': [usage], 'keys': {f'ed25519:{pub(k)}': pub(k)}}
            mk, sk, uk = key(msk, 'master'), key(ssk, 'self_signing'), key(usk, 'user_signing')
            sk['signatures'] = {u: {f'ed25519:{pub(msk)}': sign(msk, sk)}}
            uk['signatures'] = {u: {f'ed25519:{pub(msk)}': sign(msk, uk)}}
            body = {'master_key': mk, 'self_signing_key': sk, 'user_signing_key': uk}
            url = f'{hs}/_matrix/client/v3/keys/device_signing/upload'
            code, js = req('POST', url, body, h)
            if code == 401 and 'session' in js:                 # user-interactive auth: the bot's password
                body['auth'] = {'type': 'm.login.password', 'identifier': {'type': 'm.id.user', 'user': u}, 'password': password, 'session': js['session']}
                code, js = req('POST', url, body, h)
            if code >= 300: raise CryptoError(f'uploading cross-signing keys answered {code}: {js.get("error", "")}')
            s['xsign'] = {'master': b64(msk.private_bytes_raw()), 'self': b64(ssk.private_bytes_raw()), 'user': b64(usk.private_bytes_raw())}
        signed = signable(s['dk']); signed['signatures'] = {u: {f'ed25519:{pub(ssk)}': sign(ssk, s['dk'])}}
        r = ok('POST', f'{hs}/_matrix/client/v3/keys/signatures/upload', {u: {s['device']: signed}}, h)
        if r.get('failures'): raise CryptoError(f'signing the device failed: {json.dumps(r["failures"])[:200]}')

    # ---- sending
    def room_encrypted(self, hs, h, room):
        c = self._encrypted.get(room)
        if c and (c[0] or time.time() - c[1] < 300): return c[0]    # encryption can't be turned off again, so True is final
        code, _ = req('GET', f'{hs}/_matrix/client/v3/rooms/{urllib.parse.quote(room)}/state/m.room.encryption', None, h)
        enc = code == 200
        if code not in (200, 404): raise CryptoError(f'Couldn\'t read the room\'s settings ({code}). Is the bot in the room?')
        self._encrypted[room] = (enc, time.time()); return enc

    def mark_encrypted(self, room):
        self._encrypted[room] = (True, time.time())

    def send(self, hs, h, room, content):
        if not available(): raise CryptoError('This room is end-to-end encrypted, and encryption support (vodozemac) isn\'t installed on this server.')
        with self.lock:
            s = self._load()
            if not s: raise CryptoError('This room is end-to-end encrypted. Sign the bot in again (Settings → Notifications → Matrix) so OpenRoost can set up encryption.')
            pk = unb64(s['pk'])
            members = self._members(hs, h, room)
            devices = self._devices(hs, h, s, members)
            g, now = s['groups'].get(room), time.time()
            if g and (g['count'] >= ROTATE_MSGS or now - g['created'] > ROTATE_SECS or set(g['users']) - set(members)): g = None
            if not g:
                gs = vz.GroupSession()
                g = s['groups'][room] = {'pickle': gs.pickle(pk), 'created': now, 'count': 0, 'users': [], 'shared': []}
            gs = vz.GroupSession.from_pickle(g['pickle'], pk)
            need = [d for d in devices if f"{d['user']}|{d['device']}" not in g['shared']]
            if need: self._share(hs, h, s, room, gs, g, need)
            ct = gs.encrypt(canonical({'type': 'm.room.message', 'content': content, 'room_id': room})).to_base64()
            g['pickle'] = gs.pickle(pk); g['count'] += 1
            self._save(s)                                        # the ratchet has moved: save before sending, never reuse an index
            acct = vz.Account.from_pickle(s['account'], pk)
            ok('PUT', f'{hs}/_matrix/client/v3/rooms/{urllib.parse.quote(room)}/send/m.room.encrypted/{uuid.uuid4().hex}',
               {'algorithm': MEGOLM, 'sender_key': acct.curve25519_key.to_base64(), 'ciphertext': ct, 'session_id': gs.session_id, 'device_id': s['device']}, h)
            return len(devices)

    # ---- receiving (replies to the emergency countdown)
    def _signed_key(self, s, acct, key, fallback=False):
        o = {'key': key.to_base64()}
        if fallback: o['fallback'] = True
        o['signatures'] = {s['user']: {f"ed25519:{s['device']}": acct.sign(canonical(o)).to_base64()}}
        return o

    def replenish(self, hs, h, counts, unused_fallback):
        """Top up one-time keys and keep a fallback key published (from /sync's counts)."""
        with self.lock:
            s = self._load()
            if not s or not available(): return
            n = (counts or {}).get('signed_curve25519', 0)
            want_fb = unused_fallback is not None and 'signed_curve25519' not in unused_fallback
            if n >= OTK_COUNT // 2 and not want_fb: return
            pk = unb64(s['pk']); acct = vz.Account.from_pickle(s['account'], pk); body = {}
            if n < OTK_COUNT // 2:
                acct.generate_one_time_keys(OTK_COUNT - n)
                body['one_time_keys'] = {f'signed_curve25519:{k}': self._signed_key(s, acct, v) for k, v in acct.one_time_keys.items()}
            if want_fb:
                acct.generate_fallback_key()
                body['fallback_keys'] = {f'signed_curve25519:{k}': self._signed_key(s, acct, v, True) for k, v in acct.fallback_key.items()}
            ok('POST', f'{hs}/_matrix/client/v3/keys/upload', body, h)
            acct.mark_keys_as_published(); s['account'] = acct.pickle(pk); self._save(s)

    def receive_to_device(self, hs, h, ev):
        """An Olm-encrypted to-device message for the bot: keep the room key it carries."""
        c = ev.get('content') or {}
        if ev.get('type') != 'm.room.encrypted' or c.get('algorithm') != OLM or not available(): return
        with self.lock:
            s = self._load()
            if not s: return
            pk = unb64(s['pk']); acct = vz.Account.from_pickle(s['account'], pk)
            ct = (c.get('ciphertext') or {}).get(acct.curve25519_key.to_base64()); sk = c.get('sender_key')
            if not ct or not sk: return
            try: msg = vz.AnyOlmMessage.from_parts(int(ct['type']), unb64(ct['body']))
            except Exception: return
            plain, ins = None, s.setdefault('olm_in', {}).setdefault(sk, [])
            for i, p in enumerate(ins):
                sess = vz.Session.from_pickle(p, pk)
                try: plain = sess.decrypt(msg); ins[i] = sess.pickle(pk); break
                except Exception: continue
            if plain is None and sk in s['olm']:                     # a reply on the session the bot started
                sess = vz.Session.from_pickle(s['olm'][sk], pk)
                try: plain = sess.decrypt(msg); s['olm'][sk] = sess.pickle(pk)
                except Exception: plain = None
            if plain is None and int(ct['type']) == 0:
                try:
                    sess, plain = acct.create_inbound_session(vz.Curve25519PublicKey.from_base64(sk), msg.to_pre_key())
                    ins.append(sess.pickle(pk)); del ins[:-5]; s['account'] = acct.pickle(pk)
                except Exception as e:
                    self.log(f'matrix: couldn\'t open an encrypted message from {ev.get("sender")}: {e}'); self._save(s); return
            if plain is None: self._save(s); return
            try: d = json.loads(plain)
            except ValueError: self._save(s); return
            if d.get('recipient') != s['user'] or (d.get('recipient_keys') or {}).get('ed25519') != acct.ed25519_key.to_base64() or d.get('sender') != ev.get('sender'):
                self.log('matrix: ignoring a to-device message not addressed to this bot'); self._save(s); return
            ed = (d.get('keys') or {}).get('ed25519')
            if not any(x['curve'] == sk and x['ed'] == ed for x in self._devices(hs, h, s, [d['sender']])):
                self.log(f"matrix: ignoring keys from {d['sender']}: they don't match any of their devices"); self._save(s); return
            k = d.get('content') or {}
            if d.get('type') == 'm.room_key' and k.get('algorithm') == MEGOLM and k.get('room_id') and k.get('session_id'):
                try: ig = vz.InboundGroupSession(vz.SessionKey(k['session_key']))
                except Exception: self._save(s); return
                inb = s.setdefault('inbound', {})
                inb[f"{k['room_id']}|{k['session_id']}"] = {'pickle': ig.pickle(pk), 'sender': d['sender'], 'at': time.time()}
                for old in sorted(inb, key=lambda x: inb[x]['at'])[:-300]: inb.pop(old)
            self._save(s)

    def decrypt_event(self, room, ev):
        """Decrypt a Megolm room event. None if the key hasn't arrived (yet) or it doesn't check out."""
        c = ev.get('content') or {}
        if c.get('algorithm') != MEGOLM or not available(): return None
        with self.lock:
            s = self._load()
            e = s and (s.get('inbound') or {}).get(f"{room}|{c.get('session_id')}")
            if not e or e['sender'] != ev.get('sender'): return None
            try:
                d = vz.InboundGroupSession.from_pickle(e['pickle'], unb64(s['pk'])).decrypt(vz.MegolmMessage.from_base64(c['ciphertext']))
                plain = json.loads(d.plaintext)
            except Exception: return None
            return plain if plain.get('room_id') == room else None

    def _members(self, hs, h, room):
        r = ok('GET', f'{hs}/_matrix/client/v3/rooms/{urllib.parse.quote(room)}/members?not_membership=leave', None, h)
        return sorted({e['state_key'] for e in r.get('chunk', []) if (e.get('content') or {}).get('membership') in ('join', 'invite')})

    def _devices(self, hs, h, s, users):
        r = ok('POST', f'{hs}/_matrix/client/v3/keys/query', {'device_keys': {u: [] for u in users}}, h)
        out = []
        for u, devs in (r.get('device_keys') or {}).items():
            if u not in users: continue
            for did, dk in (devs or {}).items():
                if u == s['user'] and did == s['device']: continue
                if dk.get('user_id') != u or dk.get('device_id') != did or MEGOLM not in dk.get('algorithms', []) or OLM not in dk.get('algorithms', []): continue
                ed, ck = dk.get('keys', {}).get(f'ed25519:{did}'), dk.get('keys', {}).get(f'curve25519:{did}')
                sig = ((dk.get('signatures') or {}).get(u) or {}).get(f'ed25519:{did}')
                if not (ed and ck and sig): continue
                try: vz.Ed25519PublicKey.from_base64(ed).verify_signature(canonical(signable(dk)), vz.Ed25519Signature.from_base64(sig))
                except Exception:
                    self.log(f'matrix: ignoring {u} device {did}: bad signature'); continue
                pinned = s['devices'].get(f'{u}|{did}')
                if pinned and pinned != ed:
                    self.log(f'matrix: {u} device {did} changed its signing key; not sending it keys'); continue
                s['devices'][f'{u}|{did}'] = ed
                out.append({'user': u, 'device': did, 'curve': ck, 'ed': ed})
        return out

    def _share(self, hs, h, s, room, gs, g, devs):
        pk = unb64(s['pk']); acct = vz.Account.from_pickle(s['account'], pk)
        missing = [d for d in devs if d['curve'] not in s['olm']]
        if missing:
            want = {}
            for d in missing: want.setdefault(d['user'], {})[d['device']] = 'signed_curve25519'
            r = ok('POST', f'{hs}/_matrix/client/v3/keys/claim', {'one_time_keys': want, 'timeout': 10000}, h)
            for d in missing:
                for kid, o in (((r.get('one_time_keys') or {}).get(d['user']) or {}).get(d['device']) or {}).items():
                    if not kid.startswith('signed_curve25519:') or not isinstance(o, dict): continue
                    sig = ((o.get('signatures') or {}).get(d['user']) or {}).get(f"ed25519:{d['device']}")
                    try:
                        vz.Ed25519PublicKey.from_base64(d['ed']).verify_signature(canonical(signable(o)), vz.Ed25519Signature.from_base64(sig or ''))
                    except Exception:
                        self.log(f"matrix: bad one-time key signature from {d['user']} {d['device']}"); continue
                    sess = acct.create_outbound_session(vz.Curve25519PublicKey.from_base64(d['curve']), vz.Curve25519PublicKey.from_base64(o['key']))
                    s['olm'][d['curve']] = sess.pickle(pk); break
            s['account'] = acct.pickle(pk)
        ck, ek, key = acct.curve25519_key.to_base64(), acct.ed25519_key.to_base64(), gs.session_key.to_base64()
        msgs, sent = {}, 0
        for d in devs:
            if d['curve'] not in s['olm']:
                self.log(f"matrix: {d['user']} device {d['device']} has no one-time keys left; it can't read alerts until it's online again"); continue
            sess = vz.Session.from_pickle(s['olm'][d['curve']], pk)
            plain = canonical({'type': 'm.room_key', 'content': {'algorithm': MEGOLM, 'room_id': room, 'session_id': gs.session_id, 'session_key': key},
                               'sender': s['user'], 'sender_device': s['device'], 'keys': {'ed25519': ek},
                               'recipient': d['user'], 'recipient_keys': {'ed25519': d['ed']}})
            t, body = sess.encrypt(plain).to_parts()
            s['olm'][d['curve']] = sess.pickle(pk)
            msgs.setdefault(d['user'], {})[d['device']] = {'algorithm': OLM, 'sender_key': ck, 'ciphertext': {d['curve']: {'type': t, 'body': b64(body)}}}
            g['shared'].append(f"{d['user']}|{d['device']}")
            if d['user'] not in g['users']: g['users'].append(d['user'])
            sent += 1
        self._save(s)
        if msgs: ok('PUT', f'{hs}/_matrix/client/v3/sendToDevice/m.room.encrypted/{uuid.uuid4().hex}', {'messages': msgs}, h)
        return sent
