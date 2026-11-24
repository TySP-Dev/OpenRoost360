"""The Matrix bot's /sync loop: what it reads from the homeserver.

* Joins the household alert room when invited to it (and only that room).
* Hands Olm to-device messages (room keys) to mxcrypto and keeps the bot's one-time keys topped up.
* Passes new text messages in the bot's rooms (decrypted if needed) to a callback; the emergency countdown uses
  this for "N" replies. Old history is never read: the first sync only takes a position.
Runs while Matrix alerts are on and the bot is signed in; backs off on errors.
"""
import json, threading, time, urllib.parse

from . import mxcrypto

FILTER = json.dumps({'presence': {'types': []}, 'account_data': {'types': []},
                     'room': {'timeline': {'types': ['m.room.message', 'm.room.encrypted'], 'limit': 30}, 'state': {'types': []},
                              'ephemeral': {'types': []}, 'account_data': {'types': []}}}, separators=(',', ':'))
POLL_MS = 25000
PENDING_FOR = 120          # seconds to keep an encrypted event whose key hasn't arrived yet


class MatrixSync:
    def __init__(self, store, notifier, on_message, log=print):
        self.store, self.notifier, self.on_message, self.log = store, notifier, on_message, log
        self.pending, self.seen = [], set()
        self.ok_since = None
        threading.Thread(target=self._run, daemon=True, name='matrix-sync').start()

    def _run(self):
        while True:
            try: wait = self._once()
            except Exception as e:
                self.log(f'matrix sync: {e!r}'); wait = 30
            if wait: time.sleep(wait)

    def _once(self):
        st = self.store.get_settings(); tok = self.store.get_secret('mxToken'); hs = (st.get('mxHs') or '').rstrip('/')
        if not (st.get('mxOn') and hs and tok): return 30
        crypto = self.notifier.crypto; dev = (crypto.status() or {}).get('device') or 'plain'
        h = {'Authorization': 'Bearer ' + tok}
        pos = self.store.kv('mxSync') or {}
        since = pos.get('since') if pos.get('device') == dev and pos.get('hs') == hs else None
        q = {'filter': FILTER, 'timeout': str(POLL_MS if since else 0)}
        if since: q['since'] = since
        code, r = mxcrypto.req('GET', f'{hs}/_matrix/client/v3/sync?{urllib.parse.urlencode(q)}', None, h, timeout=POLL_MS / 1000 + 20)
        if code == 401:
            self.log('matrix sync: the bot\'s access token was refused; sign the bot in again'); return 300
        if code >= 300: self.log(f'matrix sync answered {code}: {r.get("error", "")}'); return 30
        for ev in (r.get('to_device') or {}).get('events', []):
            try: crypto.receive_to_device(hs, h, ev)
            except mxcrypto.CryptoError as e: self.log(f'matrix: {e}')
        try: crypto.replenish(hs, h, r.get('device_one_time_keys_count'), r.get('device_unused_fallback_key_types'))
        except mxcrypto.CryptoError as e: self.log(f'matrix: topping up keys failed: {e}')
        rooms = r.get('rooms') or {}
        if rooms.get('invite'):
            want = self.notifier.mx_room_id(st, hs, h, join=False)
            for rid in rooms['invite']:
                if rid == want:
                    try: self.notifier.mx_join(hs, h, rid); self.log(f'matrix: joined the alert room {rid}')
                    except Exception as e: self.log(f'matrix: couldn\'t join {rid}: {e}')
        if since:                                     # the first sync only takes a position: never act on old history
            me = self.store.get_settings().get('mxUser')
            for rid, room in (rooms.get('join') or {}).items():
                for ev in (room.get('timeline') or {}).get('events', []):
                    if ev.get('sender') == me or ev.get('event_id') in self.seen: continue
                    self.pending.append((time.time(), rid, ev))
            self._drain(crypto)
        self.store.set_kv('mxSync', {'since': r.get('next_batch'), 'device': dev, 'hs': hs})
        self.ok_since = self.ok_since or time.time()
        return 0

    def _drain(self, crypto):
        keep = []
        for at, rid, ev in self.pending:
            content = ev.get('content') or {}
            if ev.get('type') == 'm.room.encrypted':
                plain = crypto.decrypt_event(rid, ev)
                if plain is None:
                    if time.time() - at < PENDING_FOR: keep.append((at, rid, ev))      # its key may come in the next sync
                    continue
                if plain.get('type') != 'm.room.message': continue
                content = plain.get('content') or {}
            body = content.get('body')
            if isinstance(body, str):
                self.seen.add(ev.get('event_id'))
                try: self.on_message(rid, ev.get('sender'), body, ev.get('origin_server_ts', 0) / 1000)
                except Exception as e: self.log(f'matrix: handling a reply failed: {e!r}')
        self.pending = keep
        if len(self.seen) > 5000: self.seen = set(list(self.seen)[-1000:])
