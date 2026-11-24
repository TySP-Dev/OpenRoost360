#!/usr/bin/env python3
"""Functional test of the alert path: hub event -> listener -> hub engine -> notifier -> email + Matrix.
Uses test-only stand-ins for the hub, a mail server and a Matrix homeserver.

    python3 tests/test_notify.py            # exit code 0 = all passed
"""
import base64, json, os, socket, sys, threading, time
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE); sys.path.insert(0, os.path.dirname(HERE))
import fakematrix, smtpsink
from fakehub import FakeHub, status, sensor
from test_security import Server, check, cookie_of, results, OWNER_PW


def port():
    s = socket.socket(); s.bind(('127.0.0.1', 0)); p = s.getsockname()[1]; s.close(); return p


try:
    import vodozemac as vz
except ImportError:
    vz = None
OLM, MEGOLM = 'm.olm.v1.curve25519-aes-sha2', 'm.megolm.v1.aes-sha2'
canonical = fakematrix.canonical


class Receiver:
    """A family member's phone, as an independent Olm/Megolm implementation (vodozemac) would see it."""
    def __init__(self, user, device, otks=5):
        self.user, self.device, self.acct, self.olm, self.groups, self.seen = user, device, vz.Account(), {}, {}, 0
        self.ck, self.ek = self.acct.curve25519_key.to_base64(), self.acct.ed25519_key.to_base64()
        dk = {'user_id': user, 'device_id': device, 'algorithms': [OLM, MEGOLM], 'keys': {f'curve25519:{device}': self.ck, f'ed25519:{device}': self.ek}}
        dk['signatures'] = {user: {f'ed25519:{device}': self.acct.sign(canonical(dk)).to_base64()}}
        self.acct.generate_one_time_keys(otks); keys = {}
        for kid, k in self.acct.one_time_keys.items():
            o = {'key': k.to_base64()}; o['signatures'] = {user: {f'ed25519:{device}': self.acct.sign(canonical(o)).to_base64()}}; keys[f'signed_curve25519:{kid}'] = o
        self.acct.mark_keys_as_published(); fakematrix.add_device(user, device, dk, keys)

    def inbox(self):
        """Decrypt new to-device messages; remember room keys. Returns the decrypted events."""
        out = []
        for td in fakematrix.TODEVICE[self.seen:]:
            c = td['messages'].get(self.user, {}).get(self.device)
            if not c: continue
            ct = c['ciphertext'][self.ck]; msg = vz.AnyOlmMessage.from_parts(ct['type'], fakematrix.unb64(ct['body']))
            if c['sender_key'] in self.olm: plain = self.olm[c['sender_key']].decrypt(msg)
            else: sess, plain = self.acct.create_inbound_session(vz.Curve25519PublicKey.from_base64(c['sender_key']), msg.to_pre_key()); self.olm[c['sender_key']] = sess
            ev = json.loads(plain); out.append(ev)
            if ev['type'] == 'm.room_key': self.groups[ev['content']['session_id']] = vz.InboundGroupSession(vz.SessionKey(ev['content']['session_key']))
        self.seen = len(fakematrix.TODEVICE)
        return out

    def say(self, room, text, bot_device):
        """Send an encrypted message to the room, sharing the room key with the bot's device over Olm first."""
        self.out = getattr(self, 'out', {})
        if room not in self.out:
            gs = vz.GroupSession(); self.out[room] = gs
            dk = fakematrix.DEVICE_KEYS[fakematrix.BOT][bot_device]; bck, bek = dk['keys'][f'curve25519:{bot_device}'], dk['keys'][f'ed25519:{bot_device}']
            pool = fakematrix.OTKS[fakematrix.BOT][bot_device]; o = pool.pop(next(iter(pool)))
            sess = self.acct.create_outbound_session(vz.Curve25519PublicKey.from_base64(bck), vz.Curve25519PublicKey.from_base64(o['key']))
            plain = canonical({'type': 'm.room_key', 'content': {'algorithm': MEGOLM, 'room_id': room, 'session_id': gs.session_id, 'session_key': gs.session_key.to_base64()},
                               'sender': self.user, 'sender_device': self.device, 'keys': {'ed25519': self.ek}, 'recipient': fakematrix.BOT, 'recipient_keys': {'ed25519': bek}})
            t, body = sess.encrypt(plain).to_parts()
            fakematrix.to_bot(bot_device, self.user, 'm.room.encrypted', {'algorithm': OLM, 'sender_key': self.ck, 'ciphertext': {bck: {'type': t, 'body': base64.b64encode(body).decode().rstrip('=')}}})
        gs = self.out[room]
        ct = gs.encrypt(canonical({'type': 'm.room.message', 'content': {'msgtype': 'm.text', 'body': text}, 'room_id': room})).to_base64()
        fakematrix.post(room, self.user, 'm.room.encrypted', {'algorithm': MEGOLM, 'sender_key': self.ck, 'ciphertext': ct, 'session_id': gs.session_id, 'device_id': self.device})

    def read(self, ev):
        d = self.groups[ev['session_id']].decrypt(vz.MegolmMessage.from_base64(ev['ciphertext'])); return json.loads(d.plaintext), d.message_index


def e2ee(s, web, h):
    print('\n== Matrix end-to-end encryption')
    if not vz: print('   (skipped: vodozemac not installed in this Python)'); return
    st, e, _, _ = s.req('GET', '/api/v1/notify/matrix/e2ee', cookie=web)
    check('bot device has encryption keys after sign-in', st == 200 and e.get('ready') and e['device'].startswith('BOTDEV'), e)
    check('bot device is cross-signed by its own account (signature verified by the server)', e.get('crossSigned') and (fakematrix.BOT, e['device']) in fakematrix.SIG_UPLOADS, (e, fakematrix.SIG_UPLOADS))
    check('Olm account is stored encrypted (no key material in the database)', e['fingerprint'].encode() not in open(os.path.join(s.data, 'openroost.db'), 'rb').read())
    room = '!secure:test.local'; fakematrix.ENCRYPTED.add(room); fakematrix.MEMBERS[room] = {fakematrix.BOT, '@ty:test.local'}
    phone, laptop = Receiver('@ty:test.local', 'TYPHONE'), Receiver('@ty:test.local', 'TYLAPTOP')
    s.req('PUT', '/api/v1/settings', {'settings': {'mxRoom': room}}, cookie=web)
    n = len(fakematrix.SENT); st, js, _, _ = s.req('POST', '/api/v1/notify/test/matrix', {}, cookie=web)
    sent = fakematrix.SENT[n:]
    check('message to an encrypted room is sent encrypted', st == 200 and 'encrypted' in js['result'] and len(sent) == 1 and sent[0]['type'] == 'm.room.encrypted' and sent[0]['algorithm'] == MEGOLM, (st, js, sent))
    check('…and contains no readable text', 'Test from' not in json.dumps(sent) and 'reach you' not in json.dumps(sent))
    keys = phone.inbox(); lkeys = laptop.inbox()
    rk = next((k for k in keys if k['type'] == 'm.room_key'), None)
    check('room key reaches each of the family member\'s devices over Olm', rk and any(k['type'] == 'm.room_key' for k in lkeys), (keys, lkeys))
    check('room key is addressed and signed correctly (sender, recipient keys, room)', rk and rk['sender'] == fakematrix.BOT and rk['recipient_keys']['ed25519'] == phone.ek
          and rk['keys']['ed25519'] == e['fingerprint'] and rk['content']['room_id'] == room, rk)
    body, idx = phone.read(sent[0])
    check('the phone decrypts the message', body['type'] == 'm.room.message' and 'Test from OpenRoost360' in body['content']['body'] and body['room_id'] == room and idx == 0, body)
    check('so does the laptop', 'Test from OpenRoost360' in laptop.read(sent[0])[0]['content']['body'])
    t = len(fakematrix.TODEVICE); n = len(fakematrix.SENT)
    h.publish(sensor(7, 'leak', 0)); h.publish(sensor(7, 'leak', 1)); time.sleep(1.5)
    ev = next(x for x in fakematrix.SENT[n:] if x['room'] == room)
    body, idx = phone.read(ev)
    check('a real alarm arrives encrypted with @room, same session (no new keys sent)', body['content']['body'].startswith('@room') and 'Water leak' in body['content']['body'] and idx == 1 and len(fakematrix.TODEVICE) == t, (body, idx))
    s.req('POST', '/api/v1/alerts/leak/ack', {}, cookie=web)
    sid = ev['session_id']
    fakematrix.MEMBERS[room] = {fakematrix.BOT, '@guest:test.local'}; guest = Receiver('@guest:test.local', 'GUESTPHONE')
    n = len(fakematrix.SENT); s.req('POST', '/api/v1/notify/test/matrix', {}, cookie=web); ev = fakematrix.SENT[n]
    guest.inbox(); before = len(phone.groups); phone.inbox()
    check('when someone leaves, the room key is replaced and they don\'t get the new one', ev['session_id'] != sid and len(phone.groups) == before, ev['session_id'])
    check('the new member reads new messages', 'Test from OpenRoost360' in guest.read(ev)[0]['content']['body'])
    print('\n== Encrypted DM to an emergency contact')
    contact = Receiver('@nana:test.local', 'NANAPHONE')
    s.req('PUT', '/api/v1/settings', {'settings': {'mxE2ee': True, 'contacts': [{'id': 1, 'name': 'Nana', 'mx': '@nana:test.local', 'tiers': {'distress': 1, 'alarms': 0, 'info': 0}}]}}, cookie=web)
    n = len(fakematrix.SENT); h.publish(sensor(1, 'keypad', 12)); time.sleep(2)
    dm = next((x for x in fakematrix.SENT[n:] if x['room'].startswith('!dm')), None)
    check('panic DM goes to a new room created encrypted', dm and dm['room'] in fakematrix.ENCRYPTED and dm['type'] == 'm.room.encrypted', fakematrix.SENT[n:])
    contact.inbox()
    check('the emergency contact decrypts it', dm and 'Panic' in contact.read(dm)[0]['content']['body'])
    s.req('POST', '/api/v1/alerts/panic/ack', {}, cookie=web)
    # the guest's phone is replaced by one with a different key but the same device id: it must not get keys again
    fakematrix.MEMBERS[room] = {fakematrix.BOT, '@guest:test.local', '@new:test.local'}; Receiver('@guest:test.local', 'GUESTPHONE'); Receiver('@new:test.local', 'NEWPHONE')
    s.req('POST', '/api/v1/notify/test/matrix', {}, cookie=web)


def wait(cond, secs):
    end = time.time() + secs
    while time.time() < end:
        if cond(): return True
        time.sleep(0.2)
    return cond()


def countdown(s, web, h, mailbox):
    print('\n== Emergency countdown')
    if not vz: print('   (skipped: vodozemac not installed in this Python)'); return s, web, h
    import re as _re
    room = '!family:test.local'; fakematrix.ENCRYPTED.add(room); fakematrix.MEMBERS[room] = {fakematrix.BOT, '@ty:test.local'}
    ty = Receiver('@ty:test.local', 'TYCOUNT')
    SECS = 12
    s.req('PUT', '/api/v1/settings', {'settings': {'mxRoom': room, 'mxMention': True,
        'contacts': [{'id': 1, 'name': 'Nana', 'email': 'nana@example.com', 'mx': '@nana:test.local', 'tiers': {'distress': 1, 'alarms': 1, 'info': 0}}],
        'esc': {'intrusion': {'on': True, 'secs': SECS}, 'fire': {'on': True, 'secs': SECS}, 'duress': {'on': True, 'secs': SECS}, 'room': True,
                'responders': [{'id': 1, 'name': 'Ty', 'email': 'ty@example.com', 'mx': '@ty:test.local'}]}}}, cookie=web)
    bot_dev = s.req('GET', '/api/v1/notify/matrix/e2ee', cookie=web)[1]['device']
    to_nana = lambda: open(mailbox).read().count('To: nana@example.com')
    nana_rooms = lambda: [x for x in fakematrix.SENT if x['room'] != room and '@nana:test.local' in fakematrix.MEMBERS.get(x['room'], ())]
    def room_texts():
        ty.inbox(); out = []
        for x in fakematrix.SENT:
            if x['room'] == room and x.get('type') == 'm.room.encrypted' and x['session_id'] in ty.groups: out.append(ty.read(x)[0]['content']['body'])
        return out
    def esc_of(kind):
        js = s.req('GET', '/api/v1/escalations', cookie=web)[1]; return next((x for x in js['escalations'] if x['kind'] == kind), None)

    print('-- break-in, cancelled with an encrypted "N" from Ty')
    n_mail, n_dm = to_nana(), len(nana_rooms())
    h.publish({'ev': '4', 'as': 4, 't': int(time.time())})
    ok = wait(lambda: any('BREAK IN' in t for t in room_texts()), 6)
    txt = next((t for t in room_texts() if 'BREAK IN' in t), '')
    check('the household room gets the countdown (encrypted), in the agreed wording',
          ok and txt.startswith('@room BREAK IN\n') and f'PLEASE RESPOND "N" WITHIN {SECS} SECONDS TO CANCEL THE EMERGENCY EMAIL / MATRIX MESSAGE' in txt, txt)
    check('Ty gets the countdown by email with a cancel link', wait(lambda: 'BREAK IN' in open(mailbox).read() and '?cancel=' in open(mailbox).read().replace('=\n', ''), 4))
    check('the app shows the countdown as pending', (esc_of('intrusion') or {}).get('state') == 'pending', esc_of('intrusion'))
    check('the emergency contact is not told yet', to_nana() == n_mail and len(nana_rooms()) == n_dm)
    fakematrix.MEMBERS[room].add('@stranger:test.local'); fakematrix.post(room, '@stranger:test.local', 'm.room.message', {'msgtype': 'm.text', 'body': 'N'})
    time.sleep(2)
    check('an "N" from someone not on the list is ignored', esc_of('intrusion')['state'] == 'pending', esc_of('intrusion'))
    ty.say(room, 'N', bot_dev)
    check('Ty\'s encrypted "N" cancels it', wait(lambda: esc_of('intrusion')['state'] == 'cancelled', 8) and esc_of('intrusion')['by'] == '@ty:test.local', esc_of('intrusion'))
    check('the room is told it was cancelled', wait(lambda: any(t.startswith('CANCELLED: BREAK IN') for t in room_texts()), 4), room_texts()[-2:])
    time.sleep(SECS)
    check('after the deadline the emergency contact still hasn\'t been told (email or Matrix)', to_nana() == n_mail and len(nana_rooms()) == n_dm, (to_nana(), n_mail))

    print('-- fire alarm, nobody answers')
    h.publish(status(fr=1)); time.sleep(2)
    check('the fire countdown starts', (esc_of('fire') or {}).get('state') == 'pending', esc_of('fire'))
    check('…and the contact waits', to_nana() == n_mail)
    check('when time runs out, the emergency contact is emailed and messaged on Matrix',
          wait(lambda: to_nana() > n_mail and len(nana_rooms()) > n_dm, SECS + 6) and 'Fire alarm' in open(mailbox).read().split('To: nana@example.com')[-1], (to_nana(), len(nana_rooms())))
    sent_txt = lambda: next((t for t in room_texts() if t.startswith('EMERGENCY MESSAGES SENT: FIRE ALARM')), '')
    check('follow-up in the household room: the emergency messages went out, and to whom', wait(lambda: bool(sent_txt()), 4) and 'Nana (email + Matrix)' in sent_txt(), sent_txt())
    check('follow-up email to the people on the list', wait(lambda: 'EMERGENCY MESSAGES SENT: FIRE ALARM' in open(mailbox).read().split('To: ty@example.com')[-1], 4))
    check('follow-up Matrix DM to them too', any(x['room'] != room and '@ty:test.local' in fakematrix.MEMBERS.get(x['room'], ()) and x.get('type') == 'm.room.encrypted' for x in fakematrix.SENT[-6:]))
    check('the app shows who was told', esc_of('fire').get('told') == ['Nana'], esc_of('fire'))
    check('the app shows it as sent', esc_of('fire')['state'] == 'sent')
    h.publish(status(fr=0))

    print('-- distress PIN, cancelled with the email link')
    n_mail = to_nana(); n_dm = len(nana_rooms())
    h.publish({'ev': '0', 'as': 0, 'da': 'ho', 't': int(time.time())})
    wait(lambda: 'DISTRESS PIN USED' in open(mailbox).read(), 6)
    tok = _re.findall(r'\?cancel=([A-Za-z0-9_-]{43})', open(mailbox).read().replace('=\n', '').replace('=3D', '='))[-1]
    st, js, _, _ = s.req('POST', '/api/v1/escalations/peek', {'token': tok})
    check('the cancel link shows what it\'s for, without signing in', st == 200 and js['escalation']['label'] == 'DISTRESS PIN USED' and js['name'] == 'Ty', (st, js))
    st, _, _, _ = s.req('POST', '/api/v1/escalations/cancel', {'token': 'x' * 43}); check('a made-up cancel link is refused', st == 404, st)
    st, js, _, _ = s.req('POST', '/api/v1/escalations/cancel', {'token': tok})
    check('the email link cancels it', st == 200 and js['escalation']['state'] == 'cancelled' and js['escalation']['via'] == 'email link', (st, js))
    st, _, _, _ = s.req('POST', '/api/v1/escalations/cancel', {'token': tok}); check('cancelling twice says it\'s no longer pending', st == 409, st)
    time.sleep(SECS + 1)
    check('the emergency contact is not told', to_nana() == n_mail and len(nana_rooms()) == n_dm)

    print('-- break-in cancelled from the app')
    h.publish({'ev': '4', 'as': 4, 't': int(time.time())}); time.sleep(1.5)
    x = esc_of('intrusion')
    st, js, _, _ = s.req('POST', f"/api/v1/escalations/{x['id']}/cancel", {}, cookie=web)
    check('a member or owner cancels in the app', st == 200 and js['escalation']['state'] == 'cancelled', (st, js))
    st, _, _, _ = s.req('POST', f"/api/v1/escalations/{x['id']}/cancel", {}); check('…which needs sign-in', st == 401, st)

    print('-- the server restarts during a countdown')
    n_mail = to_nana()
    h.publish(status(fr=1)); time.sleep(1.5)
    check('a fire countdown is running', (esc_of('fire') or {}).get('state') == 'pending')
    h.close(); log = s.close(keep=True); time.sleep(SECS)
    check('a device whose signing key changed gets no more keys (logged)', 'changed its signing key' in log, log[-400:])
    s2 = Server(data=s.data)
    _, _, _, hd = s2.req('POST', '/api/v1/auth/login', {'username': 'tyowner', 'password': OWNER_PW}); web2, _ = cookie_of(hd)
    check('after the restart, the overdue countdown is sent instead of lost', wait(lambda: to_nana() > n_mail, 8), (to_nana(), n_mail))
    h2 = FakeHub(s2.lport); h2.subscribe(); h2.publish(status())
    return s2, web2, h2


def main():
    mport, xport = port(), port()
    s = Server(); mailbox = s.data + '.mail'
    threading.Thread(target=smtpsink.run, args=(mport, mailbox), daemon=True).start()
    fakematrix.run(xport); time.sleep(0.3)
    hs = f'http://127.0.0.1:{xport}'
    body = {'code': s.code, 'admin': {'username': 'tyowner', 'password': OWNER_PW},
            'settings': {'siteName': 'Home', 'repeatMin': 1, 'publicUrl': 'https://openroost.lan:8443',
                         'routing': {'leak': [1, 0, 1, 0], 'intrusion': [1, 0, 1, 0]},
                         'mail': {'mode': 'relay-existing', 'host': '127.0.0.1', 'port': str(mport), 'sec': 'none', 'from': 'alerts@example.com'},
                         'smtpTo': 'ty@example.com', 'mxOn': True, 'mxRoom': '#alerts:test.local', 'mxMention': True}}
    print('\n== Matrix during setup')
    st, js, _, _ = s.req('POST', '/api/v1/setup/matrix-login', {'code': s.code, 'hs': hs, 'user': '@openroost:test.local', 'password': 'wrong'})
    check('wrong bot password is refused with Matrix\'s reason', st == 400 and 'Invalid password' in js['error'], js)
    st, js, _, _ = s.req('POST', '/api/v1/setup/matrix-login', {'code': s.code, 'hs': hs, 'user': '@openroost:test.local', 'password': 'bot-password'}); check('bot signs in during setup', st == 200, js)
    st, js, _, _ = s.req('POST', '/api/v1/setup/matrix-test', {'code': s.code, 'room': '#alerts:test.local', 'site': 'Home'})
    check('setup test message reaches the room (alias resolved)', st == 200 and fakematrix.SENT and fakematrix.SENT[-1]['room'] == '!alerts:test.local', (js, fakematrix.SENT[-1:]))
    st, js, _, hd = s.req('POST', '/api/v1/setup/complete', body); web, _ = cookie_of(hd)
    check('setup completes with email + Matrix', st == 200, js)
    st, js, txt, _ = s.req('GET', '/api/v1/settings', cookie=web); check('the bot password is never stored, only the token', 'bot-password' not in txt and js['secretsSet']['mxToken'])

    print('\n== Test buttons')
    st, js, _, _ = s.req('POST', '/api/v1/notify/test/email', {}, cookie=web); time.sleep(0.5)
    check('test email sent to the recipients', st == 200 and 'Email alerts work' in open(mailbox).read(), js)
    n = len(fakematrix.SENT); st, js, _, _ = s.req('POST', '/api/v1/notify/test/matrix', {}, cookie=web)
    check('test Matrix message sent', st == 200 and len(fakematrix.SENT) == n + 1, js)

    print('\n== Alarm from the hub -> email + Matrix')
    h = FakeHub(s.lport); h.subscribe(); h.publish(status())
    s.req('POST', '/api/v1/hub/claim', {}, cookie=web)
    h.publish(sensor(7, 'leak', 0)); n = len(fakematrix.SENT); h.publish(sensor(7, 'leak', 1)); time.sleep(1.5)
    mail = open(mailbox).read()
    check('leak alarm emailed (branded HTML, link to the dashboard)', 'Water leak' in mail and 'text/html' in mail and 'openroost.lan:8443' in mail)
    mx = fakematrix.SENT[n:]
    check('leak alarm posted to Matrix with @room', any(m['body'].startswith('@room') and 'Water leak' in m['body'] for m in mx), mx)
    st, js, _, _ = s.req('GET', '/api/v1/alerts', cookie=web); check('alarm is active in the API', any(a['kind'] == 'leak' and a['active'] for a in js['alerts']), js)
    print('   (waiting ~75 s for a repeat)'); time.sleep(75)
    check('unacknowledged alarm repeats', any('still active' in m['body'] for m in fakematrix.SENT[n:]), fakematrix.SENT[n:])
    s.req('POST', '/api/v1/alerts/leak/ack', {}, cookie=web); k = len(fakematrix.SENT); time.sleep(75)
    check('acknowledging stops the repeats', len(fakematrix.SENT) == k, fakematrix.SENT[k:])
    e2ee(s, web, h)
    s, web, h = countdown(s, web, h, mailbox)
    h.close(); s.close()
    failed = [r for r in results if not r[1]]
    print(f'\n{len(results) - len(failed)}/{len(results)} passed')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
