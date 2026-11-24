#!/usr/bin/env python3
"""Security smoke tests for the OpenRoost360 server (API v1, listener). Starts throwaway servers on spare ports with
temporary data folders, attacks them over HTTP, and inspects what lands on disk.

    python3 tests/test_security.py             # exit code 0 = all passed
"""
import base64, glob, http.client, json, os, re, shutil, socket, sqlite3, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
results = []
OWNER_PW = 'Quiet rooster at dawn 42'
SECRETS = {'ph.pass': 'PHSECRET-abc123', 'mail.key': 'RESENDKEY-xyz789', 'mxToken': 'MXTOKEN-secret-777',
           'hookSecret': 'HOOKSECRET-555', 'ssoSecret': 'SSOSECRET-444'}


def check(name, ok, detail=''):
    results.append((name, bool(ok), detail))
    print(('  PASS ' if ok else '  FAIL ') + name + (f'  [{detail}]' if detail and not ok else ''))


class Server:
    def __init__(self, env=None, data=None):
        ports = []
        for _ in range(2):
            s = socket.socket(); s.bind(('127.0.0.1', 0)); ports.append(s.getsockname()[1]); s.close()
        self.port, self.lport = ports
        self.data = data or tempfile.mkdtemp(prefix='or360-test-')
        s = socket.socket(); s.bind(('127.0.0.1', 0)); self.hport = s.getsockname()[1]; s.close()
        self.proc = subprocess.Popen([sys.executable, '-m', 'openroost', '--bind', '127.0.0.1', '--port', str(self.port), '--https-port', str(self.hport),
                                      '--listener-port', str(self.lport), '--data', self.data],
                                     env={**os.environ, 'OPENROOST_TLS': 'off', **(env or {})}, cwd=ROOT, stdout=open(self.data + '.log', 'w'), stderr=subprocess.STDOUT)   # a pipe nobody reads would fill and block the server
        for _ in range(50):
            try: socket.create_connection(('127.0.0.1', self.port), 0.2).close(); break
            except OSError: time.sleep(0.1)
        self.code = None
        for _ in range(50):
            if data or self.proc.poll() is not None: break
            if os.path.exists(os.path.join(self.data, 'SETUP-CODE.txt')):
                self.code = open(os.path.join(self.data, 'SETUP-CODE.txt')).read().strip(); break
            time.sleep(0.1)

    def req(self, method, path, body=None, cookie=None, headers=None, raw=None, host=None):
        c = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        h = {'Host': host or f'127.0.0.1:{self.port}'}
        if method != 'GET': h['X-OpenRoost'] = '1'
        if body is not None: h['Content-Type'] = 'application/json'
        if cookie: h['Cookie'] = 'or360_sid=' + cookie
        h.update(headers or {})
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        c.request(method, path, body=data, headers={k: v for k, v in h.items() if v is not None})
        r = c.getresponse(); txt = r.read().decode(errors='replace'); c.close()
        try: js = json.loads(txt)
        except ValueError: js = None
        return r.status, js, txt, r.getheaders()

    def close(self, keep=False):
        self.proc.terminate(); self.proc.wait(5)
        log = open(self.data + '.log', errors='replace').read(); os.remove(self.data + '.log')
        if not keep: shutil.rmtree(self.data, ignore_errors=True)
        return log


def cookie_of(headers):
    for k, v in headers:
        if k.lower() == 'set-cookie' and v.startswith('or360_sid='): return v.split(';')[0].split('=', 1)[1], v
    return None, None


def setup_body(code, password=OWNER_PW, username='tyowner'):
    return {'code': code, 'admin': {'username': username, 'password': password},
            'settings': {'siteName': 'Home', 'ph': {'mode': 'existing', 'url': 'http://192.168.1.2/admin', 'pass': SECRETS['ph.pass'], 'ok': True},
                         'mail': {'mode': 'relay-start', 'up': 'resend', 'key': SECRETS['mail.key'], 'from': 'alerts@example.com', 'to': 'ty@example.com', 'running': True},
                         'sensorMeta': {'2': {'name': 'Porch Door', 'room': 'Porch'}}}}


def main():
    print('\n== First-run setup')
    s = Server()
    st, js, _, _ = s.req('GET', '/api/v1/status'); check('status says setup not done', st == 200 and js['setupDone'] is False)
    check('setup code file is private (0600)', oct(os.stat(os.path.join(s.data, 'SETUP-CODE.txt')).st_mode & 0o777) == '0o600')
    st, _, _, _ = s.req('POST', '/api/v1/setup/complete', setup_body('0000-0000-0000')); check('wrong setup code refused', st == 403)
    st, _, _, _ = s.req('POST', '/api/v1/setup/complete', setup_body(None)); check('missing setup code refused', st == 403)
    for pw, why in [('short', 'too short'), ('tyowner-is-great', 'contains username'), ('aaaaaaaaaaaaaaaa', 'too few distinct characters'), ('administrator', 'common')]:
        st, js, _, _ = s.req('POST', '/api/v1/setup/complete', setup_body(s.code, pw)); check(f'weak owner password refused ({why})', st == 400, f'{st} {js}')
    st, js, _, _ = s.req('POST', '/api/v1/setup/complete', setup_body(s.code, username='<script>')); check('bad username refused', st == 400)
    st, js, _, hd = s.req('POST', '/api/v1/setup/complete', setup_body(s.code)); owner, raw_cookie = cookie_of(hd)
    check('setup with right code succeeds', st == 200 and owner, f'{st} {js}')
    check('session cookie is HttpOnly + SameSite=Strict', raw_cookie and 'HttpOnly' in raw_cookie and 'SameSite=Strict' in raw_cookie, raw_cookie)
    check('setup code file deleted after setup', not os.path.exists(os.path.join(s.data, 'SETUP-CODE.txt')))
    st, _, _, _ = s.req('POST', '/api/v1/setup/complete', setup_body(s.code, username='attacker')); check('setup can’t be run again', st == 409)

    print('\n== Unauthenticated access')
    for m, p in [('GET', '/api/v1/settings'), ('PUT', '/api/v1/settings'), ('GET', '/api/v1/users'), ('POST', '/api/v1/users'), ('GET', '/api/v1/audit'), ('GET', '/api/v1/me'),
                 ('GET', '/api/v1/me/sessions'), ('GET', '/api/v1/overview'), ('GET', '/api/v1/sensors'), ('GET', '/api/v1/events'), ('GET', '/api/v1/stream'), ('POST', '/api/v1/backup')]:
        st, _, _, _ = s.req(m, p, {} if m != 'GET' else None); check(f'{m} {p} without a session → 401', st == 401, st)
    st, _, _, _ = s.req('GET', '/api/v1/settings', cookie='forged-token-value'); check('forged session token → 401', st == 401)

    print('\n== CSRF, DNS rebinding, request hygiene')
    st, _, _, _ = s.req('POST', '/api/v1/auth/login', {'username': 'tyowner', 'password': OWNER_PW}, headers={'X-OpenRoost': None}); check('POST without X-OpenRoost header → 403', st == 403, st)
    st, _, _, _ = s.req('PUT', '/api/v1/settings', {'settings': {}}, cookie=owner, headers={'Origin': 'http://evil.example'}); check('cross-origin Origin → 403', st == 403, st)
    st, _, _, _ = s.req('PUT', '/api/v1/settings', {'settings': {}}, cookie=owner, headers={'Origin': 'null'}); check('Origin: null (sandboxed iframe) → 403', st == 403, st)
    st, _, _, _ = s.req('POST', '/api/v1/auth/login', raw=b'username=a&password=b', headers={'Content-Type': 'application/x-www-form-urlencoded'}); check('form-encoded body refused (415)', st == 415, st)
    st, _, _, _ = s.req('GET', '/api/v1/status', host='evil.example'); check('unknown Host (DNS rebinding) → 421', st == 421, st)
    st, _, _, _ = s.req('GET', '/', host='evil.example'); check('unknown Host on static files → 421', st == 421, st)
    st, _, _, _ = s.req('PUT', '/api/v1/settings', raw=b'{"settings":' + b'"x' * 40000 + b'"}', cookie=owner); check('oversized body → 413', st == 413, st)
    st, _, _, _ = s.req('PUT', '/api/v1/settings', raw=b'{not json', cookie=owner, headers={'Content-Type': 'application/json'}); check('invalid JSON → 400', st == 400, st)
    st, js, txt, _ = s.req('PUT', '/api/v1/settings', raw=b'[1,2]', cookie=owner, headers={'Content-Type': 'application/json'}); check('non-object JSON → 400, no stack trace', st == 400 and 'Traceback' not in txt, st)
    st, _, _, _ = s.req('TRACE', '/api/v1/status'); check('TRACE not allowed', st in (405, 501), st)

    print('\n== Settings validation')
    bad = [({'nope': 1}, 'unknown key'), ({'hookUrl': 'javascript:alert(1)'}, 'javascript: URL'), ({'ssoIssuer': 'http://x/"><script>'}, 'URL with markup'),
           ({'siteName': 'x' * 41}, 'too long'), ({'siteName': 'a\x00b'}, 'control character'), ({'repeatMin': 'many'}, 'wrong type'),
           ({'repeatMin': 9999}, 'out of range'), ({'ph': {'mode': 'evil'}}, 'bad enum in object'), ({'contacts': [{'name': 'x', 'email': 'not-an-email'}]}, 'bad contact email'),
           ({'sensorMeta': {'../x': {'name': 'a'}}}, 'bad sensor id'), ({'smtpTo': 'a@b.co\nevil'}, 'bad recipient list'), ({'sessionLen': 'never'}, 'infinite session')]
    for patch, why in bad:
        st, _, _, _ = s.req('PUT', '/api/v1/settings', {'settings': patch}, cookie=owner); check(f'rejects {why}', st == 400, st)

    print('\n== Secrets: write-only, encrypted at rest')
    st, js, _, _ = s.req('PUT', '/api/v1/settings', {'settings': {'mxToken': SECRETS['mxToken'], 'hookSecret': SECRETS['hookSecret'], 'ssoSecret': SECRETS['ssoSecret'], 'mxOn': True}}, cookie=owner)
    check('owner can save secrets', st == 200, f'{st} {js}')
    st, js, _, _ = s.req('PUT', '/api/v1/hub/pins', {'pins': {'owner': '4826'}}, cookie=owner)
    check('PIN endpoint answers 501 Planned (hub /config format unknown)', st == 501 and js.get('feature') == 'hub.pins', (st, js))
    st, js, txt, _ = s.req('GET', '/api/v1/settings', cookie=owner)
    check('GET /api/settings contains no secret values', st == 200 and not any(v in txt for v in SECRETS.values()))
    check('…but reports which secrets are set', all(js['secretsSet'].get(k) for k in SECRETS), js['secretsSet'])
    st, js, _, _ = s.req('PUT', '/api/v1/settings', {'settings': {'mxToken': ''}}, cookie=owner); st2, js2, _, _ = s.req('GET', '/api/v1/settings', cookie=owner)
    check('empty secret on save leaves it unchanged', js2['secretsSet']['mxToken'])
    st, js, _, _ = s.req('PUT', '/api/v1/settings', {'settings': {}, 'clear': ['hookSecret']}, cookie=owner); st2, js2, _, _ = s.req('GET', '/api/v1/settings', cookie=owner)
    check('clear removes a secret', not js2['secretsSet']['hookSecret'])
    st, _, _, _ = s.req('PUT', '/api/v1/settings', {'settings': {}, 'clear': ['siteName']}, cookie=owner); check('clear refuses non-secret names', st == 400)

    blobs = b''.join(open(f, 'rb').read() for f in glob.glob(os.path.join(s.data, '*')) if os.path.isfile(f))
    leaks = [k for k, v in SECRETS.items() if v.encode() in blobs] + [p for p in (OWNER_PW,) if p.encode() in blobs]
    where = [os.path.basename(f) for f in glob.glob(os.path.join(s.data, '*')) if os.path.isfile(f) and any(v.encode() in open(f, 'rb').read() for v in list(SECRETS.values()) + [OWNER_PW])]
    check('no secret, PIN or password in plaintext anywhere in the data folder', not leaks, (leaks, where))
    check('owner token not stored in plaintext', owner.encode() not in blobs)
    db = sqlite3.connect(os.path.join(s.data, 'openroost.db'))
    h = db.execute("SELECT pw_hash FROM users WHERE username='tyowner'").fetchone()[0]
    check('password stored as Argon2id (64 MiB, t=3)', re.match(r'argon2id\$v=19\$m=65536,t=3,p=4,k=[0-9a-f]{12}\$', h), h[:40])
    check('data folder 0700, files 0600', oct(os.stat(s.data).st_mode & 0o777) == '0o700' and all(os.stat(f).st_mode & 0o077 == 0 for f in glob.glob(os.path.join(s.data, '*'))))
    from openroost.store import Store
    st_obj = Store(s.data)
    a, b = (db.execute('SELECT blob FROM secrets WHERE name=?', (n,)).fetchone()[0] for n in ('ph.pass', 'mail.key'))
    try: st_obj.keys.open('ph.pass', b); swapped = True
    except Exception: swapped = False
    check('ciphertext moved to another field fails to decrypt (bound by name)', not swapped)
    tampered = bytearray(a); tampered[-1] ^= 1
    try: st_obj.keys.open('ph.pass', bytes(tampered)); ok = True
    except Exception: ok = False
    check('tampered ciphertext is rejected (AES-GCM tag)', not ok)
    check('same secret encrypts differently each time (random nonce)', st_obj.keys.seal('x', 'same') != st_obj.keys.seal('x', 'same'))
    os.rename(os.path.join(s.data, 'master.key'), os.path.join(s.data, 'master.key.bak'))
    try: Store(s.data).get_secret('ph.pass'); wrong_key_ok = True
    except (Exception, SystemExit): wrong_key_ok = False
    finally:
        os.remove(os.path.join(s.data, 'master.key')); os.rename(os.path.join(s.data, 'master.key.bak'), os.path.join(s.data, 'master.key'))
    check('database alone (different master key) can’t decrypt secrets', not wrong_key_ok)

    print('\n== Roles and account management')
    st, js, _, _ = s.req('POST', '/api/v1/users', {'username': 'partner', 'password': 'Garden hose blue 1984', 'role': 'member'}, cookie=owner); mid = js and js['user']['id']
    check('owner adds a member', st == 200, js)
    s.req('POST', '/api/v1/users', {'username': 'teen', 'password': 'Purple bicycle runs 77', 'role': 'viewer'}, cookie=owner)
    st, js, _, _ = s.req('POST', '/api/v1/users', {'username': 'partner', 'password': 'Another good pass 99', 'role': 'member'}, cookie=owner); check('duplicate username refused', st == 400)
    st, js, _, _ = s.req('POST', '/api/v1/users', {'username': 'x2', 'password': 'Another good pass 99', 'role': 'god'}, cookie=owner); check('unknown role refused', st == 400)
    st, js, _, hd = s.req('POST', '/api/v1/auth/login', {'username': 'partner', 'password': 'Garden hose blue 1984'}); member, _ = cookie_of(hd)
    st, js, _, hd = s.req('POST', '/api/v1/auth/login', {'username': 'teen', 'password': 'Purple bicycle runs 77'}); viewer, _ = cookie_of(hd)
    for who, ck in (('member', member), ('viewer', viewer)):
        st, js, txt, _ = s.req('GET', '/api/v1/settings', cookie=ck); check(f'{who} can read settings, without secrets', st == 200 and not any(v in txt for v in SECRETS.values()))
        for m, p, b in [('PUT', '/api/v1/settings', {'settings': {'siteName': 'pwned'}}), ('GET', '/api/v1/hub/pins', None), ('PUT', '/api/v1/hub/pins', {'pins': {}}),
                        ('GET', '/api/v1/users', None), ('POST', '/api/v1/users', {'username': 'x', 'password': 'y', 'role': 'owner'}),
                        ('PATCH', f'/api/v1/users/{mid}', {'role': 'owner'}), ('POST', f'/api/v1/users/{mid}/password', {'password': 'Whatever long pass 1'}), ('GET', '/api/v1/audit', None)]:
            st, _, _, _ = s.req(m, p, b, cookie=ck); check(f'{who} blocked: {m} {p}', st == 403, st)
    st, js, _, _ = s.req('GET', '/api/v1/me', cookie=owner); oid = js['user']['id']
    st, _, _, _ = s.req('PATCH', f'/api/v1/users/{oid}', {'role': 'member'}, cookie=owner); check('last owner can’t be demoted', st == 409, st)
    st, _, _, _ = s.req('DELETE', f'/api/v1/users/{oid}', cookie=owner); check('owner can’t delete own account', st == 409, st)
    st, _, _, _ = s.req('PATCH', f'/api/v1/users/{mid}', {'role': 'viewer'}, cookie=owner)
    st, _, _, _ = s.req('GET', '/api/v1/me', cookie=member); check('role change signs the user out (takes effect at next sign-in)', st == 401, st)
    st, _, _, _ = s.req('PATCH', '/api/v1/me', {'display': '<img src=x onerror=alert(1)>', 'email': 'x'}, cookie=owner); check('profile email validated (400, not 500)', st == 400, st)
    st, _, _, _ = s.req('POST', '/api/v1/users', {'username': 'ctl', 'password': 'Another good pass 99', 'role': 'viewer', 'display': 'a\x00b'}, cookie=owner); check('control characters in a member name → 400, not 500', st == 400, st)

    print('\n== Sessions')
    st, js, _, hd = s.req('POST', '/api/v1/auth/login', {'username': 'tyowner', 'password': OWNER_PW}, cookie=owner); owner2, _ = cookie_of(hd)
    check('login issues a new token (no session fixation)', owner2 and owner2 != owner)
    st, _, _, _ = s.req('GET', '/api/v1/me', cookie=owner); check('old token from before re-login is ended', st == 401, st)
    st, js, _, hd = s.req('POST', '/api/v1/auth/login', {'username': 'tyowner', 'password': OWNER_PW}); other, _ = cookie_of(hd)
    st, _, _, _ = s.req('POST', '/api/v1/me/password', {'current': 'wrong', 'new': 'New owner password 2026'}, cookie=owner2); check('password change needs the current password', st == 403)
    st, _, _, _ = s.req('POST', '/api/v1/me/password', {'current': OWNER_PW, 'new': 'New owner password 2026'}, cookie=owner2); check('password change succeeds', st == 200, st)
    st, _, _, _ = s.req('GET', '/api/v1/me', cookie=other); check('password change signs out other sessions', st == 401, st)
    st, _, _, _ = s.req('GET', '/api/v1/me', cookie=owner2); check('…but keeps the current one', st == 200, st)
    st, _, _, _ = s.req('POST', '/api/v1/auth/logout', {}, cookie=owner2); st, _, _, _ = s.req('GET', '/api/v1/me', cookie=owner2); check('logout ends the session server-side', st == 401, st)

    print('\n== Password reset by email')
    import smtpsink as _sink, threading as _th2
    sport = socket.socket(); sport.bind(('127.0.0.1', 0)); mport = sport.getsockname()[1]; sport.close()
    mailbox = s.data + '.mail'
    _th2.Thread(target=_sink.run, args=(mport, mailbox), daemon=True).start(); time.sleep(0.3)
    st, js, _, hd = s.req('POST', '/api/v1/auth/login', {'username': 'tyowner', 'password': 'New owner password 2026'}); rc, _ = cookie_of(hd)
    s.req('PUT', '/api/v1/settings', {'settings': {'publicUrl': 'https://openroost.lan:8443', 'mail': {'mode': 'relay-existing', 'host': '127.0.0.1', 'port': str(mport), 'sec': 'none', 'from': 'alerts@example.com'}}}, cookie=rc)
    s.req('PATCH', '/api/v1/me', {'display': 'Ty', 'email': 'ty@example.com'}, cookie=rc)
    st1, js1, _, _ = s.req('POST', '/api/v1/auth/reset-request', {'login': 'tyowner'})
    st2, js2, _, _ = s.req('POST', '/api/v1/auth/reset-request', {'login': 'nobody-here'})
    check('reset request answers the same for real and unknown accounts', st1 == st2 == 200 and js1 == js2, (js1, js2))
    time.sleep(1.5); mail = open(mailbox).read() if os.path.exists(mailbox) else ''
    import re as _re
    m = _re.search(r'https://openroost\.lan:8443/\?reset=([0-9a-f]{64})', mail.replace('=\n', '').replace('=3D', '='))
    check('reset email sent, with a link on the saved web address (not the request Host)', bool(m), mail[:300])
    check('reset email is the branded HTML template', 'text/html' in mail and 'OpenRoost360' in mail)
    tok = m.group(1) if m else ''
    st, js, _, _ = s.req('POST', '/api/v1/auth/reset', {'token': tok, 'password': 'short'}); check('reset still enforces the password rules', st == 400, st)
    st, js, _, _ = s.req('POST', '/api/v1/auth/reset', {'token': tok, 'password': 'Brand new password 2027'}); check('reset link sets a new password', st == 200, (st, js))
    st, _, _, _ = s.req('GET', '/api/v1/me', cookie=rc); check('reset signs out existing sessions', st == 401, st)
    st, js, _, _ = s.req('POST', '/api/v1/auth/reset', {'token': tok, 'password': 'Another new password 2027'}); check('a reset link works once', st == 400, st)
    st, js, _, _ = s.req('POST', '/api/v1/auth/reset', {'token': 'a' * 64, 'password': 'Another new password 2027'}); check('made-up reset tokens are refused', st == 400, st)
    time.sleep(1.5); check('"password changed" email sent after the reset', 'Your password was changed' in open(mailbox).read())
    codes = [s.req('POST', '/api/v1/auth/reset-request', {'login': 'tyowner'})[0] for _ in range(6)]
    check('reset requests are throttled', codes[-1] == 429, codes)
    st, js, _, hd = s.req('POST', '/api/v1/auth/login', {'username': 'tyowner', 'password': 'Brand new password 2027'})
    s.req('POST', '/api/v1/me/password', {'current': 'Brand new password 2027', 'new': 'New owner password 2026'}, cookie=cookie_of(hd)[0])

    print('\n== Mobile app tokens')
    st, js, _, _ = s.req('POST', '/api/v1/auth/token', {'username': 'tyowner', 'password': 'New owner password 2026', 'deviceName': 'Pixel 9'})
    tok = js and js.get('token')
    check('app sign-in returns a bearer token', st == 200 and tok and tok.startswith('ort_'), (st, js))
    bh = {'Authorization': 'Bearer ' + (tok or ''), 'X-OpenRoost': None}
    st, js, _, _ = s.req('GET', '/api/v1/overview', headers=bh); check('bearer token reads data', st == 200 and 'hub' in js, st)
    st, js, _, _ = s.req('PUT', '/api/v1/settings', {'settings': {'siteName': 'Home'}}, headers=bh); check('bearer token writes without the CSRF header', st == 200, (st, js))
    st, js, _, hd = s.req('POST', '/api/v1/auth/login', {'username': 'tyowner', 'password': 'New owner password 2026'}); web, _ = cookie_of(hd)
    st, _, _, _ = s.req('GET', '/api/v1/me', headers={'Authorization': 'Bearer ' + web}); check("a browser cookie can't be used as an app token", st == 401, st)
    st, js, _, _ = s.req('GET', '/api/v1/me/sessions', headers=bh); check('device shows in the session list', any(x['kind'] == 'device' and x['name'] == 'Pixel 9' for x in js['sessions']))
    st, _, _, _ = s.req('POST', '/api/v1/auth/logout', {}, headers=bh); st, _, _, _ = s.req('GET', '/api/v1/me', headers=bh); check('logout revokes the app token', st == 401, st)

    print('\n== Planned features (501 for the app to show)')
    for m, p, fid in [('POST', '/api/v1/arm', 'hub.arm'), ('PUT', '/api/v1/hub/settings', 'hub.delays'), ('PUT', '/api/v1/sensors/2/alert-mode', 'sensors.alertMode'),
                      ('POST', '/api/v1/sensors/2/unpair', 'sensors.unpair'), ('POST', '/api/v1/hub/wifi/scan', 'hub.wifi')]:
        st, js, _, _ = s.req(m, p, {}, cookie=web); check(f'{m} {p} -> 501 planned ({fid})', st == 501 and js.get('feature') == fid and js.get('error') == 'Planned, unsupported', (st, js))

    print('\n== Invite links')
    s.req('PUT', '/api/v1/settings', {'settings': {'publicUrl': 'https://openroost.lan:8443'}}, cookie=web)
    st, js, _, _ = s.req('POST', '/api/v1/users/invites', {'role': 'wizard'}, cookie=web); check('invite: unknown role refused', st == 400, (st, js))
    st, js, _, _ = s.req('POST', '/api/v1/users/invites', {'role': 'member', 'hours': 999}, cookie=web); check('invite: expiry capped at 7 days', st == 400, (st, js))
    st, js, _, _ = s.req('POST', '/api/v1/users/invites', {'role': 'viewer', 'hours': 24, 'note': 'Grandma'}, cookie=web)
    link = js.get('link', ''); itok = link.split('invite=')[-1]
    check('owner creates an invite link on the saved web address', st == 200 and link.startswith('https://openroost.lan:8443/?invite=') and len(itok) == 43, js)
    st, js, txt, _ = s.req('GET', '/api/v1/users/invites', cookie=web)
    check('pending invites are listed without their links', st == 200 and len(js['invites']) == 1 and js['invites'][0]['note'] == 'Grandma' and itok not in txt, js)
    check('the invite token is not stored in the database', itok.encode() not in open(os.path.join(s.data, 'openroost.db'), 'rb').read())
    st, js, _, _ = s.req('POST', '/api/v1/auth/invite', {'token': 'x' * 43}); check('a made-up invite token is refused', st == 404, st)
    st, js, _, _ = s.req('POST', '/api/v1/auth/invite', {'token': itok}); check('invite link shows site and role before accepting', st == 200 and js['role'] == 'viewer' and js['by'] == 'tyowner', js)
    st, js, _, _ = s.req('POST', '/api/v1/auth/invite/accept', {'token': itok, 'username': 'grandma', 'password': 'short'}); check('invite: weak password refused', st == 400, st)
    st, js, _, hd = s.req('POST', '/api/v1/auth/invite/accept', {'token': itok, 'username': 'grandma', 'password': 'Knitting by the fire 1957', 'display': 'Grandma'})
    gck, _ = cookie_of(hd); check('accepting creates the account with the invite\'s role and signs in', st == 200 and js['user']['role'] == 'viewer' and gck, (st, js))
    st, js, _, _ = s.req('POST', '/api/v1/auth/invite/accept', {'token': itok, 'username': 'grandma2', 'password': 'Knitting by the fire 1957'}); check('an invite link works only once', st == 404, st)
    st, _, _, _ = s.req('POST', '/api/v1/users/invites', {'role': 'owner'}, cookie=gck); check('viewers can\'t create invites', st == 403, st)
    st, _, _, _ = s.req('POST', '/api/v1/users/invites', {'role': 'owner'}); check('creating invites needs sign-in', st == 401, st)
    st, js, _, _ = s.req('POST', '/api/v1/users/invites', {'role': 'member'}, cookie=web); tok2 = js['link'].split('invite=')[-1]
    s.req('DELETE', '/api/v1/users/invites/' + js['invite']['id'], cookie=web)
    st, _, _, _ = s.req('POST', '/api/v1/auth/invite', {'token': tok2}); check('a revoked invite stops working', st == 404, st)
    st, js, _, _ = s.req('POST', '/api/v1/users/invites', {'role': 'member'}, cookie=web); tok3 = js['link'].split('invite=')[-1]
    st, js, _, _ = s.req('POST', '/api/v1/auth/invite/accept', {'token': tok3, 'username': 'phoneuser', 'password': 'Purple phone sings 2026', 'deviceName': 'Pixel'})
    check('the app can accept an invite and gets a device token', st == 200 and js.get('token', '').startswith('ort_') and js['user']['role'] == 'member', js)
    st, js, _, _ = s.req('GET', '/api/v1/audit', cookie=web); check('invites are audited', any(a['action'] == 'invite.accept' for a in js['audit']))

    st, js, _, _ = s.req('GET', '/api/v1/services/bundled', cookie=web); check('bundled-services status for owners', st == 200 and 'pihole' in js and 'relay' in js, (st, js))
    st, _, _, _ = s.req('GET', '/api/v1/services/bundled'); check('bundled-services status needs sign-in', st == 401, st)
    st, js, _, _ = s.req('GET', '/api/v1/openapi.json'); check('OpenAPI lists planned endpoints', st == 200 and js['paths']['/api/v1/arm']['post'].get('x-planned') == 'hub.arm')
    st, js, _, _ = s.req('GET', '/api/v1/features'); check('feature list is public and marks planned ones', st == 200 and any(f['id'] == 'hub.arm' and f['status'] == 'planned' for f in js['features']))

    print('\n== Hub listener')
    from fakehub import FakeHub, status, sensor, CID
    h = FakeHub(s.lport); h.subscribe(); h.publish(status())
    st, js, _, _ = s.req('POST', '/api/v1/hub/claim', {}, cookie=web); check('owner claims the connected hub', st == 200 and js['claimed'] == h.dev, (st, js))
    h.publish(sensor(2, 'door', 14)); time.sleep(0.3)
    st, js, _, _ = s.req('GET', '/api/v1/sensors/2', cookie=web); check('hub events reach the API', st == 200 and js['state'] == 'open', js)
    st, js, _, _ = s.req('GET', '/api/v1/debug/wire?limit=100', cookie=web)
    kinds = [e['kind'] for e in js.get('entries', [])]
    check('protocol log records the hub session (tls, connect, subscribe, publish)', st == 200 and all(k in kinds for k in ('tls', 'connect', 'subscribe', 'publish', 'sent')), kinds)
    check('protocol log decodes the payload', any(e['kind'] == 'publish' and isinstance(e.get('json'), dict) and e['json'].get('dj', {}).get('ev') == 14 for e in js['entries']))
    check('protocol log shows JWT claims, not the signature', any(e['kind'] == 'connect' and 'jwt' in (e.get('password') or {}) for e in js['entries']) and 'sig' not in json.dumps([e for e in js['entries'] if e['kind'] == 'connect']))
    st, _, _, hd = s.req('POST', '/api/v1/auth/login', {'username': 'teen', 'password': 'Purple bicycle runs 77'}); vck, _ = cookie_of(hd)
    st, _, _, _ = s.req('GET', '/api/v1/debug/wire', cookie=vck); check('viewers can\'t read the protocol log', st == 403, st)
    def stream_sample(ck):
        c = http.client.HTTPConnection('127.0.0.1', s.port, timeout=4)
        c.request('GET', '/api/v1/stream', headers={'Host': f'127.0.0.1:{s.port}', 'Cookie': 'or360_sid=' + ck}); r = c.getresponse()
        threading.Timer(0.5, lambda: h.publish(sensor(2, 'door', 15))).start()
        buf, end = b'', time.time() + 2.5
        while time.time() < end:
            try: buf += r.fp.read1(4096)
            except Exception: break
        c.close(); return buf.decode(errors='replace')
    import threading
    check('live protocol-log entries reach owners', 'event: wire' in stream_sample(web))
    check('…and never viewers', 'event: wire' not in stream_sample(vck) )
    other = FakeHub(s.lport, client_id=CID.replace('z0a1b2c3d4e5f', 'z111111111111'))
    check('a second device claiming to be a hub is refused (CONNACK 5)', other.connack[1] == b'\x00\x05', other.connack)
    try: bad = FakeHub(s.lport, client_id='laptop'); refused = bad.connack[1] == b'\x00\x05'
    except OSError: refused = True
    check('a non-hub MQTT client is refused', refused)
    import ssl as _ssl
    raw = socket.create_connection(('127.0.0.1', s.lport), 5); c = _ssl.create_default_context(); c.check_hostname = False; c.verify_mode = _ssl.CERT_NONE
    t = c.wrap_socket(raw); t.sendall(b'\x10\xff\xff\xff\x7f')            # CONNECT claiming a 256 MB body
    try: closed = t.recv(10) == b''
    except OSError: closed = True
    check('oversized MQTT packet closes the connection', closed)
    st, js, _, _ = s.req('PUT', '/api/v1/settings', {'settings': {'duressSilent': True}}, cookie=web)
    h.publish(status(as_=4)); h.publish({'ev': '0', 'as': 0, 'da': 'ho'}); time.sleep(0.3)
    st, js, txt, _ = s.req('GET', '/api/v1/events?limit=50', cookie=web); check('silent duress: hostage-PIN event hidden from history', 'hostage' not in txt.lower(), txt[:200])
    st, js, _, _ = s.req('GET', '/api/v1/arm', cookie=web); check('silent duress: last disarm not labelled hostage', (js.get('lastDisarm') or {}).get('source') != 'ho', js)
    st, js, txt, _ = s.req('GET', '/api/v1/alerts', cookie=web); check('silent duress: no on-screen alert', 'duress' not in txt, txt)
    h.close()

    print('\n== Two-factor sign-in')
    from openroost.auth import _hotp
    st, js, _, _ = s.req('POST', '/api/v1/me/totp/setup', {}, cookie=web); secret = js['secret']
    now_code = _hotp(secret, int(time.time() // 30))
    st, js, _, _ = s.req('POST', '/api/v1/me/totp/enable', {'code': '000000' if now_code != '000000' else '111111'}, cookie=web); check("wrong code doesn't enable 2FA", st == 400)
    code = _hotp(secret, int(time.time() // 30))
    st, js, _, _ = s.req('POST', '/api/v1/me/totp/enable', {'code': code}, cookie=web); check('2FA enabled with a correct code', st == 200, (st, js))
    st, js, _, hd = s.req('POST', '/api/v1/auth/login', {'username': 'tyowner', 'password': 'New owner password 2026'})
    check('password alone no longer signs in', st == 200 and js.get('mfaRequired') and not cookie_of(hd)[0], js)
    ticket = js.get('ticket')
    st, js, _, _ = s.req('POST', '/api/v1/auth/totp', {'ticket': ticket, 'code': code}); check("the code used to enable 2FA can't be replayed", st == 401, st)
    time.sleep(max(0, 30 - time.time() % 30) + 0.5)
    code2 = _hotp(secret, int(time.time() // 30))
    st, js, _, hd = s.req('POST', '/api/v1/auth/totp', {'ticket': ticket, 'code': code2}); web2, _ = cookie_of(hd)
    check('ticket + fresh code signs in', st == 200 and web2, (st, js))
    st, js, _, _ = s.req('POST', '/api/v1/auth/totp', {'ticket': ticket, 'code': code2}); check('a sign-in ticket works once', st == 401, st)

    print('\n== Static files')
    for p in ['/../openroost/store.py', '/%2e%2e/openroost/store.py', '/../tests/test_security.py', '/..%2fopenroost%2fweb.py', '/.git/config',
              '/data/openroost.db', '//etc/passwd', '/kit.css/../../openroost/store.py', '/%2e%2e%2f%2e%2e%2fetc/passwd', '/../CLAUDE.md']:
        st, _, txt, _ = s.req('GET', p); check(f'blocked: {p}', st in (403, 404) and 'argon2' not in txt and 'def ' not in txt and 'import' not in txt, st)
    st, _, _, hd = s.req('GET', '/kit.css'); check('shared stylesheet still served', st == 200)
    hdr = {k.lower(): v for k, v in hd}
    for k in ('content-security-policy', 'x-content-type-options', 'x-frame-options', 'referrer-policy'):
        check(f'header {k} set', k in hdr)
    check("CSP forbids framing and plugins", "frame-ancestors 'none'" in hdr.get('content-security-policy', '') and "object-src 'none'" in hdr.get('content-security-policy', ''))
    check('server version not advertised', 'Python' not in hdr.get('server', ''))
    log = s.close()
    check('server log never contains a password or secret', not any(v in log for v in list(SECRETS.values()) + [OWNER_PW, 'New owner password 2026']))

    print('\n== HTTPS, proxies, rate limit, updates (fresh servers)')
    import ssl as _ssl, http.server as _hs, threading as _th
    class Tags(_hs.BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            b = json.dumps([{'name': 'v0.2.0'}, {'name': 'v0.1.0'}, {'name': 'not-a-version'}]).encode()
            self.send_response(200); self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    tags = _hs.HTTPServer(('127.0.0.1', 0), Tags); _th.Thread(target=tags.serve_forever, daemon=True).start()
    s = Server({'OPENROOST_TLS': 'on', 'OPENROOST_PROXY_IPS': '127.0.0.2', 'OPENROOST_UPDATE_URL': f'http://127.0.0.1:{tags.server_port}/tags'})
    ctx = _ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = _ssl.CERT_NONE
    def sreq(method, path, body=None, cookie=None):
        c = http.client.HTTPSConnection('127.0.0.1', s.hport, timeout=10, context=ctx)
        h = {'Host': f'127.0.0.1:{s.hport}', 'X-OpenRoost': '1', 'Content-Type': 'application/json', **({'Cookie': 'or360_sid=' + cookie} if cookie else {})}
        c.request(method, path, body=json.dumps(body).encode() if body is not None else None, headers=h)
        r = c.getresponse(); txt = r.read().decode(); der = c.sock.getpeercert(binary_form=True); c.close()
        return r.status, (json.loads(txt) if txt[:1] == '{' else None), r.getheaders(), der
    st, js, _, der = sreq('GET', '/api/v1/status')
    import hashlib as _hl
    fp = ':'.join(f'{b:02X}' for b in _hl.sha256(der).digest())
    check('HTTPS serves the API', st == 200 and js['secure'] is True, (st, js))
    check('the fingerprint in /status matches the certificate actually served', js['tlsFingerprint'] == fp, (js['tlsFingerprint'], fp))
    st, js, hd, _ = sreq('POST', '/api/v1/setup/complete', setup_body(s.code)); scookie = next((v for k, v in hd if k.lower() == 'set-cookie'), '')
    check('cookies are Secure over HTTPS', '; Secure' in scookie, scookie)
    st, _, _, hd = s.req('POST', '/api/v1/auth/login', {'username': 'tyowner', 'password': OWNER_PW})
    loc = next((v for k, v in hd if k.lower() == 'location'), '')
    check('plain HTTP is redirected to HTTPS (308, keeps the method)', st == 308 and loc.startswith(f'https://127.0.0.1:{s.hport}/'), (st, loc))
    old = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT); old.check_hostname = False; old.verify_mode = _ssl.CERT_NONE
    old.minimum_version = old.maximum_version = _ssl.TLSVersion.TLSv1_1
    try:
        old.set_ciphers('ALL:@SECLEVEL=0')
        with socket.create_connection(('127.0.0.1', s.hport), 5) as raw, old.wrap_socket(raw): weak = True
    except (_ssl.SSLError, OSError): weak = False
    check('TLS 1.1 and older are refused', not weak)
    st, js, txt, _ = s.req('GET', '/api/v1/status', headers={'X-Forwarded-Proto': 'https', 'X-Forwarded-For': '9.9.9.9'})
    check('X-Forwarded-* from an untrusted address is ignored (still redirected)', st == 308, st)
    scookie = scookie.split(';')[0].split('=', 1)[1]
    st, js, _, _ = sreq('GET', '/api/v1/version'); check('version details need sign-in', st == 401, st)
    st, js, _, _ = sreq('POST', '/api/v1/version/check', {}, cookie=scookie)
    check('update check finds the newest release tag', st == 200 and js['latest'] == 'v0.2.0' and js['updateAvailable'] is True and js['version'] == '0.1.0', js)
    st, js, _, _ = sreq('GET', '/api/v1/events?limit=10', cookie=scookie); check('an available update is noted in history', any('Update available: v0.2.0' in e['title'] for e in js['events']))
    st, js, _, _ = sreq('GET', '/api/v1/features'); check('update checks marked supported', any(f['id'] == 'admin.updates' and f['status'] == 'supported' for f in js['features']))
    s.close(); tags.shutdown()
    s = Server()
    codes = [s.req('GET', '/api/v1/features')[0] for _ in range(605)]
    check('per-address rate limit kicks in (600 requests a minute)', codes[-1] == 429 and codes[0] == 200, codes[-3:])
    s.close()

    print('\n== Master-key rotation (fresh server)')
    s = Server(); st, _, _, hd = s.req('POST', '/api/v1/setup/complete', setup_body(s.code)); oc, _ = cookie_of(hd)
    s.req('PUT', '/api/v1/settings', {'settings': {'hookUrl': 'http://127.0.0.1:9/h', 'hookSecret': 'webhook-secret-value-123'}}, cookie=oc)
    s.req('POST', '/api/v1/users', {'username': 'member1', 'password': 'Garden gnome party 88', 'role': 'member'}, cookie=oc)
    _, _, _, hd = s.req('POST', '/api/v1/auth/login', {'username': 'member1', 'password': 'Garden gnome party 88'}); mc, _ = cookie_of(hd)
    _, k0, _, _ = s.req('GET', '/api/v1/admin/key', cookie=oc); old_file = open(os.path.join(s.data, 'master.key'), 'rb').read()
    st, _, _, _ = s.req('GET', '/api/v1/admin/key', cookie=mc); check('only owners see the key status', st == 403, st)
    st, _, _, _ = s.req('POST', '/api/v1/admin/rotate-key', {'password': OWNER_PW}, cookie=mc); check('members can\'t rotate the key', st == 403, st)
    st, js, _, _ = s.req('POST', '/api/v1/admin/rotate-key', {'password': 'wrong password!!'}, cookie=oc); check('rotation needs the owner\'s password', st == 403, st)
    st, js, _, hd = s.req('POST', '/api/v1/admin/rotate-key', {'password': OWNER_PW}, cookie=oc); nc, _ = cookie_of(hd)
    check('rotation succeeds with a new key id', st == 200 and js['id'] != k0['id'] and js['sessionsEnded'] >= 2, js)
    check('master.key file replaced, still private', open(os.path.join(s.data, 'master.key'), 'rb').read() != old_file and oct(os.stat(os.path.join(s.data, 'master.key')).st_mode & 0o777) == '0o600')
    st, _, _, _ = s.req('GET', '/api/v1/me', cookie=mc); check('everyone else is signed out', st == 401, st)
    st, _, _, _ = s.req('GET', '/api/v1/me', cookie=oc); check('the old owner session is gone too', st == 401, st)
    st, js, _, _ = s.req('GET', '/api/v1/settings', cookie=nc); check('the rotating owner stays signed in (new session)', st == 200 and js['secretsSet']['hookSecret'], st)
    st, js, _, _ = s.req('GET', '/api/v1/admin/key', cookie=nc); check('the member is still on the old key until they sign in', js['accountsOnOldKey'] == 1, js)
    log = s.close(keep=True)
    db = open(os.path.join(s.data, 'openroost.db'), 'rb').read()
    check('secrets still not in plain text after rotation', b'webhook-secret-value-123' not in db)
    s2 = Server(data=s.data)
    st, js, _, hd = s2.req('POST', '/api/v1/auth/login', {'username': 'member1', 'password': 'Garden gnome party 88'})
    check('after a restart, the member signs in with their old password (old pepper kept)', st == 200, (st, js))
    _, _, _, hd = s2.req('POST', '/api/v1/auth/login', {'username': 'tyowner', 'password': OWNER_PW}); nc, _ = cookie_of(hd)
    st, js, _, _ = s2.req('GET', '/api/v1/admin/key', cookie=nc); check('…and is moved to the new key', js['accountsOnOldKey'] == 0, js)
    import sqlite3 as _sq
    con = _sq.connect(os.path.join(s.data, 'openroost.db')); peppers = con.execute("SELECT COUNT(*) FROM secrets WHERE name LIKE 'pepper:%'").fetchone()[0]; con.close()
    check('the old pepper is deleted once nobody needs it', peppers == 0, peppers)
    st, js, _, _ = s2.req('POST', '/api/v1/notify/test/webhook', {}, cookie=nc)
    check('re-encrypted secrets still decrypt (webhook test reads its secret)', st == 400 and 'reach' in js['error'].lower(), (st, js))
    s2.close(keep=True)
    open(os.path.join(s.data, 'master.key.next'), 'wb').write(os.urandom(32))
    s3 = Server(data=s.data); st, _, _, _ = s3.req('GET', '/api/v1/status')
    check('an interrupted rotation (stray master.key.next) is abandoned safely', st == 200 and not os.path.exists(os.path.join(s.data, 'master.key.next')), st)
    s3.close(keep=True)
    open(os.path.join(s.data, 'master.key'), 'wb').write(os.urandom(32))
    s4 = Server(data=s.data); time.sleep(1); log = s4.close()
    check('a master.key that doesn\'t match the database is refused at start-up', s4.proc.returncode not in (None, 0) and 'not the one this database was encrypted with' in log, log[-300:])
    s = Server(env={'OPENROOST_MASTER_KEY': base64.b64encode(os.urandom(32)).decode()}); _, _, _, hd = s.req('POST', '/api/v1/setup/complete', setup_body(s.code)); oc, _ = cookie_of(hd)
    st, js, _, _ = s.req('POST', '/api/v1/admin/rotate-key', {'password': OWNER_PW}, cookie=oc); check('a key from the environment isn\'t rotated (clear message)', st == 409 and 'OPENROOST_MASTER_KEY' in js['error'], js)
    s.close()

    print('\n== Brute force (fresh server)')
    s = Server()
    for _ in range(5): s.req('POST', '/api/v1/setup/complete', setup_body('AAAA-BBBB-CCCC'))
    st, _, _, _ = s.req('POST', '/api/v1/setup/complete', setup_body(s.code)); check('setup code locked after 5 wrong tries', st == 429, st)
    s.close()
    s = Server(); st, _, _, _ = s.req('POST', '/api/v1/setup/complete', setup_body(s.code))
    t0 = time.time(); st, js1, _, _ = s.req('POST', '/api/v1/auth/login', {'username': 'nobody', 'password': 'x'}); t_unknown = time.time() - t0
    t0 = time.time(); st, js2, _, _ = s.req('POST', '/api/v1/auth/login', {'username': 'tyowner', 'password': 'wrong one'}); t_known = time.time() - t0
    check('same error for unknown user and wrong password', js1 == js2, (js1, js2))
    check('similar timing for unknown vs known user', abs(t_unknown - t_known) < 0.25, f'{t_unknown:.3f}s vs {t_known:.3f}s')
    for _ in range(3): s.req('POST', '/api/v1/auth/login', {'username': 'tyowner', 'password': 'wrong'})
    st, js, _, _ = s.req('POST', '/api/v1/auth/login', {'username': 'tyowner', 'password': OWNER_PW}); check('login locked after 5 failures, even with the right password', st == 429, st)
    s.close()

    failed = [r for r in results if not r[1]]
    print(f'\n{len(results) - len(failed)}/{len(results)} passed')
    for n, _, d in failed: print('  FAILED:', n, d)
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
