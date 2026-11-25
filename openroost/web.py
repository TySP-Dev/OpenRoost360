"""OpenRoost360 HTTP server: the web app and API v1 (also used by the mobile app).

Auth
  * Browser: POST /api/v1/auth/login -> HttpOnly, SameSite=Strict cookie. State-changing calls
    must carry X-OpenRoost: 1 and a same-origin Origin (CSRF guard).
  * Mobile app: POST /api/v1/auth/token -> bearer token (`Authorization: Bearer ort_…`), 90-day
    sliding, revocable per device. No CSRF header needed (browsers can't send it cross-site).
  * Optional: TOTP codes, Authentik (OpenID Connect), trusted reverse-proxy header.
Live data: GET /api/v1/stream (server-sent events). Planned features answer 501 with
{"error": "Planned, unsupported", "feature": "<id>"} — see GET /api/v1/features.
"""
from html import escape as html_escape
import collections, http.server, ipaddress, json, os, re, secrets, socket, ssl, sys, threading, time, urllib.parse
from http import cookies
from urllib.parse import urlsplit, parse_qs

from . import __version__, auth, backup, emails, features, services
from .notify import NotifyError, Notifier
from .services import ServiceError
from .hub import MANUAL_TYPES
from .store import ROLES, SECRET_PATHS, V, ValidationError

MAX_BODY = 64 * 1024
COOKIE = 'or360_sid'
TTL = {'1h': 3600, '12h': 12 * 3600, '1d': 86400, '7d': 7 * 86400, '30d': 30 * 86400}
DEVICE_TTL = 90 * 86400
FAIL_WINDOW, FAIL_LIMIT, LOCK_FOR = 15 * 60, 5, 15 * 60
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
       "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
       "form-action 'self'; object-src 'none'")
RANK = {'viewer': 0, 'member': 1, 'owner': 2}
RATE_WINDOW, RATE_LIMIT, STREAMS_PER_IP = 60, 600, 8          # requests per address per minute; open live streams per address


class RateLimit:
    def __init__(self): self.hits, self.streams, self.lock = collections.defaultdict(collections.deque), collections.Counter(), threading.Lock()

    def allow(self, ip):
        now = time.time()
        with self.lock:
            q = self.hits[ip]
            while q and q[0] < now - RATE_WINDOW: q.popleft()
            if len(q) >= RATE_LIMIT: return False
            q.append(now)
            if len(self.hits) > 5000: self.hits = collections.defaultdict(collections.deque, {k: v for k, v in self.hits.items() if v and v[-1] > now - RATE_WINDOW})
            return True

    def stream(self, ip, delta):
        with self.lock:
            if delta > 0 and self.streams[ip] >= STREAMS_PER_IP: return False
            self.streams[ip] += delta
            return True


class ApiError(Exception):
    def __init__(self, code, msg, **extra): super().__init__(msg); self.status, self.msg, self.extra = code, msg, extra


class Planned(ApiError):
    def __init__(self, fid):
        super().__init__(501, 'Planned, unsupported', feature=fid, status='planned', summary=features.FEATURES[fid][1])


class Throttle:
    """Failed attempts per key, persisted in the database so a restart doesn't reset them."""
    def __init__(self, store): self.store, self.lock = store, threading.Lock()

    def blocked(self, *keys):
        now = time.time()
        with self.lock: return max((self.store.throttle_get(k)[1] - now for k in keys), default=0)

    def fail(self, *keys):
        now = time.time()
        with self.lock:
            for k in keys:
                fails, _ = self.store.throttle_get(k)
                fails = [t for t in fails if t > now - FAIL_WINDOW] + [now]
                if len(fails) >= FAIL_LIMIT: self.store.throttle_set(k, [], now + LOCK_FOR)
                else: self.store.throttle_set(k, fails, 0)

    def ok(self, *keys):
        with self.lock:
            for k in keys: self.store.throttle_set(k, [], 0)


class App:
    def __init__(self, store, hub, notifier, web_root, listener_port, extra_hosts=(), https_port=None, proxies=(), tls_fingerprint=None, updates=None):
        self.store, self.hub, self.notifier, self.web_root = store, hub, notifier, os.path.realpath(web_root)
        self.listener_port, self.extra_hosts = listener_port, set(extra_hosts)
        self.https_port, self.proxies, self.fingerprint, self.updates = https_port, set(proxies), tls_fingerprint, updates
        self.rate = RateLimit()
        self.throttle, self.oidc = Throttle(store), auth.Oidc()
        self.keep_nat = self.find_hub = None              # set by __main__: re-check the port redirect / look for the hub in Pi-hole
        self._hub_search = 0
        self.setup_lock, self.invite_lock, self.mfa = threading.Lock(), threading.Lock(), {}          # mfa: ticket -> (uid, remember, expires, kind, name)
        self.dummy_hash = store.keys.hash_password(os.urandom(16).hex())
        self.routes = []
        self._register()

    # ------------------------------------------------------------- route table
    def route(self, method, pattern, need=None, summary='', planned=None, tags=()):
        def deco(fn):
            self.routes.append({'method': method, 'pattern': pattern, 'rx': re.compile(pattern.replace('{id}', r'(\d{1,9})').replace('{sid}', r'([0-9a-f]{16})').replace('{iid}', r'([0-9a-f]{12})')
                                .replace('{kind}', r'([a-z_]{2,20})').replace('{channel}', r'([a-z]{2,10})').replace('{fix}', r'([a-z]{2,10})') + '$'),
                                'fn': fn, 'need': need, 'summary': summary, 'planned': planned, 'tags': tags})
            return fn
        return deco

    def planned(self, method, pattern, fid, need='owner', summary=''):
        def fn(h, sess, *a): raise Planned(fid)
        self.route(method, pattern, need, summary or features.FEATURES[fid][1], planned=fid)(fn)

    # ------------------------------------------------------------- helpers
    def public_user(self, u):
        return {'id': u['id'], 'username': u['username'], 'display': u['display'], 'role': u['role'], 'email': u.get('email', ''), 'totp': u.get('totp_on', False), 'sso': bool(u.get('oidc_sub'))}

    def ttl_for(self, remember):
        return TTL['30d'] if remember else TTL.get(self.store.get_settings().get('sessionLen'), TTL['12h'])

    def need_setup_code(self, h, code):
        if self.store.setup_done(): raise ApiError(409, 'Setup is already done. Sign in to change settings.')
        if self.throttle.blocked('setup:' + h.ip) > 0: raise ApiError(429, 'Too many wrong setup codes. Wait 15 minutes.', retryAfter=LOCK_FOR)
        if not self.store.check_setup_code(code):
            self.throttle.fail('setup:' + h.ip); self.store.audit('-', h.ip, 'setup.code_wrong')
            raise ApiError(403, 'That setup code is wrong. It is printed in the server log and saved in the data folder as SETUP-CODE.txt.')

    def oidc_redirect(self, h):
        """The redirect URI sent to Authentik: the dashboard address set in Settings → System when there is one (it must
        match what's registered in Authentik exactly), else the address this browser used."""
        pub = (self.store.get_settings().get('publicUrl') or '').strip().rstrip('/')
        if pub and urlsplit(pub).netloc.lower() == (h.headers.get('Host') or '').lower(): return pub + '/api/v1/auth/oidc/callback'
        return h.origin() + '/api/v1/auth/oidc/callback'

    def snapshot_settings(self):
        return {'settings': self.store.get_settings(), 'secretsSet': self.store.secrets_set()}

    def _register(self):
        R, P, st, hub = self.route, self.planned, self.store, self.hub
        app_fp = lambda: self.fingerprint

        # ============================================================ public
        @R('GET', '/api/v1/status', summary='Is setup done, am I signed in, which sign-in options exist', tags=('auth',))
        def status(h, sess):
            s = st.get_settings()
            h.send_json(200, {'setupDone': st.setup_done(), 'signedIn': bool(sess), 'secure': h.secure(), 'tlsFingerprint': app_fp(),
                              'sso': {'on': bool(s.get('ssoOn') and s.get('ssoIssuer') and s.get('ssoClientId')), 'button': s.get('ssoButton') or 'Sign in with Authentik'},
                              'localLogin': s.get('ssoLocal', True) or not s.get('ssoOn')})

        @R('GET', '/api/v1/features', summary='Supported and planned features', tags=('meta',))
        def feats(h, sess): h.send_json(200, {'features': features.listing()})

        @R('GET', '/api/v1/openapi.json', summary='This API, as OpenAPI 3.1', tags=('meta',))
        def openapi(h, sess): h.send_json(200, self.openapi())

        # ============================================================ first-run setup (needs the setup code)
        @R('POST', '/api/v1/setup/verify', summary='Check a setup code', tags=('setup',))
        def setup_verify(h, sess):
            self.need_setup_code(h, h.body().get('code')); h.send_json(200, {'ok': True})

        @R('POST', '/api/v1/setup/checks', summary='Server checks during setup', tags=('setup',))
        def setup_checks(h, sess):
            b = h.body(); self.need_setup_code(h, b.get('code'))
            if b.get('ph'): self._temp_ph(b['ph'])
            h.send_json(200, {'checks': services.checks(st, hub, self.listener_port), 'serverIp': services.server_ip(st.get_settings())})

        @R('POST', '/api/v1/setup/pihole', summary='Test an existing Pi-hole during setup', tags=('setup',))
        def setup_pihole(h, sess):
            b = h.body(); self.need_setup_code(h, b.get('code'))
            try: h.send_json(200, services.pihole_test(b.get('url'), b.get('password')))
            except ServiceError as e: raise ApiError(400, str(e))

        @R('POST', '/api/v1/setup/fix/{fix}', summary='Fix a failed setup check (dns, nat)', tags=('setup',))
        def setup_fix(h, sess, fix):
            b = h.body(); self.need_setup_code(h, b.get('code'))
            if b.get('ph'): self._temp_ph(b['ph'])
            h.send_json(200, self.fix(fix, (b.get('ip') or '').strip() or None))

        @R('POST', '/api/v1/setup/state', summary='Hub, listener and sensors seen so far (setup)', tags=('setup',))
        def setup_state(h, sess):
            self.need_setup_code(h, h.body().get('code'))
            targets = services.hub_targets(st, hub)
            if not targets and self.find_hub and time.time() - self._hub_search > 20:          # look in Pi-hole's query log
                self._hub_search = time.time(); threading.Thread(target=self.find_hub, daemon=True).start()
            nat = [{'ip': ip, 'status': services.nat_check(ip, self.listener_port)[0]} for ip in targets]
            h.send_json(200, {'listener': hub.listener_view(), 'hub': hub.hub_view(), 'sensors': hub.sensors_view(), 'nat': nat,
                              'hubSeen': st.kv('hubSeen'), 'hubIp': st.get_settings().get('hubIp') or ''})

        @R('POST', '/api/v1/setup/mail-test', summary='Send a test email with the settings being set up', tags=('setup',))
        def setup_mail(h, sess):
            b = h.body(); self.need_setup_code(h, b.get('code'))
            mail = dict(b.get('mail') or {})
            secret = mail.pop('pass', '') or ''
            s = dict(st.get_settings()); s['mail'] = mail
            class Tmp:   # send with unsaved settings and an unsaved secret
                def get_secret(self_, name): return secret if name == 'mail.pass' else None
            n = Notifier.__new__(Notifier); n.store = Tmp()
            text, html = emails.test(b.get('site') or 'Home')
            try: h.send_json(200, {'result': n.send_email(s, [mail.get('to')], 'Test from OpenRoost360', text, html)})
            except NotifyError as e: raise ApiError(400, str(e))

        @R('POST', '/api/v1/setup/bundled', summary='Which bundled services (Pi-hole, mail relay) are running (setup)', tags=('setup',))
        def setup_bundled(h, sess):
            self.need_setup_code(h, h.body().get('code')); h.send_json(200, services.bundled())

        @R('POST', '/api/v1/setup/matrix-login', summary='Sign the Matrix bot in during setup; stores only the access token', tags=('setup',))
        def setup_mx_login(h, sess):
            b = h.body(); self.need_setup_code(h, b.get('code'))
            V.url(b.get('hs') or ''); V.str(255)(b.get('user') or '')
            try: tok, note, base = self.notifier.matrix_login(b.get('hs') or '', b.get('user') or '', b.get('password') or '')
            except NotifyError as e: raise ApiError(400, str(e))
            st.save_settings({'mxToken': tok, 'mxHs': base, 'mxUser': b['user']}); h.send_json(200, {'ok': True, 'note': note, 'hs': base, 'e2ee': self.notifier.crypto.status()})

        @R('POST', '/api/v1/setup/matrix-test', summary='Send a Matrix test message during setup', tags=('setup',))
        def setup_mx_test(h, sess):
            b = h.body(); self.need_setup_code(h, b.get('code'))
            s = dict(st.get_settings()); s['mxRoom'] = V.str(255)(b.get('room') or '')
            try: h.send_json(200, {'result': self.notifier.send_matrix(s, f'[{b.get("site") or "Home"}] Test from OpenRoost360', 'If you can read this, Matrix alerts work.')})
            except NotifyError as e: raise ApiError(400, str(e))

        @R('POST', '/api/v1/setup/complete', summary='Finish setup: create the owner account and save everything', tags=('setup',))
        def setup_complete(h, sess):
            with self.setup_lock:
                b = h.body(); self.need_setup_code(h, b.get('code'))
                admin = b.get('admin') or {}
                uid = st.create_user(admin.get('username'), admin.get('password'), 'owner', admin.get('display', ''), admin.get('email', ''))
                try:
                    st.save_settings(b.get('settings') or {}, merge=False)
                except Exception:
                    st.q('DELETE FROM users WHERE id=?', uid); raise
                if b.get('hubId') and hub.status.get('id') == b['hubId']: hub.claim_hub(b['hubId'], hub.status.get('ip'))
                st.set_meta('setup_done', '1'); st.q("DELETE FROM meta WHERE key='setup_code'")
                try: os.remove(os.path.join(os.path.dirname(st.path), 'SETUP-CODE.txt'))
                except FileNotFoundError: pass
                token, _ = st.new_session(uid, h.ip, h.headers.get('User-Agent'), TTL['12h'])
                st.audit(admin.get('username'), h.ip, 'setup.complete', 'owner account created')
                h.send_json(200, {'ok': True, 'user': self.public_user(st.user(uid))}, set_cookie=h.cookie(token, TTL['12h']))

        # ============================================================ auth
        def check_login(h, b):
            name = str(b.get('username') or '').strip()[:64]; pw = b.get('password') or ''
            keys = ('ip:' + h.ip, 'user:' + name.lower())
            wait = self.throttle.blocked(*keys)
            if wait > 0: raise ApiError(429, f'Too many failed sign-ins. Try again in {int(wait // 60) + 1} min.', retryAfter=wait)
            s = st.get_settings()
            if s.get('ssoOn') and not s.get('ssoLocal', True): raise ApiError(403, 'Password sign-in is turned off. Use single sign-on.')
            u = st.user_by_name(name)
            ok = st.keys.verify_password(pw, u['pw_hash'] if u else self.dummy_hash) and u is not None
            if not ok:
                self.throttle.fail(*keys); st.audit(name or '-', h.ip, 'login.fail'); raise ApiError(401, 'Wrong username or password')
            self.throttle.ok(*keys); st.rehash_if_old(u['id'], pw)
            return u, keys

        def finish_login(h, u, remember, kind='web', name='', old_sid=None):
            if kind == 'device':
                token, sid = st.new_session(u['id'], h.ip, h.headers.get('User-Agent'), DEVICE_TTL, 'device', name or 'Mobile app')
                st.audit(u['username'], h.ip, 'token.issue', name)
                return h.send_json(200, {'token': token, 'tokenType': 'Bearer', 'expiresIn': DEVICE_TTL, 'user': self.public_user(u)})
            if old_sid: st.end_session(old_sid)                      # no session fixation
            ttl = self.ttl_for(remember)
            token, _ = st.new_session(u['id'], h.ip, h.headers.get('User-Agent'), ttl)
            st.audit(u['username'], h.ip, 'login.ok')
            h.send_json(200, {'user': self.public_user(u)}, set_cookie=h.cookie(token, ttl))

        def mfa_or_finish(h, sess, u, b, kind):
            if u.get('totp_on'):
                code = b.get('totp')
                if code: return verify_totp_then(h, u, code, lambda: finish_login(h, u, b.get('remember'), kind, b.get('deviceName'), sess and sess['sid']))
                ticket = os.urandom(18).hex()
                self.mfa = {k: v for k, v in self.mfa.items() if v[2] > time.time()}
                self.mfa[ticket] = (u['id'], bool(b.get('remember')), time.time() + 300, kind, b.get('deviceName', ''))
                return h.send_json(200, {'mfaRequired': True, 'ticket': ticket})
            finish_login(h, u, b.get('remember'), kind, b.get('deviceName'), sess and sess['sid'])

        def verify_totp_then(h, u, code, then):
            key = 'totp:' + str(u['id'])
            if self.throttle.blocked(key) > 0: raise ApiError(429, 'Too many wrong codes. Wait 15 minutes.', retryAfter=LOCK_FOR)
            last = st.kv(f'totp_last:{u["id"]}', 0)
            step = auth.totp_verify(st.user_totp_secret(u['id']), code, last)
            if step is None: self.throttle.fail(key); st.audit(u['username'], h.ip, 'totp.fail'); raise ApiError(401, 'That code isn\'t right')
            st.set_kv(f'totp_last:{u["id"]}', step); self.throttle.ok(key)
            then()

        @R('POST', '/api/v1/auth/login', summary='Browser sign-in (sets the session cookie)', tags=('auth',))
        def login(h, sess):
            b = h.body(); u, _ = check_login(h, b); mfa_or_finish(h, sess, u, b, 'web')

        @R('POST', '/api/v1/auth/token', summary='Mobile app sign-in: returns a bearer token for this device', tags=('auth',))
        def token(h, sess):
            b = h.body(); V.str(60)(b.get('deviceName', '') or ''); u, _ = check_login(h, b); mfa_or_finish(h, None, u, b, 'device')

        @R('POST', '/api/v1/auth/totp', summary='Second step of sign-in: the authenticator code', tags=('auth',))
        def login_totp(h, sess):
            b = h.body(); t = self.mfa.get(b.get('ticket') or '')
            if not t or t[2] < time.time(): raise ApiError(401, 'Sign-in timed out. Start again.')
            u = st.user(t[0])
            def done():
                self.mfa.pop(b.get('ticket'), None); finish_login(h, u, t[1], t[3], t[4], sess and sess['sid'])
            verify_totp_then(h, u, b.get('code'), done)

        RESET_MIN = 30

        @R('POST', '/api/v1/auth/reset-request', summary='Email a password-reset link: {"login": username or email}. Always answers the same way', tags=('auth',))
        def reset_request(h, sess):
            b = h.body(); login = str(b.get('login') or '').strip()[:254]
            keys = ('reset-ip:' + h.ip, 'reset-user:' + login.lower())
            if self.throttle.blocked(*keys) > 0: raise ApiError(429, 'Too many reset requests. Try again in 15 minutes.', retryAfter=LOCK_FOR)
            self.throttle.fail(*keys)                                   # every request counts: max 5 per 15 minutes
            s = st.get_settings()
            u = st.user_by_name(login) or next((st.user(x['id']) for x in st.users() if x['email'] and x['email'].lower() == login.lower()), None)
            if u and u['email'] and not u.get('oidc_sub') and s.get('publicUrl') and (s.get('mail') or {}).get('mode') not in (None, 'off'):
                token = os.urandom(32).hex()
                st.set_kv('reset:' + st.keys.token_hash(token), {'uid': u['id'], 'exp': time.time() + RESET_MIN * 60})
                link = s['publicUrl'].rstrip('/') + '/?reset=' + token
                text, html = emails.reset(s.get('siteName') or 'Home', u['display'], link, RESET_MIN)
                self.mail_user(u, 'Reset your OpenRoost360 password', text, html)
                st.audit(u['username'], h.ip, 'password.reset_requested')
            else:
                st.audit(login or '-', h.ip, 'password.reset_requested', 'no email sent')
            h.send_json(200, {'ok': True, 'message': 'If that account has an email address, a reset link is on its way. It expires in 30 minutes.'})

        @R('POST', '/api/v1/auth/reset', summary='Set a new password with a reset link: {"token", "password"}', tags=('auth',))
        def reset_do(h, sess):
            b = h.body(); tok = str(b.get('token') or '')
            if self.throttle.blocked('reset-tok:' + h.ip) > 0: raise ApiError(429, 'Too many attempts. Wait 15 minutes.', retryAfter=LOCK_FOR)
            key = 'reset:' + st.keys.token_hash(tok) if re.fullmatch(r'[0-9a-f]{64}', tok) else None
            rec = st.kv(key) if key else None
            if not rec or rec['exp'] < time.time():
                self.throttle.fail('reset-tok:' + h.ip); raise ApiError(400, 'This reset link is invalid or has expired. Ask for a new one.')
            u = st.user(rec['uid'])
            if not u: raise ApiError(400, 'This reset link is invalid or has expired.')
            st.set_password(u['id'], b.get('password'))
            st.q('DELETE FROM hub_kv WHERE key=?', key); st.end_other_sessions(u['id'])
            st.audit(u['username'], h.ip, 'password.reset')
            text, html = emails.password_changed(st.get_settings().get('siteName') or 'Home', u['display'], h.ip)
            self.mail_user(u, 'Your OpenRoost360 password was changed', text, html)
            h.send_json(200, {'ok': True})

        @R('POST', '/api/v1/auth/logout', 'viewer', summary='Sign out this browser or device', tags=('auth',))
        def logout(h, sess):
            st.end_session(sess['sid']); st.audit(sess['user']['username'], h.ip, 'logout')
            h.send_json(200, {'ok': True}, set_cookie=h.cookie('', 0) if sess['kind'] == 'web' else None)

        @R('GET', '/api/v1/auth/oidc/start', summary='Start single sign-on (redirects to Authentik). ?link=1 while signed in links your account instead', tags=('auth',))
        def oidc_start(h, sess):
            s = st.get_settings()
            if not (s.get('ssoOn') and s.get('ssoIssuer') and s.get('ssoClientId')): raise ApiError(404, 'Single sign-on isn\'t set up')
            q = parse_qs(urlsplit(h.path).query)
            link = sess['user']['id'] if sess and sess.get('sid') and q.get('link', [''])[0] == '1' else None
            try: url = self.oidc.start(s, self.oidc_redirect(h), q.get('remember', [''])[0] == '1', link)
            except auth.OidcError as e: return h.redirect('/?ssoError=' + urllib.parse.quote(str(e)))
            h.redirect(url)

        def land(h, to='/', set_cookie=None):
            """After the provider sends the browser back, go on with a same-site navigation: a redirect chain that began
            on the provider's site is cross-site, and browsers would hold back the SameSite=Strict session cookie."""
            body = (f'<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url={html_escape(to)}">'
                    f'<title>Signing in…</title><p style="font-family:sans-serif">Signing in… <a href="{html_escape(to)}">Continue</a></p>').encode()
            h.send_bytes(200, body, 'text/html; charset=utf-8', set_cookie=set_cookie)

        @R('GET', '/api/v1/auth/oidc/callback', summary='Single sign-on return address (set this in Authentik)', tags=('auth',))
        def oidc_cb(h, sess):
            q = parse_qs(urlsplit(h.path).query); s = st.get_settings()
            try:
                if q.get('error'): raise auth.OidcError(q.get('error_description', q['error'])[0])
                claims, remember, link = self.oidc.finish(s, st.get_secret('ssoSecret'), q.get('state', [''])[0], q.get('code', [''])[0])
                u = st.user_by_oidc(claims['sub']); role = auth.role_from_groups(s, claims.get('groups'))
                if link:                                                 # "Link Authentik" from Settings → Account
                    me_ = st.user(link)
                    if not me_: raise auth.OidcError('Your account is gone')
                    if u and u['id'] != link: raise auth.OidcError('That Authentik user is already linked to another OpenRoost account')
                    st.link_oidc(link, claims['sub']); st.audit(me_['username'], h.ip, 'sso.linked', claims.get('preferred_username') or '')
                    return land(h, '/#settings/account')
                if not u:
                    if not s.get('ssoAutoCreate'): raise auth.OidcError('No OpenRoost account is linked to this Authentik user. Sign in with your password and use Settings → Account → Link Authentik, or turn on “Create accounts on first sign-in”.')
                    base = re.sub(r'[^A-Za-z0-9._-]', '', claims.get('preferred_username') or claims.get('email', '').split('@')[0] or 'user')[:28] or 'user'
                    name = base if len(base) >= 3 else base + '_sso'
                    while st.user_by_name(name): name = f'{base[:24]}{os.urandom(2).hex()}'
                    uid = st.create_user(name, os.urandom(24).hex() + 'Aa!', role or 'viewer', (claims.get('name') or name)[:80], '')
                    st.link_oidc(uid, claims['sub']); u = st.user(uid); st.audit(name, h.ip, 'sso.account_created', role or 'viewer')
                elif role and u['role'] != role and not (u['role'] == 'owner' and st.owners() <= 1):
                    st.q('UPDATE users SET role=? WHERE id=?', role, u['id']); u = st.user(u['id'])
                ttl = self.ttl_for(remember)
                token, _ = st.new_session(u['id'], h.ip, h.headers.get('User-Agent'), ttl)
                st.audit(u['username'], h.ip, 'login.sso')
                land(h, '/', h.cookie(token, ttl))
            except auth.OidcError as e:
                st.audit('-', h.ip, 'login.sso_fail', str(e)); land(h, '/?ssoError=' + urllib.parse.quote(str(e)))

        @R('POST', '/api/v1/me/sso/unlink', 'viewer', summary='Unlink your Authentik account (needs your password)', tags=('me',))
        def sso_unlink(h, sess):
            b = h.body(); u = sess['user']
            if self.throttle.blocked('pw:' + str(u['id'])) > 0: raise ApiError(429, 'Too many wrong passwords. Wait 15 minutes.', retryAfter=LOCK_FOR)
            if not st.keys.verify_password(b.get('password') or '', u['pw_hash']):
                self.throttle.fail('pw:' + str(u['id'])); raise ApiError(403, 'Wrong password')
            st.q('UPDATE users SET oidc_sub=NULL WHERE id=?', u['id']); st.audit(u['username'], h.ip, 'sso.unlinked'); h.send_json(200, {'ok': True})

        # ============================================================ me
        @R('GET', '/api/v1/me', 'viewer', summary='The signed-in user', tags=('me',))
        def me(h, sess): h.send_json(200, {'user': self.public_user(sess['user']), 'sessionId': sess['sid'], 'sessionKind': sess['kind']})

        @R('PATCH', '/api/v1/me', 'viewer', summary='Change display name or email', tags=('me',))
        def me_edit(h, sess):
            b, u = h.body(), sess['user']
            display = b.get('display', u['display']); email = b.get('email', u['email'])
            if not isinstance(display, str) or not 0 < len(display.strip()) <= 80: raise ValidationError({'display': '1–80 characters'})
            V.str(80)(display); V.email(email)
            st.q('UPDATE users SET display=?, email=? WHERE id=?', display.strip(), email, u['id']); st.audit(u['username'], h.ip, 'profile.edit')
            h.send_json(200, {'user': self.public_user(st.user(u['id']))})

        @R('POST', '/api/v1/me/password', 'viewer', summary='Change password (signs out other sessions)', tags=('me',))
        def me_pw(h, sess):
            b, u = h.body(), sess['user']
            if self.throttle.blocked('pw:' + str(u['id'])) > 0: raise ApiError(429, 'Too many wrong passwords. Wait 15 minutes.', retryAfter=LOCK_FOR)
            if not st.keys.verify_password(b.get('current') or '', u['pw_hash']):
                self.throttle.fail('pw:' + str(u['id'])); raise ApiError(403, 'Current password is wrong')
            st.set_password(u['id'], b.get('new')); st.end_other_sessions(u['id'], sess['sid'])
            st.audit(u['username'], h.ip, 'password.change', 'other sessions signed out')
            text, html = emails.password_changed(st.get_settings().get('siteName') or 'Home', u['display'], h.ip)
            self.mail_user(u, 'Your OpenRoost360 password was changed', text, html)
            h.send_json(200, {'ok': True})

        @R('GET', '/api/v1/me/sessions', 'viewer', summary='My browsers and app devices', tags=('me',))
        def my_sessions(h, sess):
            h.send_json(200, {'sessions': [dict(x, current=x['id'] == sess['sid']) for x in st.sessions_for(sess['user']['id'])]})

        @R('DELETE', '/api/v1/me/sessions/{sid}', 'viewer', summary='Sign out one browser or device', tags=('me',))
        def my_session_end(h, sess, target):
            st.end_session(target, sess['user']['id']); st.audit(sess['user']['username'], h.ip, 'session.revoke', target)
            h.send_json(200, {'ok': True}, set_cookie=h.cookie('', 0) if target == sess['sid'] and sess['kind'] == 'web' else None)

        @R('POST', '/api/v1/me/totp/setup', 'viewer', summary='Start two-factor setup: returns a secret and otpauth URI', tags=('me',))
        def totp_setup(h, sess):
            u = sess['user']
            if u.get('totp_on'): raise ApiError(409, 'Two-factor sign-in is already on')
            secret = auth.totp_new_secret(); st.set_kv(f'totp_pending:{u["id"]}', {'s': st.keys.seal(f'totp-pending:{u["id"]}', secret).hex(), 't': time.time()})
            h.send_json(200, {'secret': secret, 'uri': auth.totp_uri(secret, u['username'])})

        @R('POST', '/api/v1/me/totp/enable', 'viewer', summary='Confirm two-factor setup with a code', tags=('me',))
        def totp_enable(h, sess):
            u = sess['user']; p = st.kv(f'totp_pending:{u["id"]}')
            if not p or p['t'] < time.time() - 900: raise ApiError(400, 'Start two-factor setup again')
            secret = st.keys.open(f'totp-pending:{u["id"]}', bytes.fromhex(p['s']))
            step = auth.totp_verify(secret, h.body().get('code'))
            if step is None: raise ApiError(400, 'That code isn\'t right. Check the time on your phone.')
            st.set_user_totp(u['id'], secret); st.set_kv(f'totp_last:{u["id"]}', step); st.set_kv(f'totp_pending:{u["id"]}', None)
            st.end_other_sessions(u['id'], sess['sid']); st.audit(u['username'], h.ip, 'totp.enable'); h.send_json(200, {'ok': True})

        @R('POST', '/api/v1/me/totp/disable', 'viewer', summary='Turn two-factor sign-in off (needs the password)', tags=('me',))
        def totp_disable(h, sess):
            u = sess['user']
            if not st.keys.verify_password(h.body().get('password') or '', u['pw_hash']): raise ApiError(403, 'Password is wrong')
            st.set_user_totp(u['id'], None); st.audit(u['username'], h.ip, 'totp.disable'); h.send_json(200, {'ok': True})

        # ============================================================ home & hub (read)
        @R('GET', '/api/v1/overview', 'viewer', summary='Everything the home screen needs in one call', tags=('hub',))
        def overview(h, sess): h.send_json(200, hub.overview())

        @R('GET', '/api/v1/hub', 'viewer', summary='Hub status', tags=('hub',))
        def hub_get(h, sess): h.send_json(200, hub.hub_view())

        @R('GET', '/api/v1/arm', 'viewer', summary='Arm state and countdown', tags=('hub',))
        def arm_get(h, sess): h.send_json(200, hub.arm_view())

        P('POST', '/api/v1/arm', 'hub.arm', need='member', summary='Arm or disarm: {"mode": "off" | "home" | "away", "pin"?}')

        @R('GET', '/api/v1/alerts', 'viewer', summary='Active and recent alarms', tags=('hub',))
        def alerts(h, sess): h.send_json(200, {'alerts': hub.alerts_view()})

        @R('POST', '/api/v1/alerts/{kind}/ack', 'member', summary='Acknowledge an alarm (stops repeats)', tags=('hub',))
        def ack(h, sess, kind):
            if not hub.ack_alert(kind, sess['user']['display']): raise ApiError(404, 'No such alert')
            st.audit(sess['user']['username'], h.ip, 'alert.ack', kind); h.send_json(200, {'ok': True})

        @R('GET', '/api/v1/events', 'viewer', summary='History. Query: limit, before (id), kind (comma list), since (epoch s)', tags=('hub',))
        def events(h, sess):
            q = parse_qs(urlsplit(h.path).query)
            kinds = [k for k in (q.get('kind', [''])[0].split(',')) if re.fullmatch(r'[a-z]{2,12}', k)] or None
            try: limit, before, since = int(q.get('limit', ['100'])[0]), q.get('before', [None])[0], q.get('since', [None])[0]
            except ValueError: raise ApiError(400, 'Bad query')
            evs = st.events(limit, before, kinds, since)
            if st.get_settings().get('duressSilent', True): evs = [e for e in evs if e['kind'] != 'duress']
            if not st.get_settings().get('rawLog', True) or sess['user']['role'] != 'owner':
                for e in evs: e.pop('raw', None)
            h.send_json(200, {'events': evs})

        @R('GET', '/api/v1/sensors', 'viewer', summary='All sensors', tags=('sensors',))
        def sensors(h, sess): h.send_json(200, {'sensors': hub.sensors_view()})

        @R('GET', '/api/v1/sensors/{id}', 'viewer', summary='One sensor', tags=('sensors',))
        def sensor(h, sess, sid):
            v = hub.sensor_view(int(sid))
            if not v: raise ApiError(404, 'No such sensor')
            h.send_json(200, v)

        @R('PATCH', '/api/v1/sensors/{id}', 'owner', summary='Name a sensor or set its room: {"name", "room"}', tags=('sensors',))
        def sensor_edit(h, sess, sid):
            sid = int(sid); b = h.body()
            if sid not in hub.sensors: raise ApiError(404, 'No such sensor')
            meta = dict(st.get_settings().get('sensorMeta', {})); m = dict(meta.get(str(sid), {}))
            if 'name' in b: m['name'] = V.str(40)(b['name']).strip()
            if 'room' in b: m['room'] = V.str(40)(b['room']).strip()
            if 'type' in b:
                cur = hub.sensors[sid]
                if b['type'] not in MANUAL_TYPES: raise ApiError(400, 'Unknown sensor type')
                if not hub.type_editable(cur): raise ApiError(409, 'The hub reports this sensor\'s type itself')
                with hub.lock: cur.update(type=b['type'], manual=True); st.save_sensor(sid, cur)
            if b.get('removed') is False: m.pop('removed', None)
            meta[str(sid)] = m; st.save_settings({'sensorMeta': meta}, merge=False)
            if m.get('room'):
                rooms = list(st.get_settings().get('rooms', []))
                if m['room'] not in rooms: rooms.append(m['room']); st.save_settings({'rooms': rooms})
            st.audit(sess['user']['username'], h.ip, 'sensor.edit', f'{sid}: {m.get("name")} / {m.get("room")}')
            v = hub.sensor_view(sid); hub.bus.publish('sensor', v); h.send_json(200, v)

        @R('GET', '/api/v1/sensors/untracked', 'viewer', summary='Devices the hub has reported that aren\'t in the sensor list: ID, type, last heard', tags=('sensors',))
        def sensors_untracked(h, sess): h.send_json(200, {'devices': hub.untracked_view()})

        @R('POST', '/api/v1/sensors', 'owner', summary='Add a sensor by hand: {"id" (slot), "type", "name", "room"?}. It shows as waiting until the hub reports that slot', tags=('sensors',))
        def sensor_add(h, sess):
            b = h.body()
            try: sid = int(b.get('id'))
            except (TypeError, ValueError): raise ApiError(400, 'Enter the sensor\'s slot number')
            if not 1 <= sid <= 999999: raise ApiError(400, 'The slot number is 1 to 999999')
            kind = b.get('type')
            if kind not in MANUAL_TYPES: raise ApiError(400, 'Choose the sensor type')
            name, room = V.str(40)(b.get('name') or '').strip(), V.str(40)(b.get('room') or '').strip()
            if not name: raise ApiError(400, 'Give the sensor a name')
            try: hub.add_manual(sid, kind)
            except ValueError as e: raise ApiError(409, str(e))
            meta = dict(st.get_settings().get('sensorMeta', {})); meta[str(sid)] = {'name': name, **({'room': room} if room else {})}
            st.save_settings({'sensorMeta': meta}, merge=False)
            if room:
                rooms = list(st.get_settings().get('rooms', []))
                if room not in rooms: rooms.append(room); st.save_settings({'rooms': rooms})
            st.audit(sess['user']['username'], h.ip, 'sensor.add', f'{sid}: {name} ({kind})')
            v = hub.sensor_view(sid); hub.bus.publish('sensor', v); h.send_json(200, v)

        @R('DELETE', '/api/v1/sensors/{id}', 'owner', summary='Remove a sensor from OpenRoost (the hub keeps it paired)', tags=('sensors',))
        def sensor_remove(h, sess, sid):
            meta = dict(st.get_settings().get('sensorMeta', {})); m = dict(meta.get(str(sid), {})); m['removed'] = True
            meta[str(sid)] = m; st.save_settings({'sensorMeta': meta}, merge=False)
            st.audit(sess['user']['username'], h.ip, 'sensor.remove', sid); hub.bus.publish('sensor', hub.sensor_view(int(sid))); h.send_json(200, {'ok': True})

        P('PUT', '/api/v1/sensors/{id}/alert-mode', 'sensors.alertMode')
        P('POST', '/api/v1/sensors/{id}/unpair', 'sensors.unpair')

        @R('GET', '/api/v1/pairing', 'viewer', summary='Pairing window and newly found sensors', tags=('sensors',))
        def pairing(h, sess): h.send_json(200, hub.pairing_view())

        @R('POST', '/api/v1/pairing/start', 'owner', summary='Open a 10-minute window to collect new sensors (press the hub\'s gray button)', tags=('sensors',))
        def pairing_start(h, sess): h.send_json(200, hub.start_pairing())

        @R('POST', '/api/v1/pairing/stop', 'owner', summary='Close the pairing window', tags=('sensors',))
        def pairing_stop(h, sess): hub.stop_pairing(); h.send_json(200, hub.pairing_view())

        @R('PATCH', '/api/v1/hub', 'owner', summary='Name the hub or set where it is: {"name", "location"}', tags=('hub',))
        def hub_edit(h, sess):
            b = h.body(); patch = {}
            if 'name' in b: patch['hubName'] = V.str(40)(b['name']).strip() or 'SmartBase'
            if 'location' in b: patch['hubLoc'] = V.str(80)(b['location']).strip()
            if patch: st.save_settings(patch)
            st.audit(sess['user']['username'], h.ip, 'hub.edit', ', '.join(f'{k}={v}' for k, v in patch.items()))
            v = hub.hub_view(); hub.bus.publish('hub', v); h.send_json(200, v)

        @R('POST', '/api/v1/hub/claim', 'owner', summary='Trust the hub that is connected now (others are refused)', tags=('hub',))
        def claim(h, sess):
            if not hub.status.get('id'): raise ApiError(409, 'No hub has connected yet')
            hub.claim_hub(hub.status['id'], hub.status.get('ip')); st.audit(sess['user']['username'], h.ip, 'hub.claim', hub.status['id']); h.send_json(200, hub.hub_view())

        P('GET', '/api/v1/hub/pins', 'hub.pins'); P('PUT', '/api/v1/hub/pins', 'hub.pins')
        P('PUT', '/api/v1/hub/settings', 'hub.delays', summary='Entry/exit delays and door chime')
        P('POST', '/api/v1/hub/wifi/scan', 'hub.wifi'); P('POST', '/api/v1/hub/wifi/provision', 'hub.wifi')

        @R('GET', '/api/v1/debug/wire', 'owner', summary='Protocol log: everything the listener sent and received. Query: limit (max 3000), after (seq)', tags=('debug',))
        def wire(h, sess):
            q = parse_qs(urlsplit(h.path).query)
            try: limit, after = min(int(q.get('limit', ['1000'])[0]), 3000), int(q.get('after', ['0'])[0])
            except ValueError: raise ApiError(400, 'Bad query')
            h.send_json(200, {'entries': hub.wire.recent(limit, after) if hub.wire else [], 'file': bool(st.get_settings().get('wireFile'))})

        @R('GET', '/api/v1/stream', 'viewer', summary='Live updates (server-sent events: hub, arm, sensor, event, alert, escalation, pairing, listener; wire for owners)', tags=('hub',))
        def stream(h, sess): h.stream(self.hub.bus, sess)

        # ============================================================ settings
        @R('GET', '/api/v1/settings', 'viewer', summary='All settings (secrets only as set / not set)', tags=('settings',))
        def settings_get(h, sess):
            d = self.snapshot_settings(); d['role'] = sess['user']['role']; h.send_json(200, d)

        @R('PUT', '/api/v1/settings', 'owner', summary='Save settings: {"settings": {...}, "clear": [secret names]}', tags=('settings',))
        def settings_put(h, sess):
            b = h.body()
            before = st.get_settings()
            changed, secs, cleared = st.save_settings(b.get('settings') or {}, b.get('clear') or [])
            after = st.get_settings()
            if any(before.get(k) != after.get(k) for k in ('hubIp', 'manageNat')) and self.keep_nat: self.keep_nat()
            if any(before.get(k) != after.get(k) for k in ('lowBat', 'sensorMissingH', 'hubName', 'hubLoc')):
                for v in hub.sensors_view(): hub.bus.publish('sensor', v)
                hub.bus.publish('hub', hub.hub_view())
            st.audit(sess['user']['username'], h.ip, 'settings.save', ', '.join(changed + [s + ' (secret)' for s in secs] + [c + ' (cleared)' for c in cleared]))
            h.send_json(200, {'ok': True, 'secretsSet': st.secrets_set()})

        @R('GET', '/api/v1/rooms', 'viewer', summary='Rooms', tags=('settings',))
        def rooms(h, sess): h.send_json(200, {'rooms': st.get_settings().get('rooms', [])})

        # ============================================================ services
        @R('GET', '/api/v1/services/checks', 'owner', summary='Redirect health: listener, time reply, Pi-hole, DNS, port redirect, hub session', tags=('services',))
        def svc_checks(h, sess): h.send_json(200, {'checks': services.checks(st, hub, self.listener_port), 'serverIp': services.server_ip(st.get_settings())})

        @R('POST', '/api/v1/services/fix/{fix}', 'owner', summary='Fix a failed check: dns (add Pi-hole records) or nat (add the port redirect)', tags=('services',))
        def svc_fix(h, sess, fix):
            r = self.fix(fix, (h.body().get('ip') or '').strip() or None); st.audit(sess['user']['username'], h.ip, 'services.fix', fix); h.send_json(200, r)

        @R('POST', '/api/v1/services/pihole/test', 'owner', summary='Test a Pi-hole: {"url", "password"?} (stored password if omitted)', tags=('services',))
        def ph_test(h, sess):
            b = h.body()
            try: h.send_json(200, services.pihole_test(b.get('url'), b.get('password') or st.get_secret('ph.pass')))
            except ServiceError as e: raise ApiError(400, str(e))

        @R('POST', '/api/v1/services/pihole/use', 'owner', summary='Switch Pi-hole: adds the records to the new one, removes them from the old one, saves', tags=('services',))
        def ph_use(h, sess):
            b = h.body(); cfg = dict(b.get('ph') or {})
            old = st.get_settings().get('ph') or {}; old_pw = st.get_secret('ph.pass')
            if cfg.get('mode') == 'bundled':
                bnd = services.bundled()['pihole']
                if not bnd['available']: raise ApiError(400, bnd.get('error') or 'OpenRoost\'s own Pi-hole isn\'t running. Start it with: docker compose --profile pihole up -d')
                cfg = {'mode': 'bundled', 'url': bnd['url'], 'ok': True, 'ver': bnd.get('version', '')}
                st.save_settings({'ph': cfg}, merge=False); st.save_settings({}, ['ph.pass'])
            elif cfg.get('mode') == 'existing':
                new_pw = cfg.get('pass') or (old_pw if old.get('url') == cfg.get('url') else '')
                try: info = services.pihole_test(cfg.get('url'), new_pw)
                except ServiceError as e: raise ApiError(400, str(e))
                cfg.update(ok=True, ver=info['version']); cfg['pass'] = new_pw or ''
                st.save_settings({'ph': cfg}, merge=False)
            else: raise ApiError(400, 'Choose a Pi-hole')
            try: res = services.ensure_records(st)
            except ServiceError as e: raise ApiError(400, str(e))
            moved = old.get('mode') and (old.get('mode') != cfg['mode'] or old.get('url') != cfg.get('url'))
            if moved:
                try: services.remove_records(st, old, old_pw)
                except ServiceError as e: res['oldPiholeError'] = str(e)
            st.audit(sess['user']['username'], h.ip, 'pihole.use', cfg.get('url'))
            h.send_json(200, {'ok': True, **res, 'version': info['version'], 'secretsSet': st.secrets_set()})

        @R('POST', '/api/v1/services/sso/test', 'owner', summary='Check an OpenID Connect issuer (discovery + signing keys)', tags=('services',))
        def sso_test(h, sess):
            issuer = (h.body().get('issuer') or st.get_settings().get('ssoIssuer') or '').strip()
            V.url(issuer)
            if not issuer: raise ApiError(400, 'Enter the issuer URL first')
            try:
                cfg = self.oidc.discover(issuer); keys = auth._get_json(cfg['jwks_uri']).get('keys', [])
            except auth.OidcError as e: raise ApiError(400, str(e))
            how = f'{len(keys)} signing key{"s" if len(keys) != 1 else ""}' if keys else 'no signing key, so tokens are signed with the client secret (fine; save the client secret)'
            h.send_json(200, {'result': f'Found the provider: sign-in, token and {how}.'})

        @R('GET', '/api/v1/services/bundled', 'owner', summary='Which bundled services (Pi-hole, mail relay) are running', tags=('services',))
        def bundled(h, sess): h.send_json(200, services.bundled())

        # ============================================================ notifications
        @R('POST', '/api/v1/notify/test/{channel}', 'owner', summary='Send a test: email, ntfy, webhook or matrix ({"to"} for email)', tags=('notify',))
        def notify_test(h, sess, channel):
            to = h.body().get('to')
            if to: V.email(to)
            try: h.send_json(200, {'result': self.notifier.test(channel, to)})
            except NotifyError as e: raise ApiError(400, str(e))

        @R('POST', '/api/v1/notify/matrix/login', 'owner', summary='Sign the Matrix bot in with its password; stores only the access token', tags=('notify',))
        def mx_login(h, sess):
            b = h.body(); s = st.get_settings()
            hs, user = (b.get('hs') or s.get('mxHs') or ''), (b.get('user') or s.get('mxUser') or '')
            V.str(255)(user)
            if not hs or not user: raise ApiError(400, 'Enter the homeserver and the bot account first')
            try: tok, note, base = self.notifier.matrix_login(hs, user, b.get('password') or '')
            except NotifyError as e: raise ApiError(400, str(e))
            st.save_settings({'mxToken': tok, 'mxHs': base, 'mxUser': user}); st.audit(sess['user']['username'], h.ip, 'matrix.login', base)
            h.send_json(200, {'ok': True, 'note': note, 'hs': base, 'e2ee': self.notifier.crypto.status(), 'secretsSet': st.secrets_set()})

        @R('GET', '/api/v1/notify/matrix/e2ee', 'owner', summary='Matrix encryption status: device, cross-signing, its fingerprint', tags=('notify',))
        def mx_e2ee(h, sess): h.send_json(200, self.notifier.crypto.status())

        # ============================================================ emergency countdown
        def esc_visible(sess, r): return not r.get('silent') or sess['user']['role'] == 'owner'

        @R('GET', '/api/v1/escalations', 'viewer', summary='Emergency countdowns of the last 24 hours (pending ones first)', tags=('hub',))
        def escs(h, sess):
            items = [r for r in (self.notifier.esc.recent() if self.notifier.esc else []) if esc_visible(sess, r)]
            h.send_json(200, {'escalations': sorted(items, key=lambda r: (r['state'] != 'pending', -r['start'])), 'now': time.time()})

        @R('POST', '/api/v1/escalations/{iid}/cancel', 'member', summary='Cancel a pending countdown: the emergency contacts are not told', tags=('hub',))
        def esc_cancel(h, sess, eid):
            r = self.notifier.esc and self.notifier.esc.get(eid)
            if not r or not esc_visible(sess, r): raise ApiError(404, 'No such countdown')
            if r['state'] != 'pending': raise ApiError(409, esc_gone(r))
            r = self.notifier.esc.cancel(eid, sess['user']['display'], 'the app')
            st.audit(sess['user']['username'], h.ip, 'countdown.cancel', f"{r['kind']}: {r['state']}")
            if r['state'] != 'cancelled': raise ApiError(409, esc_gone(r))
            h.send_json(200, {'escalation': self.notifier.esc.view(r)})

        def esc_gone(r):
            return 'Too late: the emergency contacts were already told.' if r['state'] == 'sent' else f"Already cancelled by {r.get('by') or 'someone'}."

        def esc_token(h):
            if self.throttle.blocked('esc:' + h.ip) > 0: raise ApiError(429, 'Too many attempts. Wait 15 minutes.', retryAfter=LOCK_FOR)
            r, name = self.notifier.esc.by_token(h.body().get('token')) if self.notifier.esc else (None, None)
            if not r: self.throttle.fail('esc:' + h.ip); raise ApiError(404, 'This cancel link is invalid or has expired.')
            return r, name

        @R('POST', '/api/v1/escalations/peek', summary='What a cancel link from a countdown email is for: {"token"}', tags=('hub',))
        def esc_peek(h, sess):
            r, name = esc_token(h); v = self.notifier.esc.view(r); v.pop('silent', None)
            h.send_json(200, {'escalation': v, 'name': name, 'now': time.time(), 'site': st.get_settings().get('siteName') or 'Home'})

        @R('POST', '/api/v1/escalations/cancel', summary='Cancel with the link from a countdown email: {"token"} (no sign-in: the link is the permission)', tags=('hub',))
        def esc_cancel_token(h, sess):
            r, name = esc_token(h)
            if r['state'] != 'pending': raise ApiError(409, esc_gone(r))
            r = self.notifier.esc.cancel(r['id'], name, 'email link')
            st.audit(name, h.ip, 'countdown.cancel', f"{r['kind']} by email link: {r['state']}")
            if r['state'] != 'cancelled': raise ApiError(409, esc_gone(r))
            v = self.notifier.esc.view(r); v.pop('silent', None); h.send_json(200, {'escalation': v})

        # ============================================================ users (owners)
        @R('GET', '/api/v1/users', 'owner', summary='Household members', tags=('users',))
        def users(h, sess): h.send_json(200, {'users': st.users()})

        @R('POST', '/api/v1/users', 'owner', summary='Add a member: {"username", "password", "role", "display"}', tags=('users',))
        def user_add(h, sess):
            b = h.body(); uid = st.create_user(b.get('username'), b.get('password'), b.get('role', 'member'), b.get('display', ''), b.get('email', ''))
            st.audit(sess['user']['username'], h.ip, 'user.add', f"{b.get('username')} as {b.get('role', 'member')}"); h.send_json(200, {'user': self.public_user(st.user(uid))})

        def target(uid):
            u = st.user(int(uid))
            if not u: raise ApiError(404, 'No such user')
            return u

        @R('PATCH', '/api/v1/users/{id}', 'owner', summary='Change a member\'s role or name', tags=('users',))
        def user_edit(h, sess, uid):
            b, u = h.body(), target(uid); role = b.get('role', u['role'])
            if role not in ROLES: raise ValidationError({'role': 'unknown role'})
            if u['role'] == 'owner' and role != 'owner' and st.owners() <= 1: raise ApiError(409, 'Keep at least one owner')
            display = b.get('display', u['display'])
            if not isinstance(display, str) or not 0 < len(display) <= 80: raise ValidationError({'display': '1–80 characters'})
            V.str(80)(display)
            st.q('UPDATE users SET role=?, display=? WHERE id=?', role, display, u['id'])
            if role != u['role']: st.end_other_sessions(u['id'])
            st.audit(sess['user']['username'], h.ip, 'user.edit', f"{u['username']}: role {u['role']}→{role}"); h.send_json(200, {'user': self.public_user(st.user(u['id']))})

        @R('POST', '/api/v1/users/{id}/password', 'owner', summary='Reset a member\'s password (signs them out)', tags=('users',))
        def user_pw(h, sess, uid):
            u = target(uid); st.set_password(u['id'], h.body().get('password'))
            st.end_other_sessions(u['id'], sess['sid'] if u['id'] == sess['user']['id'] else None)
            st.audit(sess['user']['username'], h.ip, 'user.password_reset', u['username']); h.send_json(200, {'ok': True})

        @R('POST', '/api/v1/users/{id}/totp/reset', 'owner', summary='Turn off a member\'s two-factor sign-in (lost phone)', tags=('users',))
        def user_totp_reset(h, sess, uid):
            u = target(uid); st.set_user_totp(u['id'], None); st.end_other_sessions(u['id'])
            st.audit(sess['user']['username'], h.ip, 'user.totp_reset', u['username']); h.send_json(200, {'ok': True})

        @R('DELETE', '/api/v1/users/{id}', 'owner', summary='Remove a member', tags=('users',))
        def user_del(h, sess, uid):
            u = target(uid)
            if u['id'] == sess['user']['id']: raise ApiError(409, 'You can’t remove your own account')
            if u['role'] == 'owner' and st.owners() <= 1: raise ApiError(409, 'Keep at least one owner')
            st.q('DELETE FROM users WHERE id=?', u['id']); st.audit(sess['user']['username'], h.ip, 'user.remove', u['username']); h.send_json(200, {'ok': True})

        # ---- invite links
        INVITE_HOURS = 72

        def invite_list():
            now, out = time.time(), []
            for k, v in st.kv_prefix('invite:'):
                if v['exp'] < now: st.del_kv(k); continue
                out.append({x: v.get(x) for x in ('id', 'role', 'note', 'email', 'created', 'exp', 'by')})
            return sorted(out, key=lambda x: -x['created'])

        def invite_by_token(tok):
            if not isinstance(tok, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', tok): return None, None
            key = 'invite:' + st.keys.token_hash(tok); rec = st.kv(key)
            if not rec or rec['exp'] < time.time(): return None, None
            return key, rec

        @R('GET', '/api/v1/users/invites', 'owner', summary='Pending invite links (the links themselves are only shown once)', tags=('users',))
        def invites(h, sess): h.send_json(200, {'invites': invite_list()})

        @R('POST', '/api/v1/users/invites', 'owner', summary='Create an invite link: {"role", "hours" (1–168, default 72), "note"?, "email"? (send it)}', tags=('users',))
        def invite_new(h, sess):
            b = h.body(); role = b.get('role', 'member')
            if role not in ROLES: raise ValidationError({'role': 'unknown role'})
            hours = b.get('hours', INVITE_HOURS)
            if not isinstance(hours, int) or isinstance(hours, bool) or not 1 <= hours <= 168: raise ValidationError({'hours': '1–168'})
            note, to = V.str(80)(b.get('note') or ''), V.email(b.get('email') or '')
            if len(invite_list()) >= 20: raise ApiError(409, 'Too many pending invites. Revoke some first.')
            s = st.get_settings(); base = (s.get('publicUrl') or '').rstrip('/')
            if not base: raise ApiError(409, 'Set this server\'s web address first (Settings → System → Web address): invite links point to it.')
            tok = secrets.token_urlsafe(32); now = time.time()
            rec = {'id': secrets.token_hex(6), 'role': role, 'note': note, 'email': to, 'created': now, 'exp': now + hours * 3600, 'by': sess['user']['username']}
            st.set_kv('invite:' + st.keys.token_hash(tok), rec)
            link = f'{base}/?invite={tok}'
            st.audit(sess['user']['username'], h.ip, 'invite.create', f"{role}{' for ' + to if to else ''}{' (' + note + ')' if note else ''}")
            mailed = False
            if to:
                text, html = emails.invite(s.get('siteName') or 'Home', sess['user']['display'], role, link, hours)
                try: self.notifier.send_email(s, [to], f'You\'re invited to {s.get("siteName") or "Home"} on OpenRoost360', text, html); mailed = True
                except NotifyError as e: raise ApiError(400, f'The invite was created, but the email failed: {e}. Copy the link instead.', link=link, invite=rec)
            h.send_json(200, {'link': link, 'invite': rec, 'emailed': mailed})

        @R('DELETE', '/api/v1/users/invites/{iid}', 'owner', summary='Revoke an invite link', tags=('users',))
        def invite_del(h, sess, iid):
            for k, v in st.kv_prefix('invite:'):
                if v.get('id') == iid:
                    st.del_kv(k); st.audit(sess['user']['username'], h.ip, 'invite.revoke', v['role']); return h.send_json(200, {'ok': True})
            raise ApiError(404, 'No such invite')

        @R('POST', '/api/v1/auth/invite', summary='Look at an invite link before accepting: {"token"} → site and role', tags=('auth',))
        def invite_check(h, sess):
            if self.throttle.blocked('invite:' + h.ip) > 0: raise ApiError(429, 'Too many attempts. Wait 15 minutes.', retryAfter=LOCK_FOR)
            _, rec = invite_by_token(h.body().get('token'))
            if not rec: self.throttle.fail('invite:' + h.ip); raise ApiError(404, 'This invite link is invalid, used or expired. Ask for a new one.')
            h.send_json(200, {'site': st.get_settings().get('siteName') or 'Home', 'role': rec['role'], 'expires': rec['exp'], 'by': rec['by'], 'email': rec.get('email') or ''})

        @R('POST', '/api/v1/auth/invite/accept', summary='Create an account with an invite link: {"token", "username", "password", "display"?, "email"?, "deviceName"? (app: returns a token)}', tags=('auth',))
        def invite_accept(h, sess):
            b = h.body()
            if self.throttle.blocked('invite:' + h.ip) > 0: raise ApiError(429, 'Too many attempts. Wait 15 minutes.', retryAfter=LOCK_FOR)
            with self.invite_lock:                                    # one account per link, even if accepted twice at once
                key, rec = invite_by_token(b.get('token'))
                if not rec: self.throttle.fail('invite:' + h.ip); raise ApiError(404, 'This invite link is invalid, used or expired. Ask for a new one.')
                uid = st.create_user(b.get('username'), b.get('password'), rec['role'], b.get('display') or '', b.get('email') or '')
                st.del_kv(key)
            u = st.user(uid); s = st.get_settings()
            st.audit(u['username'], h.ip, 'invite.accept', f"{rec['role']}, invited by {rec['by']}")
            text, html = emails.joined(s.get('siteName') or 'Home', u['display'], u['username'], rec['role'])
            for o in st.users():
                if o['role'] == 'owner' and o['email']: self.mail_user(o, f'{u["display"]} joined your OpenRoost360', text, html)
            finish_login(h, u, False, 'device' if b.get('deviceName') else 'web', V.str(60)(b.get('deviceName') or ''), sess and sess['sid'])

        # ============================================================ admin
        @R('GET', '/api/v1/audit', 'owner', summary='Audit log (sign-ins and changes)', tags=('admin',))
        def audit(h, sess):
            q = parse_qs(urlsplit(h.path).query)
            h.send_json(200, {'audit': st.audit_log(min(int(q.get('limit', ['200'])[0]), 1000))})

        @R('POST', '/api/v1/backup', 'owner', summary='Download an encrypted backup: {"password", "passphrase"}', tags=('admin',))
        def do_backup(h, sess):
            b = h.body()
            if not st.keys.verify_password(b.get('password') or '', sess['user']['pw_hash']): raise ApiError(403, 'Password is wrong')
            try: blob = backup.create(st, b.get('passphrase'))
            except ValueError as e: raise ApiError(400, str(e))
            st.audit(sess['user']['username'], h.ip, 'backup.download')
            h.send_bytes(200, blob, 'application/octet-stream', {'Content-Disposition': f'attachment; filename="openroost-{time.strftime("%Y%m%d")}.orb"'})

        @R('GET', '/api/v1/admin/key', 'owner', summary='Master key: its id, where it comes from, accounts still on an older key', tags=('admin',))
        def key_info(h, sess):
            h.send_json(200, {'id': st.keys.id, 'fromEnv': st.keys.from_env, 'accountsOnOldKey': st.accounts_on_old_key(), 'rotated': st.meta('key_rotated')})

        @R('POST', '/api/v1/admin/rotate-key', 'owner', summary='Rotate the master key: {"password"}. Re-encrypts all secrets, signs everyone out (you get a new session), voids reset and invite links', tags=('admin',))
        def rotate_key(h, sess):
            b = h.body(); u = sess['user']
            if self.throttle.blocked('rotate:' + str(u['id'])) > 0: raise ApiError(429, 'Too many wrong passwords. Wait 15 minutes.', retryAfter=LOCK_FOR)
            if not st.keys.verify_password(b.get('password') or '', u['pw_hash']):
                self.throttle.fail('rotate:' + str(u['id'])); raise ApiError(403, 'Password is wrong')
            old = st.keys.id
            try: ended = st.rotate_key()
            except ValueError as e: raise ApiError(409, str(e))
            st.rehash_if_old(u['id'], b['password']); st.set_meta('key_rotated', str(int(time.time())))
            self.dummy_hash = st.keys.hash_password(os.urandom(16).hex())
            st.audit(u['username'], h.ip, 'admin.rotate_key', f'{old} → {st.keys.id}, {ended} sessions ended')
            s = st.get_settings(); text, html = emails.key_rotated(s.get('siteName') or 'Home', u['display'], h.ip)
            for o in st.users():
                if o['role'] == 'owner' and o['email']: self.mail_user(o, 'OpenRoost360 master key rotated', text, html)
            fresh = st.user(u['id'])
            info = {'ok': True, 'id': st.keys.id, 'sessionsEnded': ended, 'accountsOnOldKey': st.accounts_on_old_key()}
            if sess['kind'] == 'device':
                token, _ = st.new_session(fresh['id'], h.ip, h.headers.get('User-Agent'), DEVICE_TTL, 'device', 'Mobile app')
                return h.send_json(200, {**info, 'token': token})
            ttl = self.ttl_for(False); token, _ = st.new_session(fresh['id'], h.ip, h.headers.get('User-Agent'), ttl)
            h.send_json(200, info, set_cookie=h.cookie(token, ttl))

        @R('GET', '/api/v1/version', 'viewer', summary='This server\'s version and build, the newest release, and whether an update is available', tags=('admin',))
        def version(h, sess): h.send_json(200, self.updates.status() if self.updates else {'version': __version__})

        @R('POST', '/api/v1/version/check', 'owner', summary='Check for an update now', tags=('admin',))
        def version_check(h, sess):
            if not self.updates: raise ApiError(404, 'Update checks are off')
            h.send_json(200, self.updates.check())

    def mail_user(self, u, subject, text, html):
        """Account emails (reset links, password changed) go to that user's own address, in the background."""
        if not u.get('email'): return
        def go():
            try: self.notifier.send_email(self.store.get_settings(), [u['email']], subject, text, html)
            except Exception as e: self.store.add_event(time.time(), 'system', 'warn', 'Account email failed', str(e)[:300])
        threading.Thread(target=go, daemon=True).start()

    # ------------------------------------------------------------- shared by setup and services
    def _temp_ph(self, ph):
        """During setup the chosen Pi-hole isn't saved yet: store it so the checks can use it."""
        self.store.save_settings({'ph': ph}, merge=False)

    def fix(self, what, ip=None):
        if what == 'dns':
            try: return {'ok': True, **services.ensure_records(self.store)}
            except ServiceError as e: raise ApiError(400, str(e))
        if what == 'nat':
            if ip:
                try: ipaddress.IPv4Address(ip)
                except ValueError: raise ApiError(400, 'Enter the hub\'s IPv4 address, e.g. 192.168.1.50')
                self.store.save_settings({'hubIp': ip})
            targets = services.hub_targets(self.store, self.hub)
            if not targets: raise ApiError(409, 'The hub\'s address isn\'t known yet. Enter it (your router\'s device list shows it).')
            done = []
            try:
                for t in targets: done.append((t, services.nat_ensure(t, self.listener_port)))
            except ServiceError as e: raise ApiError(400, str(e))
            return {'ok': True, 'rules': [{'ip': t, 'result': r} for t, r in done]}
        raise ApiError(404, 'Unknown fix')

    def openapi(self):
        paths = {}
        for r in self.routes:
            p = r['pattern']
            op = {'summary': r['summary'], 'tags': list(r['tags']) or (['planned'] if r['planned'] else [])}
            if r['need']: op['security'] = [{'cookie': []}, {'bearer': []}]; op['x-role'] = r['need']
            if r['planned']: op['x-planned'] = r['planned']; op['responses'] = {'501': {'description': 'Planned, unsupported'}}
            else: op['responses'] = {'200': {'description': 'OK'}}
            paths.setdefault(p, {})[r['method'].lower()] = op
        return {'openapi': '3.1.0', 'info': {'title': 'OpenRoost360 API', 'version': '1',
                'description': 'Used by the web app and the mobile app. Bearer tokens come from POST /api/v1/auth/token.'},
                'components': {'securitySchemes': {'cookie': {'type': 'apiKey', 'in': 'cookie', 'name': COOKIE}, 'bearer': {'type': 'http', 'scheme': 'bearer'}}},
                'paths': paths}

    # ------------------------------------------------------------- HTTP handler
    def handler(self):
        app = self

        class H(http.server.SimpleHTTPRequestHandler):
            server_version = 'OpenRoost'; sys_version = ''; protocol_version = 'HTTP/1.1'

            def __init__(self, *a, **kw): super().__init__(*a, directory=app.web_root, **kw)

            def log_request(self, code='-', size='-'):
                # method + path + status only: never query strings (setup code, SSO) or request text
                path = urlsplit(self.path).path[:200] if getattr(self, 'command', None) and getattr(self, 'path', None) else '-'
                sys.stderr.write(f'{self.client_address[0]} {getattr(self, "command", None) or "-"} {path} {code}\n')

            def log_message(self, fmt, *args):
                if fmt.startswith('ERROR'): sys.stderr.write(f'{self.client_address[0]} {fmt % args}\n')

            def end_headers(self):
                for k, v in (('X-Content-Type-Options', 'nosniff'), ('X-Frame-Options', 'DENY'), ('Referrer-Policy', 'no-referrer'),
                             ('Permissions-Policy', 'camera=(), microphone=(), geolocation=()'), ('Cross-Origin-Opener-Policy', 'same-origin'),
                             ('Content-Security-Policy', CSP), ('Cache-Control', 'no-store')):
                    self.send_header(k, v)
                super().end_headers()

            def from_proxy(self):
                return self.client_address[0] in app.proxies

            def secure(self):
                if isinstance(self.connection, ssl.SSLSocket): return True
                return self.from_proxy() and (self.headers.get('X-Forwarded-Proto') or '').lower() == 'https'

            @property
            def ip(self):
                if self.from_proxy():                                   # real client address from a trusted reverse proxy
                    fwd = (self.headers.get('X-Forwarded-For') or '').split(',')[0].strip()
                    try: ipaddress.ip_address(fwd); return fwd
                    except ValueError: pass
                return self.client_address[0]

            def origin(self):
                return f'{"https" if self.secure() else "http"}://{self.headers.get("Host")}'

            def host_ok(self):
                host = (self.headers.get('Host') or '').rsplit(':', 1)[0].strip('[]').lower()
                if not host: return False
                try: ipaddress.ip_address(host); return True
                except ValueError: pass
                return host == 'localhost' or host.endswith(('.local', '.lan', '.home.arpa', '.localhost')) or host in app.extra_hosts

            def send_bytes(self, status, body, ctype, extra=None, set_cookie=None):
                self.send_response(status)
                self.send_header('Content-Type', ctype); self.send_header('Content-Length', str(len(body)))
                if set_cookie: self.send_header('Set-Cookie', set_cookie)
                for k, v in (extra or {}).items(): self.send_header(k, v)
                self.end_headers()
                if self.command != 'HEAD': self.wfile.write(body)

            def send_json(self, status, obj, set_cookie=None):
                extra = {'Retry-After': str(int(obj['retryAfter']))} if status == 429 and obj.get('retryAfter') else None
                self.send_bytes(status, json.dumps(obj, separators=(',', ':')).encode(), 'application/json; charset=utf-8', extra, set_cookie)

            def redirect(self, to, set_cookie=None):
                self.send_response(302); self.send_header('Location', to); self.send_header('Content-Length', '0')
                if set_cookie: self.send_header('Set-Cookie', set_cookie)
                self.end_headers()

            def cookie(self, token, ttl):
                return f'{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={int(ttl)}' + ('; Secure' if self.secure() else '')

            def bearer(self):
                a = self.headers.get('Authorization') or ''
                return a[7:].strip() if a.lower().startswith('bearer ') else None

            def cookie_token(self):
                raw = self.headers.get('Cookie')
                if not raw: return None
                try: c = cookies.SimpleCookie(raw)
                except cookies.CookieError: return None
                return c[COOKIE].value if COOKIE in c else None

            def session(self):
                tok = self.bearer()
                via = 'bearer' if tok else 'cookie'
                tok = tok or self.cookie_token()
                s = app.store.session(tok) if tok else None
                if s:
                    if via == 'bearer' and s[2] != 'device': return None      # a stolen cookie can't be replayed as a bearer token
                    return {'sid': s[0], 'user': s[1], 'kind': s[2], 'via': via}
                st = app.store.get_settings()
                if st.get('proxyAuth'):                                          # trusted reverse proxy (e.g. Authentik outpost)
                    trusted = [x.strip() for x in (st.get('proxyIps') or '').split(',') if x.strip()]
                    name = self.headers.get(st.get('proxyHeader') or 'Remote-User')
                    if name and self.client_address[0] in trusted:          # the proxy's own address, never a forwarded one
                        u = app.store.user_by_name(name.strip())
                        if u: return {'sid': None, 'user': u, 'kind': 'proxy', 'via': 'proxy'}
                return None

            def read_raw(self):
                """Read the whole body before anything else, so a refused request can't leave bytes on a kept-alive
                connection (they would be parsed as the next request)."""
                self._raw = b''
                try: n = int(self.headers.get('Content-Length') or 0)
                except ValueError: n = -1
                if self.headers.get('Transfer-Encoding'): n = -1
                if n < 0 or n > MAX_BODY:
                    self.close_connection = True
                    raise ApiError(413 if n > MAX_BODY else 400, 'Request too large' if n > MAX_BODY else 'Bad request')
                if n: self._raw = self.rfile.read(n)

            def body(self):
                if not self._raw: return {}
                if not (self.headers.get('Content-Type') or '').startswith('application/json'): raise ApiError(415, 'Send JSON')
                try: data = json.loads(self._raw)
                except (ValueError, UnicodeDecodeError): raise ApiError(400, 'Invalid JSON')
                if not isinstance(data, dict): raise ApiError(400, 'Expected a JSON object')
                return data

            def csrf(self):
                if self.bearer(): return                                         # app requests: no cookie involved
                if self.headers.get('X-OpenRoost') != '1': raise ApiError(403, 'Missing X-OpenRoost header')
                origin = self.headers.get('Origin')
                if origin == 'null' or (origin and urlsplit(origin).netloc.lower() != (self.headers.get('Host') or '').lower()):
                    raise ApiError(403, 'Cross-origin request refused')

            def stream(self, bus, sess):
                if not app.rate.stream(self.ip, 1): raise ApiError(429, 'Too many live connections from this address')
                try: self._stream(bus, sess)
                finally: app.rate.stream(self.ip, -1)

            def _stream(self, bus, sess):
                owner = sess['user']['role'] == 'owner'      # the protocol log and silent (hostage-PIN) countdowns are for owners only
                q = bus.subscribe(None if owner else (lambda m: m['type'] != 'wire' and not (m['type'] == 'escalation' and m['data'].get('silent'))))
                self.send_response(200)
                self.send_header('Content-Type', 'text/event-stream'); self.send_header('X-Accel-Buffering', 'no')
                self.end_headers()
                self.close_connection = True
                try:
                    self.wfile.write(bus.sse({'id': 0, 'type': 'hello', 'data': app.hub.overview()})); self.wfile.flush()
                    last = time.time()
                    while True:
                        if sess['sid'] and not app.store.session(self.bearer() or self.cookie_token()): break   # signed out elsewhere
                        try: msg = q.get(timeout=20)
                        except Exception: msg = None
                        if msg: self.wfile.write(bus.sse(msg))
                        elif time.time() - last > 15: self.wfile.write(b': keepalive\n\n'); last = time.time()
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError): pass
                finally: bus.unsubscribe(q)

            def do_GET(self): self.dispatch('GET')
            def do_POST(self): self.dispatch('POST')
            def do_PUT(self): self.dispatch('PUT')
            def do_PATCH(self): self.dispatch('PATCH')
            def do_DELETE(self): self.dispatch('DELETE')
            def do_HEAD(self): self.dispatch('HEAD')

            def setup(self):
                super().setup()
                if isinstance(self.connection, ssl.SSLSocket):
                    self.connection.settimeout(15)
                    try: self.connection.do_handshake()                # in the worker thread: a slow client can't stall accepts
                    except (ssl.SSLError, OSError): self.close_connection = True; self.rfile = __import__('io').BytesIO(b'')
                    self.connection.settimeout(self.timeout)

            timeout = 120                                              # idle keep-alive connections are dropped

            def dispatch(self, method):
                if not self.host_ok():
                    return self.send_json(421, {'error': 'Unknown host. Add it to OPENROOST_HOSTS if this is your server name.'})
                if app.https_port and not self.secure() and not self.from_proxy():
                    host = (self.headers.get('Host') or '').rsplit(':', 1)[0] if not (self.headers.get('Host') or '').endswith(']') else self.headers.get('Host')
                    self.send_response(308); self.send_header('Location', f'https://{host}:{app.https_port}{self.path}'); self.send_header('Content-Length', '0'); self.end_headers()
                    self.close_connection = True; return
                if not app.rate.allow(self.ip):
                    self.close_connection = True
                    return self.send_json(429, {'error': 'Too many requests. Slow down.', 'retryAfter': RATE_WINDOW})
                path = urlsplit(self.path).path
                if not path.startswith('/api/'):
                    if method not in ('GET', 'HEAD'): return self.send_json(405, {'error': 'Method not allowed'})
                    return self.static(method)
                self._raw = b''
                try:
                    self.read_raw()
                    if method not in ('GET', 'HEAD'): self.csrf()
                    matched = False
                    for r in app.routes:
                        m = r['rx'].match(path)
                        if not m: continue
                        matched = True
                        if r['method'] != method: continue
                        sess = self.session()
                        if r['need']:
                            if not sess: raise ApiError(401, 'Sign in first')
                            if RANK[sess['user']['role']] < RANK[r['need']]: raise ApiError(403, {'owner': 'Owners only', 'member': 'Members and owners only'}[r['need']])
                        return r['fn'](self, sess, *m.groups())
                    raise ApiError(405 if matched else 404, 'Method not allowed' if matched else 'Not found')
                except ApiError as e:
                    if e.status >= 400: self.close_connection = True
                    self.send_json(e.status, {'error': e.msg, **e.extra})
                except ValidationError as e:
                    self.send_json(400, {'error': 'Invalid input', 'fields': e.errors})
                except ValueError as e:
                    self.send_json(400, {'error': 'Invalid input: ' + str(e)[:200]})
                except Exception as e:
                    self.log_message('ERROR %r', e)
                    self.send_json(500, {'error': 'Server error'})

            def static(self, method):
                path = urlsplit(self.path).path
                if path in ('', '/'): path = '/index.html'
                if any(part.startswith('.') for part in path.split('/') if part): return self.send_error(404)
                full = os.path.realpath(self.translate_path(path))
                if not (full.startswith(app.web_root + os.sep)) or not os.path.isfile(full): return self.send_error(404)
                self.path = path
                return super().do_HEAD() if method == 'HEAD' else super().do_GET()

            def send_error(self, code, message=None, explain=None):
                self.send_bytes(code, f'{code}\n'.encode(), 'text/plain; charset=utf-8')

        return H

    def serve(self, bind, port, tls_ctx=None):
        class Srv(http.server.ThreadingHTTPServer):
            daemon_threads = True
            request_queue_size = 64
            def handle_error(self, request, client_address): pass   # dropped connections and failed handshakes are normal
        srv = Srv((bind, port), self.handler())
        if tls_ctx: srv.socket = tls_ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
        return srv
