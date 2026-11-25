#!/usr/bin/env python3
"""Single sign-on against a stand-in for Authentik: discovery with Authentik's issuer form (…/application/o/<slug>/),
ID tokens signed with the client secret (HS256, Authentik's default without a signing key) and with an RSA key
(RS256), groups → roles, linking an existing account, and the landing page that lets the SameSite=Strict cookie
through after the provider's redirect.

    python3 tests/test_sso.py             # exit code 0 = all passed
"""
import base64, hashlib, hmac, http.server, json, os, sys, threading, time, urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
from test_security import Server, setup_body, OWNER_PW, check, results      # noqa: E402
from cryptography.hazmat.primitives import hashes                            # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa          # noqa: E402

CLIENT, SECRET = 'openroost-client', 'client-secret-value-123'
b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip('=')
RSA = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUB = RSA.public_key().public_numbers()


class Provider(http.server.BaseHTTPRequestHandler):
    """/application/o/openroost/: discovery, token, userinfo, jwks."""
    user = {'sub': 'hashed-sub-1', 'preferred_username': 'ty', 'name': 'Ty', 'email': 'ty@example.com', 'groups': ['openroost-admins']}
    alg, nonce, groups_in_token = 'HS256', None, True

    def log_message(self, *a): pass

    def issuer(self): return f'http://127.0.0.1:{self.server.server_port}/application/o/openroost/'

    def send(self, obj):
        b = json.dumps(obj).encode()
        self.send_response(200); self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        base = f'http://127.0.0.1:{self.server.server_port}/application/o'
        if self.path.endswith('/.well-known/openid-configuration'):
            return self.send({'issuer': self.issuer(), 'authorization_endpoint': base + '/authorize/', 'token_endpoint': base + '/token/',
                              'userinfo_endpoint': base + '/userinfo/', 'jwks_uri': base + '/openroost/jwks/'})
        if self.path.endswith('/jwks/'):
            return self.send({'keys': [{'kty': 'RSA', 'kid': 'k1', 'alg': 'RS256', 'n': b64(PUB.n.to_bytes(256, 'big')), 'e': b64(PUB.e.to_bytes(3, 'big'))}]})
        if self.path.endswith('/userinfo/'):
            return self.send(Provider.user)
        self.send_response(404); self.send_header('Content-Length', '0'); self.end_headers()

    def do_POST(self):
        form = urllib.parse.parse_qs(self.rfile.read(int(self.headers['Content-Length'])).decode())
        if form.get('client_secret', [''])[0] != SECRET or form.get('client_id', [''])[0] != CLIENT:
            b = b'{"error":"invalid_client"}'; self.send_response(401); self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b); return
        claims = {**Provider.user, 'iss': self.issuer(), 'aud': CLIENT, 'exp': int(time.time()) + 300, 'iat': int(time.time()), 'nonce': Provider.nonce}
        if not Provider.groups_in_token: claims.pop('groups')
        head = {'alg': Provider.alg, 'typ': 'JWT', **({'kid': 'k1'} if Provider.alg == 'RS256' else {})}
        signed = f'{b64(json.dumps(head).encode())}.{b64(json.dumps(claims).encode())}'.encode()
        sig = hmac.new(SECRET.encode(), signed, hashlib.sha256).digest() if Provider.alg == 'HS256' else RSA.sign(signed, padding.PKCS1v15(), hashes.SHA256())
        self.send({'access_token': 'at', 'token_type': 'Bearer', 'id_token': signed.decode() + '.' + b64(sig)})


def cookie_of(hd):
    v = next((v for k, v in hd if k.lower() == 'set-cookie'), '')
    return v.split(';')[0].split('=', 1)[1] if '=' in v else None


def sso(s, cookie=None, link=False):
    """Start → (pretend the person signs in at the provider) → callback. Returns (status, headers, body)."""
    st, _, _, hd = s.req('GET', '/api/v1/auth/oidc/start' + ('?link=1' if link else ''), cookie=cookie)
    loc = next(v for k, v in hd if k.lower() == 'location')
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query)
    Provider.nonce = q['nonce'][0]
    st, _, txt, hd = s.req('GET', '/api/v1/auth/oidc/callback?' + urllib.parse.urlencode({'state': q['state'][0], 'code': 'abc'}))
    return st, hd, txt, q


def main():
    prov = http.server.HTTPServer(('127.0.0.1', 0), Provider); threading.Thread(target=prov.serve_forever, daemon=True).start()
    issuer = f'http://127.0.0.1:{prov.server_port}/application/o/openroost/'
    s = Server()
    s.req('POST', '/api/v1/setup/complete', setup_body(s.code))
    owner = cookie_of(s.req('POST', '/api/v1/auth/login', {'username': 'tyowner', 'password': OWNER_PW})[3])
    st, js = s.req('PUT', '/api/v1/settings', {'settings': {'ssoOn': True, 'ssoIssuer': issuer, 'ssoClientId': CLIENT, 'ssoSecret': SECRET,
                                                           'ssoAdminGroup': 'openroost-admins', 'ssoMemberGroup': 'openroost-members', 'ssoAutoCreate': True, 'ssoLocal': True}}, cookie=owner)[:2]
    check('SSO settings save (Authentik-style issuer with trailing slash)', st == 200, (st, js))
    st, js = s.req('POST', '/api/v1/services/sso/test', {'issuer': issuer}, cookie=owner)[:2]
    check('Test connection works against it', st == 200, (st, js))

    print('\n== Linking the existing owner account')
    st, hd, txt, q = sso(s, cookie=owner, link=True)
    check('start sends the callback address and PKCE', q['redirect_uri'][0].endswith('/api/v1/auth/oidc/callback') and q['code_challenge_method'] == ['S256'], q)
    check('linking lands back on Settings → Account', st == 200 and '#settings/account' in txt, (st, txt[:200]))
    me = s.req('GET', '/api/v1/me', cookie=owner)[1]['user']
    check('the owner account is now linked', me['sso'] is True and me['username'] == 'tyowner', me)

    print('\n== Signing in (HS256: Authentik without a signing key)')
    st, hd, txt, _ = sso(s)
    ck = cookie_of(hd)
    check('callback answers with a same-site landing page (not a cross-site redirect chain)', st == 200 and 'http-equiv="refresh"' in txt and ck, (st, txt[:200]))
    check('the session cookie is SameSite=Strict and HttpOnly', 'SameSite=Strict' in next(v for k, v in hd if k.lower() == 'set-cookie') and 'HttpOnly' in next(v for k, v in hd if k.lower() == 'set-cookie'))
    me = s.req('GET', '/api/v1/me', cookie=ck)[1]['user']
    check('Authentik signs into the linked owner account', me['username'] == 'tyowner' and me['role'] == 'owner', me)

    print('\n== RS256 (Authentik with a signing key), new people, groups')
    Provider.alg = 'RS256'
    Provider.user = {'sub': 'hashed-sub-2', 'preferred_username': 'sam', 'name': 'Sam', 'groups': ['openroost-members']}
    st, hd, txt, _ = sso(s); ck = cookie_of(hd)
    me = s.req('GET', '/api/v1/me', cookie=ck)[1]['user'] if ck else {}
    check('a new person gets an account with the member role from their group', me.get('username') == 'sam' and me.get('role') == 'member', (st, txt[:300], me))
    Provider.groups_in_token = False
    Provider.user = {'sub': 'hashed-sub-3', 'preferred_username': 'kid', 'groups': ['openroost-admins']}
    st, hd, txt, _ = sso(s); ck = cookie_of(hd)
    me = s.req('GET', '/api/v1/me', cookie=ck)[1]['user'] if ck else {}
    check('groups only in userinfo are still used', me.get('role') == 'owner', (st, txt[:300], me))
    Provider.groups_in_token = True
    Provider.user = {'sub': 'hashed-sub-4', 'preferred_username': 'guest'}
    st, hd, txt, _ = sso(s); ck = cookie_of(hd)
    me = s.req('GET', '/api/v1/me', cookie=ck)[1]['user'] if ck else {}
    check('someone in neither group is a viewer', me.get('role') == 'viewer', me)

    print('\n== Bad tokens are refused')
    Provider.alg = 'HS256'; Provider.user = {'sub': 'hashed-sub-1', 'preferred_username': 'ty', 'groups': ['openroost-admins']}
    st, _, _, hd = s.req('GET', '/api/v1/auth/oidc/start')
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(next(v for k, v in hd if k.lower() == 'location')).query)
    Provider.nonce = 'wrong-nonce'
    st, _, txt, hd = s.req('GET', '/api/v1/auth/oidc/callback?' + urllib.parse.urlencode({'state': q['state'][0], 'code': 'abc'}))
    check('a token with the wrong nonce is refused', not cookie_of(hd) and 'ssoError' in txt, txt[:200])
    st, _, txt, hd = s.req('GET', '/api/v1/auth/oidc/callback?' + urllib.parse.urlencode({'state': 'made-up', 'code': 'abc'}))
    check('an unknown state is refused', not cookie_of(hd) and 'ssoError' in txt)
    s.req('PUT', '/api/v1/settings', {'settings': {'ssoSecret': 'a-different-secret'}}, cookie=owner)
    st, hd, txt, _ = sso(s)
    check('an HS256 token is only accepted with the right secret', not cookie_of(hd), txt[:200])

    print('\n== Unlinking')
    st, js = s.req('POST', '/api/v1/me/sso/unlink', {'password': 'wrong password 123'}, cookie=owner)[:2]
    check('unlinking needs the password', st == 403, (st, js))
    st, js = s.req('POST', '/api/v1/me/sso/unlink', {'password': OWNER_PW}, cookie=owner)[:2]
    check('…and then works', st == 200 and s.req('GET', '/api/v1/me', cookie=owner)[1]['user']['sso'] is False, (st, js))
    s.close()

    bad = [r for r in results if not r[1]]
    print(f'\n{len(results) - len(bad)}/{len(results)} passed')
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()
