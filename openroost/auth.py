"""Sign-in extras: TOTP two-factor codes (RFC 6238) and OpenID Connect (Authentik) single sign-on."""
import base64, hashlib, hmac, json, os, secrets, struct, threading, time, urllib.error, urllib.parse, urllib.request
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


# ---------------------------------------------------------------- TOTP
def totp_new_secret():
    return base64.b32encode(os.urandom(20)).decode().rstrip('=')


def totp_uri(secret, username, issuer='OpenRoost360'):
    return f'otpauth://totp/{urllib.parse.quote(issuer)}:{urllib.parse.quote(username)}?secret={secret}&issuer={urllib.parse.quote(issuer)}&digits=6&period=30'


def _hotp(secret, counter):
    key = base64.b32decode(secret + '=' * (-len(secret) % 8))
    h = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return '%06d' % ((struct.unpack('>I', h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)


def totp_verify(secret, code, last_step=0):
    """Returns the matched time step (to block replays) or None. Accepts one step of clock drift."""
    code = (code or '').strip().replace(' ', '')
    if not (code.isdigit() and len(code) == 6) or not secret: return None
    now = int(time.time() // 30)
    for step in (now - 1, now, now + 1):
        if step > last_step and hmac.compare_digest(_hotp(secret, step), code): return step
    return None


# ---------------------------------------------------------------- OpenID Connect
class OidcError(Exception):
    pass


def _b64u(s):
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


def _get_json(url, data=None):
    req = urllib.request.Request(url, data=data, headers={'Accept': 'application/json', 'User-Agent': 'OpenRoost360',
                                                           **({'Content-Type': 'application/x-www-form-urlencoded'} if data else {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r: return json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise OidcError(f'{urllib.parse.urlsplit(url).netloc} answered {e.code}: {e.read()[:300].decode(errors="replace")}') from None
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise OidcError(f'Couldn\'t reach {urllib.parse.urlsplit(url).netloc}: {getattr(e, "reason", e)}') from None


class Oidc:
    def __init__(self):
        self.pending, self.cache, self.lock = {}, {}, threading.Lock()

    def discover(self, issuer):
        issuer = issuer.rstrip('/')
        c = self.cache.get(issuer)
        if c and c['t'] > time.time() - 3600: return c['cfg']
        cfg = _get_json(issuer + '/.well-known/openid-configuration')
        if cfg.get('issuer', '').rstrip('/') != issuer: raise OidcError('The issuer URL doesn\'t match what the provider reports')
        self.cache[issuer] = {'t': time.time(), 'cfg': cfg}
        return cfg

    def start(self, st, redirect_uri, remember):
        cfg = self.discover(st['ssoIssuer'])
        state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
        with self.lock:
            now = time.time()
            self.pending = {k: v for k, v in self.pending.items() if v['t'] > now - 600}
            self.pending[state] = {'t': now, 'nonce': nonce, 'verifier': verifier, 'redirect': redirect_uri, 'remember': remember}
        q = {'response_type': 'code', 'client_id': st.get('ssoClientId', ''), 'redirect_uri': redirect_uri, 'scope': st.get('ssoScopes') or 'openid profile email',
             'state': state, 'nonce': nonce, 'code_challenge': challenge, 'code_challenge_method': 'S256'}
        return cfg['authorization_endpoint'] + '?' + urllib.parse.urlencode(q)

    def finish(self, st, client_secret, state, code):
        with self.lock: p = self.pending.pop(state or '', None)
        if not p or p['t'] < time.time() - 600: raise OidcError('This sign-in link expired. Try again.')
        cfg = self.discover(st['ssoIssuer'])
        tok = _get_json(cfg['token_endpoint'], urllib.parse.urlencode({
            'grant_type': 'authorization_code', 'code': code, 'redirect_uri': p['redirect'], 'client_id': st.get('ssoClientId', ''),
            'client_secret': client_secret or '', 'code_verifier': p['verifier']}).encode())
        claims = self.verify_id_token(cfg, st.get('ssoClientId', ''), tok.get('id_token', ''), p['nonce'])
        return claims, p['remember']

    def verify_id_token(self, cfg, client_id, token, nonce):
        try:
            h64, c64, s64 = token.split('.')
            header, claims, sig = json.loads(_b64u(h64)), json.loads(_b64u(c64)), _b64u(s64)
        except (ValueError, TypeError):
            raise OidcError('Malformed ID token') from None
        alg = header.get('alg')
        if alg not in ('RS256', 'ES256'): raise OidcError(f'Unsupported token algorithm {alg}')
        keys = _get_json(cfg['jwks_uri']).get('keys', [])
        key = next((k for k in keys if k.get('kid') == header.get('kid')), None) or (keys[0] if len(keys) == 1 else None)
        if not key: raise OidcError('Signing key not found')
        signed = f'{h64}.{c64}'.encode()
        try:
            if alg == 'RS256':
                pub = rsa.RSAPublicNumbers(int.from_bytes(_b64u(key['e']), 'big'), int.from_bytes(_b64u(key['n']), 'big')).public_key()
                pub.verify(sig, signed, padding.PKCS1v15(), hashes.SHA256())
            else:
                pub = ec.EllipticCurvePublicNumbers(int.from_bytes(_b64u(key['x']), 'big'), int.from_bytes(_b64u(key['y']), 'big'), ec.SECP256R1()).public_key()
                pub.verify(encode_dss_signature(int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big')), signed, ec.ECDSA(hashes.SHA256()))
        except (InvalidSignature, KeyError, ValueError):
            raise OidcError('ID token signature is invalid') from None
        now = time.time()
        aud = claims.get('aud'); aud = aud if isinstance(aud, list) else [aud]
        if claims.get('iss', '').rstrip('/') != cfg['issuer'].rstrip('/'): raise OidcError('ID token is from another issuer')
        if client_id not in aud: raise OidcError('ID token is for another client')
        if claims.get('exp', 0) < now - 60: raise OidcError('ID token expired')
        if claims.get('nonce') != nonce: raise OidcError('ID token nonce mismatch')
        if not claims.get('sub'): raise OidcError('ID token has no subject')
        return claims


def role_from_groups(st, groups):
    groups = set(groups or [])
    if st.get('ssoAdminGroup') and st['ssoAdminGroup'] in groups: return 'owner'
    if st.get('ssoMemberGroup') and st['ssoMemberGroup'] in groups: return 'member'
    return 'viewer'
