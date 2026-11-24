"""HTTPS for the web app and API.

By default OpenRoost makes its own certificate (data/web.crt, valid 5 years, for this server's names and LAN
address). Browsers show a warning once; the mobile app pins its SHA-256 fingerprint (shown in Settings → System
and in GET /api/v1/status). Use your own certificate with OPENROOST_TLS_CERT / OPENROOST_TLS_KEY.
"""
import datetime, hashlib, ipaddress, os, socket, ssl
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def _names(extra):
    dns, ips = {'localhost', socket.gethostname()}, {'127.0.0.1'}
    for h in list(extra):
        try: ipaddress.ip_address(h); ips.add(h)
        except ValueError: dns.add(h)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(('192.0.2.1', 9)); ips.add(s.getsockname()[0]); s.close()
    except OSError: pass
    return sorted(dns), sorted(ips)


def ensure_web_cert(data_dir, extra_hosts=()):
    crt, key = os.environ.get('OPENROOST_TLS_CERT'), os.environ.get('OPENROOST_TLS_KEY')
    if crt and key: return crt, key, False
    crt, key = os.path.join(data_dir, 'web.crt'), os.path.join(data_dir, 'web.key')
    if os.path.exists(crt) and os.path.exists(key): return crt, key, True
    k = ec.generate_private_key(ec.SECP256R1())
    dns, ips = _names(extra_hosts)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'OpenRoost360'), x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'OpenRoost360 (self-signed)')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=5 * 365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(d) for d in dns] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]), False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .sign(k, hashes.SHA256()))
    fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as f: f.write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with open(crt, 'wb') as f: f.write(cert.public_bytes(serialization.Encoding.PEM))
    return crt, key, True


def fingerprint(crt_path):
    with open(crt_path, 'rb') as f: cert = x509.load_pem_x509_certificate(f.read())
    d = cert.fingerprint(hashes.SHA256()).hex().upper()
    return ':'.join(d[i:i + 2] for i in range(0, len(d), 2))


def server_context(crt, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(crt, key)
    ctx.set_alpn_protocols(['http/1.1'])
    return ctx
