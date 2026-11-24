"""Encrypted backups: database + master key, sealed with a passphrase (scrypt -> AES-256-GCM).

Download from Settings -> System (owners, password + passphrase). Restore with the server stopped:
    python3 -m openroost restore backup.orb --data /path/to/data
"""
import base64, hashlib, io, json, os, secrets, sqlite3, tarfile, tempfile, time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCRYPT = dict(n=2 ** 17, r=8, p=1, maxmem=256 * 1024 * 1024, dklen=32)
MAGIC = 'openroost360-backup-v1'


def _key(passphrase, salt):
    return hashlib.scrypt(passphrase.encode(), salt=salt, **SCRYPT)


def create(store, passphrase):
    if len(passphrase or '') < 12: raise ValueError('Backup passphrase must be at least 12 characters')
    with tempfile.TemporaryDirectory() as d:
        snap = os.path.join(d, 'openroost.db')
        dst = sqlite3.connect(snap)
        with store.lock: store.db.backup(dst)
        dst.close()
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as tar:
            tar.add(snap, 'openroost.db')
            key_path = os.path.join(os.path.dirname(store.path), 'master.key')
            if os.path.exists(key_path): tar.add(key_path, 'master.key')
            else:
                info = tarfile.TarInfo('master.key.env'); data = os.environ.get('OPENROOST_MASTER_KEY', '').encode()
                info.size = len(data); tar.addfile(info, io.BytesIO(data))
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    ct = AESGCM(_key(passphrase, salt)).encrypt(nonce, buf.getvalue(), MAGIC.encode())
    return json.dumps({'format': MAGIC, 'created': int(time.time()), 'kdf': 'scrypt', 'salt': base64.b64encode(salt).decode(),
                       'nonce': base64.b64encode(nonce).decode(), 'data': base64.b64encode(ct).decode()}).encode()


def restore(path, passphrase, data_dir):
    with open(path) as f: b = json.load(f)
    if b.get('format') != MAGIC: raise SystemExit('Not an OpenRoost360 backup')
    try:
        raw = AESGCM(_key(passphrase, base64.b64decode(b['salt']))).decrypt(base64.b64decode(b['nonce']), base64.b64decode(b['data']), MAGIC.encode())
    except Exception:
        raise SystemExit('Wrong passphrase or damaged backup') from None
    os.makedirs(data_dir, mode=0o700, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as tar:
        for m in tar.getmembers():
            if m.name not in ('openroost.db', 'master.key', 'master.key.env') or not m.isfile(): continue
            out = os.path.join(data_dir, m.name)
            if os.path.exists(out): os.replace(out, out + '.before-restore')
            fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'wb') as f: f.write(tar.extractfile(m).read())
    for suffix in ('-wal', '-shm'):
        p = os.path.join(data_dir, 'openroost.db' + suffix)
        if os.path.exists(p): os.remove(p)
    return True
