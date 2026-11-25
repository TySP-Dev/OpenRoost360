"""OpenRoost360 storage: settings, accounts, secrets, hub state, sensors, events and alerts.

Everything the web app can set (first-run setup and Settings) lives here, in one SQLite file:

* Ordinary settings  -> JSON, validated against SCHEMA (unknown keys are rejected).
* Secrets            -> AES-256-GCM, a fresh 96-bit nonce per write, and the secret's name as
                        associated data (a ciphertext can't be moved to another field).
                        The API never returns them; it only says whether each one is set.
* Keypad PINs        -> stored as one encrypted secret ("pins"); readable by owners only.
* Account passwords  -> Argon2id (64 MiB, t=3, p=4) with a per-password salt and a server
                        "pepper" (Argon2's secret input), so a stolen database alone can't be
                        brute-forced offline.
* Session tokens     -> random 256-bit, only their SHA-256 is stored.

Keys come from a 32-byte master key: env OPENROOST_MASTER_KEY (base64) or <data>/master.key
(created 0600 on first run). Sub-keys are split off it with HKDF, so the encryption key and
the pepper are independent. Back up master.key together with the database: without it the
secrets can't be decrypted and no password verifies. The database records the key's id, so a
master.key that doesn't belong to it is refused at start-up instead of failing later.

Rotation (Settings -> System, owners): a new master key re-encrypts every secret, signs everyone
out (session tokens are keyed by it) and voids pending reset and invite links. Password hashes
are tagged with the key whose pepper made them; the old pepper is kept, encrypted under the new
key, until each account signs in again and is re-hashed. Crash-safe: the new key is written to
master.key.next first, and start-up finishes or abandons the switch depending on which key the
database says it uses.
"""
import base64, hashlib, hmac, json, os, re, secrets, sqlite3, stat, threading, time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from . import __version__
_BUILD = (os.environ.get('OPENROOST_BUILD') or '').strip()
RUNNING = __version__ + (f'+{_BUILD[:7]}' if _BUILD and _BUILD != 'unknown' else '')   # version + commit

ARGON = dict(length=32, iterations=3, lanes=4, memory_cost=65536)  # 64 MiB
ROLES = ('owner', 'member', 'viewer')
PASSWORD_MIN = 12
KEY_VERSION = 1


# ---------------------------------------------------------------- settings schema
# Types: str(max) | num(lo, hi) | bool | url | email | choice(*opts) | secret | obj(sub) | custom validator
class V:
    @staticmethod
    def str(maxlen=200):
        def f(v):
            if not isinstance(v, str): raise ValueError('must be text')
            if len(v) > maxlen: raise ValueError(f'too long (max {maxlen})')
            if any(ord(c) < 32 and c not in '\n\t' for c in v): raise ValueError('control characters not allowed')
            return v
        return f

    @staticmethod
    def num(lo, hi):
        def f(v):
            if isinstance(v, bool) or not isinstance(v, (int, float)): raise ValueError('must be a number')
            if not (lo <= v <= hi): raise ValueError(f'must be {lo}–{hi}')
            return v
        return f

    @staticmethod
    def bool(v):
        if not isinstance(v, bool): raise ValueError('must be true/false')
        return v

    @staticmethod
    def url(v):
        V.str(500)(v)
        if v and not re.match(r'^https?://[^\s<>"\'`]+$', v): raise ValueError('must be an http(s) URL')
        return v

    @staticmethod
    def email(v):
        V.str(254)(v)
        if v and not re.match(r'^[^\s@<>"\']+@[^\s@<>"\']+\.[^\s@<>"\']+$', v): raise ValueError('must be an email address')
        return v

    @staticmethod
    def emails(v):
        V.str(4000)(v)
        for line in filter(None, (x.strip() for x in v.split())): V.email(line)
        return v

    @staticmethod
    def choice(*opts):
        def f(v):
            if v not in opts: raise ValueError(f'must be one of {", ".join(map(str, opts))}')
            return v
        return f

    @staticmethod
    def token(v):  # select/segmented values, colours, time zones
        V.str(60)(v)
        if v and not re.match(r'^[A-Za-z0-9_+:/.#-]+$', v): raise ValueError('invalid value')
        return v


SECRET = object()   # marker: value is encrypted, write-only


def obj(sub):
    return ('obj', sub)


PH = {'mode': V.choice(None, 'bundled', 'existing'), 'url': V.url, 'pass': SECRET, 'ok': V.bool, 'ver': V.str(20), 'dns': V.str(60),
      'running': V.bool, 'upstream': V.choice('quad9', 'cloudflare', 'google')}
MAIL = {'mode': V.choice(None, 'relay-existing', 'relay-start', 'account', 'off'), 'up': V.choice('resend', 'other'),
        'prov': V.choice('gmail', 'icloud', 'other'), 'host': V.str(253), 'port': V.str(5), 'sec': V.choice('', 'none', 'starttls', 'tls'),
        'auth': V.bool, 'user': V.str(254), 'pass': SECRET, 'key': SECRET, 'from': V.email, 'to': V.email, 'running': V.bool}


def v_routing(v):
    if not isinstance(v, dict) or len(v) > 30: raise ValueError('invalid routing table')
    for k, row in v.items():
        V.token(k)
        if not isinstance(row, list) or len(row) > 8 or any(x not in (0, 1) for x in row): raise ValueError('invalid routing row')
    return v


def v_contacts(v):
    if not isinstance(v, list) or len(v) > 50: raise ValueError('too many contacts (max 50)')
    out = []
    for c in v:
        if not isinstance(c, dict): raise ValueError('invalid contact')
        tiers = c.get('tiers', {})
        if not isinstance(tiers, dict) or any(k not in ('distress', 'alarms', 'info') or x not in (0, 1) for k, x in tiers.items()):
            raise ValueError('invalid contact tiers')
        out.append({'id': V.num(0, 2**53)(c.get('id', 0)), 'name': V.str(80)(c.get('name', '')), 'email': V.email(c.get('email', '') or ''),
                    'mx': V.str(255)(c.get('mx', '') or ''), 'tiers': tiers})
    return out


MXID = re.compile(r'@[a-z0-9._=/+\-]{1,200}:[A-Za-z0-9.\-]{1,200}(:\d{1,5})?')


def v_esc(v):
    """Emergency countdown: per alarm on/off + seconds, whether the household room gets it, and who can cancel."""
    if not isinstance(v, dict): raise ValueError('must be an object')
    out = {}
    for kind in ('intrusion', 'fire', 'duress'):
        k = v.get(kind, {})
        if not isinstance(k, dict): raise ValueError(f'{kind}: must be an object')
        out[kind] = {'on': V.bool(k.get('on', True)), 'secs': V.num(10, 600)(k.get('secs', {'fire': 120}.get(kind, 60)))}
    out['room'] = V.bool(v.get('room', True))
    r = v.get('responders', [])
    if not isinstance(r, list) or len(r) > 20: raise ValueError('responders: at most 20')
    out['responders'] = []
    for x in r:
        if not isinstance(x, dict): raise ValueError('invalid responder')
        mx = V.str(255)(x.get('mx', '') or '').strip()
        if mx and not MXID.fullmatch(mx): raise ValueError(f'{mx}: a Matrix ID looks like @name:server')
        em = V.email(x.get('email', '') or '')
        if not (mx or em): raise ValueError('each person needs an email or a Matrix ID')
        out['responders'].append({'id': V.num(0, 2**53)(x.get('id', 0)), 'name': V.str(80)(x.get('name', '') or ''), 'email': em, 'mx': mx})
    return out


def v_sensor_meta(v):
    if not isinstance(v, dict) or len(v) > 200: raise ValueError('invalid sensor list')
    out = {}
    for sid, m in v.items():
        if not re.match(r'^\d{1,6}$', str(sid)) or not isinstance(m, dict): raise ValueError('invalid sensor entry')
        e = {}
        if 'name' in m: e['name'] = V.str(40)(m['name'])
        if 'room' in m: e['room'] = V.str(40)(m['room'])
        if 'as' in m: e['as'] = V.num(0, 7)(m['as'])
        if 'removed' in m: e['removed'] = V.bool(m['removed'])
        out[str(sid)] = e
    return out


def v_rooms(v):
    if not isinstance(v, list) or len(v) > 100: raise ValueError('invalid room list')
    return [V.str(40)(r) for r in v]


S, N, B, T, U = V.str, V.num, V.bool, V.token, V.url
SCHEMA = {
    # home & look
    'siteName': S(40), 'tempUnit': V.choice('F', 'C'), 'timeFmt': T, 'tz': T, 'theme': T, 'accent': T, 'density': T,
    'kiosk': B, 'showCodes': B, 'rawLog': B, 'updates': B, 'retention': N(1, 3650), 'manageNat': B, 'wireFile': B,
    # hub & network
    'hubName': S(40), 'hubLoc': S(80), 'serverIp': S(45), 'hubIp': S(45), 'listenPort': N(1, 65535), 'ph': obj(PH),
    # alarm (stored in OpenRoost; sending to the hub is pending the /config schema)
    'entryDelay': N(0, 300), 'exitDelay': N(0, 300), 'doorChime': B, 'alarmSound': B, 'duressSilent': B,
    # notifications
    'mail': obj(MAIL), 'smtpTo': V.emails, 'smtpSubject': S(200), 'repeatMin': N(0, 60), 'offlineMin': N(1, 120),
    'sensorMissingH': N(2, 168), 'lowBat': N(5, 50), 'quiet': S(40),
    'mxOn': B, 'mxHs': U, 'mxUser': S(255), 'mxRoom': S(255), 'mxToken': SECRET, 'mxMention': B, 'mxE2ee': B,
    'ntfyUrl': U, 'ntfyPrio': T, 'hookUrl': U, 'hookSecret': SECRET,
    'routing': v_routing, 'contacts': v_contacts, 'esc': v_esc,
    # climate
    'tempAlert': B, 'humAlert': B, 'tl': N(-40, 140), 'th': N(-40, 140), 'hl': N(0, 100), 'hh': N(0, 100),  # °F or °C (tempUnit)
    # account & sign-in
    'sessionLen': V.choice('1h', '12h', '1d', '7d', '30d'), 'totp': B, 'proxyAuth': B,
    'ssoOn': B, 'ssoLocal': B, 'ssoAutoCreate': B, 'ssoIssuer': U, 'ssoClientId': S(200), 'ssoSecret': SECRET,
    'ssoScopes': S(200), 'ssoButton': S(60), 'ssoAdminGroup': S(80), 'ssoMemberGroup': S(80),
    'proxyIps': S(200), 'proxyHeader': V.token, 'publicUrl': U,
    # sensors (names/rooms/alert modes the hub doesn't keep)
    'sensorMeta': v_sensor_meta, 'rooms': v_rooms,
}


def secret_paths(schema=SCHEMA, prefix=''):
    for k, spec in schema.items():
        if spec is SECRET: yield prefix + k
        elif isinstance(spec, tuple) and spec[0] == 'obj': yield from secret_paths(spec[1], prefix + k + '.')


SECRET_PATHS = tuple(secret_paths()) + ('pins',)


class ValidationError(ValueError):
    def __init__(self, errors): super().__init__('; '.join(f'{k}: {v}' for k, v in errors.items())); self.errors = errors


def split_settings(patch, schema=SCHEMA, prefix=''):
    """Validate a settings patch. Returns (plain, secrets): plain values to store as JSON, secrets
    to encrypt. A secret sent as '' means 'unchanged'; use clear=[...] on the API to remove one."""
    if not isinstance(patch, dict): raise ValidationError({prefix or 'settings': 'must be an object'})
    plain, secs, errors = {}, {}, {}
    for k, v in patch.items():
        path = prefix + k
        spec = schema.get(k)
        if spec is None: errors[path] = 'unknown setting'; continue
        try:
            if spec is SECRET:
                if v in ('', None): continue
                if not isinstance(v, str) or len(v) > 4096: raise ValueError('must be text up to 4096 characters')
                secs[path] = v
            elif isinstance(spec, tuple) and spec[0] == 'obj':
                p, s2 = split_settings(v, spec[1], path + '.')
                plain[k] = p; secs.update(s2)
            else:
                plain[k] = spec(v)
        except ValidationError as e: errors.update(e.errors)
        except ValueError as e: errors[path] = str(e)
    if errors: raise ValidationError(errors)
    return plain, secs


def v_pins(p):
    """Keypad PINs: owner, hostage (4 digits or empty) and up to 20 guests."""
    if not isinstance(p, dict): raise ValidationError({'pins': 'must be an object'})

    def digits(x, k):
        if isinstance(x, str) and re.fullmatch(r'\d{4}|', x): return x
        raise ValidationError({k: 'must be 4 digits'})
    out = {'owner': digits(p.get('owner', ''), 'pins.owner'), 'hostage': digits(p.get('hostage', ''), 'pins.hostage'), 'guests': []}
    g = p.get('guests', [])
    if not isinstance(g, list) or len(g) > 20: raise ValidationError({'pins.guests': 'max 20 guests'})
    for x in g:
        if not isinstance(x, dict): raise ValidationError({'pins.guests': 'invalid guest'})
        out['guests'].append({'id': V.num(0, 2**53)(x.get('id', 0)), 'name': V.str(40)(x.get('name', '')),
                              'pin': digits(x.get('pin', ''), 'pins.guests.pin'), 'active': bool(x.get('active', True))})
    if out['owner'] and out['owner'] == out['hostage']: raise ValidationError({'pins.hostage': 'must differ from the owner PIN'})
    return out


def deep_merge(a, b):
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(a.get(k), dict) and k not in ('routing', 'sensorMeta'): deep_merge(a[k], v)
        else: a[k] = v
    return a


# ---------------------------------------------------------------- crypto
def _write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as f: f.write(data); f.flush(); os.fsync(f.fileno())


def _read_key(path):
    _check_private(path)
    with open(path, 'rb') as f: master = f.read()
    if len(master) != 32: raise SystemExit(f'{path} must be exactly 32 bytes')
    return master


class Keys:
    def __init__(self, master: bytes, from_env=False):
        if len(master) != 32: raise SystemExit('master key must be exactly 32 bytes')
        sub = lambda info: HKDF(hashes.SHA256(), 32, salt=b'openroost360', info=info).derive(master)
        self.enc = AESGCM(sub(b'secrets-v1'))
        self.pepper = sub(b'password-pepper-v1')
        self.token_key = sub(b'session-tokens-v1')
        self.id = sub(b'key-id-v1')[:6].hex()                 # public: names the key, reveals nothing about it
        self.from_env = from_env
        self.old_peppers = {}                                  # key id -> pepper of a rotated-out key (filled by Store)

    @classmethod
    def load(cls, data_dir, db_key_id=None):
        raw = os.environ.get('OPENROOST_MASTER_KEY')
        if raw: return cls(base64.b64decode(raw), from_env=True)
        path = os.path.join(data_dir, 'master.key'); nxt = path + '.next'
        if os.path.exists(nxt):                                # a rotation was interrupted: keep whichever key the database uses
            new = cls(_read_key(nxt))
            if db_key_id == new.id: os.replace(nxt, path)
            else: os.remove(nxt)
        if not os.path.exists(path):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as f: f.write(secrets.token_bytes(32))
        return cls(_read_key(path))

    def seal(self, name, plaintext: str) -> bytes:
        nonce = secrets.token_bytes(12)
        return bytes([KEY_VERSION]) + nonce + self.enc.encrypt(nonce, plaintext.encode(), b'openroost:secret:' + name.encode())

    def open(self, name, blob: bytes) -> str:
        if blob[0] != KEY_VERSION: raise ValueError('unknown key version')
        return self.enc.decrypt(blob[1:13], blob[13:], b'openroost:secret:' + name.encode()).decode()

    def hash_password(self, pw: str) -> str:
        salt = secrets.token_bytes(16)
        h = Argon2id(salt=salt, secret=self.pepper, **ARGON).derive(pw.encode())
        b = lambda x: base64.b64encode(x).decode().rstrip('=')
        return f"argon2id$v=19$m={ARGON['memory_cost']},t={ARGON['iterations']},p={ARGON['lanes']},k={self.id}${b(salt)}${b(h)}"

    @staticmethod
    def hash_key(stored: str):
        """Id of the key whose pepper made this hash (None: made before key ids existed, i.e. by the current key)."""
        try: return dict(x.split('=') for x in stored.split('$')[2].split(',')).get('k')
        except Exception: return None

    def needs_rehash(self, stored: str) -> bool:
        k = self.hash_key(stored); return k is not None and k != self.id

    def verify_password(self, pw: str, stored: str) -> bool:
        try:
            _, _, params, salt, h = stored.split('$')
            p = dict(x.split('=') for x in params.split(','))
            k = p.get('k'); pepper = self.pepper if k in (None, self.id) else self.old_peppers[k]
            d = lambda x: base64.b64decode(x + '=' * (-len(x) % 4))
            Argon2id(salt=d(salt), secret=pepper, length=32, iterations=int(p['t']), lanes=int(p['p']), memory_cost=int(p['m'])).verify(pw.encode(), d(h))
            return True
        except Exception:
            return False

    def token_hash(self, token: str) -> str:
        return hmac.new(self.token_key, token.encode(), hashlib.sha256).hexdigest()


def _check_private(path):
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:
        os.chmod(path, 0o600)


# ---------------------------------------------------------------- database
DDL = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated REAL NOT NULL);
CREATE TABLE IF NOT EXISTS secrets (name TEXT PRIMARY KEY, blob BLOB NOT NULL, updated REAL NOT NULL);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE, display TEXT NOT NULL, email TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL CHECK (role IN ('owner','member','viewer')), pw_hash TEXT NOT NULL, created REAL NOT NULL, pw_changed REAL NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created REAL NOT NULL, expires REAL NOT NULL, last_seen REAL NOT NULL, ip TEXT NOT NULL, ua TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, t REAL NOT NULL, user TEXT NOT NULL, ip TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS throttle (key TEXT PRIMARY KEY, fails TEXT NOT NULL, locked REAL NOT NULL);
-- hub side (written by the listener via openroost.hub)
CREATE TABLE IF NOT EXISTS hub_kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sensors (id INTEGER PRIMARY KEY, data TEXT NOT NULL, updated REAL NOT NULL);
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, t REAL NOT NULL, kind TEXT NOT NULL, sev TEXT NOT NULL, title TEXT NOT NULL,
  detail TEXT NOT NULL, sensor INTEGER, raw TEXT);
CREATE INDEX IF NOT EXISTS events_t ON events(t);
CREATE TABLE IF NOT EXISTS alerts (kind TEXT PRIMARY KEY, data TEXT NOT NULL);
"""
MIGRATIONS = [  # (table, column, definition) added after first release; applied if missing
    ('users', 'totp', "BLOB"), ('users', 'oidc_sub', "TEXT"),
    ('sessions', 'kind', "TEXT NOT NULL DEFAULT 'web'"), ('sessions', 'name', "TEXT NOT NULL DEFAULT ''"),
]


class Store:
    def __init__(self, data_dir):
        os.makedirs(data_dir, mode=0o700, exist_ok=True)
        try:
            os.chmod(data_dir, 0o700)
            probe = os.path.join(data_dir, '.write-test'); open(probe, 'w').close(); os.remove(probe)
        except PermissionError:
            raise SystemExit(f'OpenRoost can\'t write to its data folder {data_dir}. Under Docker the container runs as root without '
                             f'permission to override file ownership, so the folder must belong to root: `sudo chown -R root:root data`, '
                             f'or delete the empty folder and let Docker create it.') from None
        self.data_dir = data_dir
        self.path = os.path.join(data_dir, 'openroost.db')
        new = not os.path.exists(self.path)
        if new: os.close(os.open(self.path, os.O_WRONLY | os.O_CREAT, 0o600))
        _check_private(self.path)
        self.db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self.db.execute('PRAGMA foreign_keys=ON'); self.db.execute('PRAGMA journal_mode=WAL'); self.db.execute('PRAGMA secure_delete=ON')
        if not new: self._snapshot_on_upgrade()
        self.db.executescript(DDL)
        for table, col, ddl in MIGRATIONS:
            if col not in {r[1] for r in self.db.execute(f'PRAGMA table_info({table})')}:
                self.db.execute(f'ALTER TABLE {table} ADD COLUMN {col} {ddl}')
        self.lock = threading.RLock()
        for suffix in ('-wal', '-shm'):
            if os.path.exists(self.path + suffix): _check_private(self.path + suffix)
        db_key = self.meta('key_id')
        self.keys = Keys.load(data_dir, db_key)
        if db_key is None: self.set_meta('key_id', self.keys.id)
        elif db_key != self.keys.id:
            raise SystemExit(f'The master key ({self.keys.id}) is not the one this database was encrypted with ({db_key}). '
                             'Restore the matching master.key (it is inside every OpenRoost backup).')
        self._load_old_peppers()
        self._migrate_settings()
        self.set_meta('version', RUNNING)

    # ---- updates keep everything: data lives in the data folder, the schema only ever grows (new tables / columns),
    # and before a different version first opens the database a copy is kept in data/backups/.
    KEEP_SNAPSHOTS = 5

    def _snapshot_on_upgrade(self):
        try: r = self.db.execute("SELECT value FROM meta WHERE key='version'").fetchall()
        except sqlite3.OperationalError: r = []
        old = r[0][0] if r else 'unknown'
        if old == RUNNING: return
        folder = os.path.join(self.data_dir, 'backups')
        os.makedirs(folder, mode=0o700, exist_ok=True)
        dest = os.path.join(folder, f'openroost-{time.strftime("%Y%m%d-%H%M%S")}-{re.sub(r"[^0-9A-Za-z.+]", "", old)}.db')
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600); os.close(fd)
        out = sqlite3.connect(dest)
        try: self.db.backup(out)
        finally: out.close()
        snaps = sorted(f for f in os.listdir(folder) if f.startswith('openroost-') and f.endswith('.db'))
        for f in snaps[:-self.KEEP_SNAPSHOTS]:
            try: os.remove(os.path.join(folder, f))
            except OSError: pass
        print(f'Database copied to {dest} before opening it with {RUNNING} (was {old})', flush=True)

    def _migrate_settings(self):
        """One-time changes to stored settings. Each runs once (marked in meta) and only touches values the owner never
        changed from an old default."""
        if self.meta('mig.lowbat35') is None:
            if self.get_settings().get('lowBat') == 20: self.save_settings({'lowBat': 35})      # old default 20 % → 35 %
            self.set_meta('mig.lowbat35', '1')

    def _load_old_peppers(self):
        self.keys.old_peppers = {}
        for (name,) in self.q("SELECT name FROM secrets WHERE name LIKE 'pepper:%'"):
            self.keys.old_peppers[name[7:]] = base64.b64decode(self.get_secret(name))

    def q(self, sql, *args):
        with self.lock: return self.db.execute(sql, args).fetchall()

    def tx(self):
        return _Tx(self)

    # ---- meta / setup
    def meta(self, key, default=None):
        r = self.q('SELECT value FROM meta WHERE key=?', key); return r[0][0] if r else default

    def set_meta(self, key, value):
        self.q('INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', key, value)

    def setup_done(self):
        return self.meta('setup_done') == '1'

    def new_setup_code(self):
        """One-time code that must be typed into setup; only its keyed hash is kept."""
        code = '-'.join(secrets.token_hex(2).upper() for _ in range(3))
        self.set_meta('setup_code', self.keys.token_hash('setup:' + code))
        return code

    def check_setup_code(self, code):
        want = self.meta('setup_code')
        return bool(want) and isinstance(code, str) and hmac.compare_digest(want, self.keys.token_hash('setup:' + code.strip().upper()))

    # ---- settings
    def get_settings(self):
        out = {}
        for k, v in self.q('SELECT key, value FROM settings'): out[k] = json.loads(v)
        return out

    def secrets_set(self):
        names = {r[0] for r in self.q('SELECT name FROM secrets')}
        return {p: p in names for p in SECRET_PATHS}

    def save_settings(self, patch, clear=(), *, merge=True):
        plain, secs = split_settings(patch)
        bad = [c for c in clear if c not in SECRET_PATHS]
        if bad: raise ValidationError({c: 'not a secret' for c in bad})
        now = time.time()
        with self.tx():
            cur = self.get_settings()
            for k, v in plain.items():
                if merge and isinstance(v, dict) and isinstance(cur.get(k), dict) and k not in ('routing', 'sensorMeta'): v = deep_merge(cur[k], v)
                self.db.execute('INSERT INTO settings(key,value,updated) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated=excluded.updated',
                                (k, json.dumps(v, separators=(',', ':')), now))
            for name, val in secs.items(): self._put_secret(name, val, now)
            for name in clear: self.db.execute('DELETE FROM secrets WHERE name=?', (name,))
        return sorted(plain), sorted(secs), list(clear)

    def _put_secret(self, name, val, now=None):
        self.db.execute('INSERT INTO secrets(name,blob,updated) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET blob=excluded.blob, updated=excluded.updated',
                        (name, self.keys.seal(name, val), now or time.time()))

    def set_secret(self, name, val):
        """Internal secrets (not settings): None deletes."""
        with self.tx():
            if val is None: self.db.execute('DELETE FROM secrets WHERE name=?', (name,))
            else: self._put_secret(name, val)

    def get_secret(self, name):
        """Server-side use only (e.g. signing in to Pi-hole). Never sent to the browser."""
        r = self.q('SELECT blob FROM secrets WHERE name=?', name)
        return self.keys.open(name, r[0][0]) if r else None

    def get_pins(self):
        raw = self.get_secret('pins'); return json.loads(raw) if raw else {'owner': '', 'hostage': '', 'guests': []}

    def save_pins(self, pins):
        pins = v_pins(pins)
        with self.tx(): self._put_secret('pins', json.dumps(pins))
        return pins

    # ---- users
    def user_count(self):
        return self.q('SELECT COUNT(*) FROM users')[0][0]

    def create_user(self, username, password, role, display='', email=''):
        username = (username or '').strip()
        if not re.fullmatch(r'[A-Za-z0-9._-]{3,32}', username): raise ValidationError({'username': '3–32 letters, digits, . _ or -'})
        if role not in ROLES: raise ValidationError({'role': 'unknown role'})
        check_password(password, username)
        V.str(80)(display); V.email(email)
        now = time.time()
        try:
            with self.tx():
                cur = self.db.execute('INSERT INTO users(username,display,email,role,pw_hash,created,pw_changed) VALUES(?,?,?,?,?,?,?)',
                                      (username, display or username, email, role, self.keys.hash_password(password), now, now))
            return cur.lastrowid
        except sqlite3.IntegrityError:
            raise ValidationError({'username': 'already taken'})

    def users(self):
        return [dict(id=r[0], username=r[1], display=r[2], email=r[3], role=r[4], created=r[5], totp=bool(r[6]), sso=bool(r[7]))
                for r in self.q('SELECT id, username, display, email, role, created, totp, oidc_sub FROM users ORDER BY id')]

    def user(self, uid):
        r = self.q('SELECT id, username, display, email, role, pw_hash, totp, oidc_sub FROM users WHERE id=?', uid)
        if not r: return None
        u = dict(zip(('id', 'username', 'display', 'email', 'role', 'pw_hash', 'totp', 'oidc_sub'), r[0]))
        u['totp_on'] = bool(u['totp'])
        return u

    def user_totp_secret(self, uid):
        r = self.q('SELECT totp FROM users WHERE id=?', uid)
        return self.keys.open(f'totp:{uid}', r[0][0]) if r and r[0][0] else None

    def set_user_totp(self, uid, secret_b32):
        with self.lock: self.q('UPDATE users SET totp=? WHERE id=?', self.keys.seal(f'totp:{uid}', secret_b32) if secret_b32 else None, uid)

    def user_by_oidc(self, sub):
        r = self.q('SELECT id FROM users WHERE oidc_sub=?', sub)
        return self.user(r[0][0]) if r else None

    def link_oidc(self, uid, sub):
        self.q('UPDATE users SET oidc_sub=? WHERE id=?', sub, uid)

    def user_by_name(self, username):
        r = self.q('SELECT id FROM users WHERE username=?', username or '')
        return self.user(r[0][0]) if r else None

    def owners(self):
        return self.q("SELECT COUNT(*) FROM users WHERE role='owner'")[0][0]

    def set_password(self, uid, password):
        u = self.user(uid); check_password(password, u['username'])
        with self.tx():
            self.db.execute('UPDATE users SET pw_hash=?, pw_changed=? WHERE id=?', (self.keys.hash_password(password), time.time(), uid))

    def rehash_if_old(self, uid, password):
        """After a successful sign-in: move a hash made with a rotated-out key's pepper to the current key."""
        u = self.user(uid)
        if u and self.keys.needs_rehash(u['pw_hash']):
            with self.tx(): self.db.execute('UPDATE users SET pw_hash=? WHERE id=?', (self.keys.hash_password(password), uid))
            self._drop_unused_peppers()

    def _drop_unused_peppers(self):
        used = {self.keys.hash_key(h) for (h,) in self.q('SELECT pw_hash FROM users')}
        for k in list(self.keys.old_peppers):
            if k not in used:
                self.q('DELETE FROM secrets WHERE name=?', 'pepper:' + k); self.keys.old_peppers.pop(k, None)

    def accounts_on_old_key(self):
        return sum(1 for (h,) in self.q('SELECT pw_hash FROM users') if self.keys.needs_rehash(h))

    # ---- master-key rotation
    def rotate_key(self):
        """Re-encrypt everything under a new master key. Returns how many sessions were ended."""
        if self.keys.from_env:
            raise ValueError('The master key comes from OPENROOST_MASTER_KEY. Generate a new one, then restore a backup with it — or remove the variable to let OpenRoost manage master.key.')
        path = os.path.join(self.data_dir, 'master.key'); nxt = path + '.next'
        master = secrets.token_bytes(32); old, new = self.keys, Keys(master)
        with self.lock:
            _write_private(nxt, master)                       # 1. new key on disk first (start-up decides which one is live)
            try:
                with self.tx():                                # 2. everything re-encrypted in one transaction
                    for name, blob in self.db.execute('SELECT name, blob FROM secrets').fetchall():
                        self.db.execute('UPDATE secrets SET blob=? WHERE name=?', (new.seal(name, old.open(name, blob)), name))
                    self.db.execute('INSERT INTO secrets(name,blob,updated) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET blob=excluded.blob',
                                    ('pepper:' + old.id, new.seal('pepper:' + old.id, base64.b64encode(old.pepper).decode()), time.time()))
                    for uid, blob in self.db.execute('SELECT id, totp FROM users WHERE totp IS NOT NULL').fetchall():
                        self.db.execute('UPDATE users SET totp=? WHERE id=?', (new.seal(f'totp:{uid}', old.open(f'totp:{uid}', blob)), uid))
                    for uid, h in self.db.execute('SELECT id, pw_hash FROM users').fetchall():
                        if old.hash_key(h) is None:            # tag hashes from before key ids with the key that made them
                            parts = h.split('$'); parts[2] += ',k=' + old.id
                            self.db.execute('UPDATE users SET pw_hash=? WHERE id=?', ('$'.join(parts), uid))
                    ended = self.db.execute('DELETE FROM sessions').rowcount
                    for pre in ('reset:', 'invite:', 'totp_pending:'):
                        self.db.execute('DELETE FROM hub_kv WHERE key LIKE ?', (pre + '%',))
                    self.db.execute("DELETE FROM meta WHERE key='setup_code'")
                    self.db.execute('INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', ('key_id', new.id))
            except Exception:
                os.remove(nxt); raise
            os.replace(nxt, path)                              # 3. switch the file
            try:
                dfd = os.open(self.data_dir, os.O_RDONLY); os.fsync(dfd); os.close(dfd)
            except OSError: pass
            self.keys = new
            self._load_old_peppers(); self._drop_unused_peppers()
        return ended

    # ---- sessions
    def new_session(self, uid, ip, ua, ttl, kind='web', name=''):
        token = secrets.token_urlsafe(32); sid = secrets.token_hex(8); now = time.time()
        if kind == 'device': token = 'ort_' + token          # recognisable prefix for app tokens (secret scanners)
        self.q('INSERT INTO sessions(id,token_hash,user_id,created,expires,last_seen,ip,ua,kind,name) VALUES(?,?,?,?,?,?,?,?,?,?)',
               sid, self.keys.token_hash(token), uid, now, now + ttl, now, ip, (ua or '')[:200], kind, (name or '')[:60])
        return token, sid

    def session(self, token):
        if not token or len(token) > 100: return None
        r = self.q('SELECT s.id, s.user_id, s.expires, s.kind, s.created FROM sessions s WHERE s.token_hash=?', self.keys.token_hash(token))
        if not r: return None
        sid, uid, exp, kind, created = r[0]
        now = time.time()
        if exp < now: self.q('DELETE FROM sessions WHERE id=?', sid); return None
        if kind == 'device':   # app tokens slide: each use extends to 90 days, capped at 1 year from creation
            self.q('UPDATE sessions SET last_seen=?, expires=? WHERE id=?', now, min(now + 90 * 86400, created + 365 * 86400), sid)
        else:
            self.q('UPDATE sessions SET last_seen=? WHERE id=?', now, sid)
        u = self.user(uid)
        return (sid, u, kind) if u else None

    def sessions_for(self, uid):
        return [dict(id=r[0], created=r[1], last_seen=r[2], ip=r[3], ua=r[4], kind=r[5], name=r[6]) for r in
                self.q('SELECT id, created, last_seen, ip, ua, kind, name FROM sessions WHERE user_id=? AND expires>? ORDER BY last_seen DESC', uid, time.time())]

    def end_session(self, sid, uid=None):
        if uid is None: self.q('DELETE FROM sessions WHERE id=?', sid)
        else: self.q('DELETE FROM sessions WHERE id=? AND user_id=?', sid, uid)

    def end_other_sessions(self, uid, keep_sid=None):
        self.q('DELETE FROM sessions WHERE user_id=? AND id IS NOT ?', uid, keep_sid)

    # ---- hub side
    def kv(self, key, default=None):
        r = self.q('SELECT value FROM hub_kv WHERE key=?', key); return json.loads(r[0][0]) if r else default

    def kv_prefix(self, prefix):
        return [(k, json.loads(v)) for k, v in self.q('SELECT key, value FROM hub_kv WHERE key LIKE ?', prefix + '%')]

    def del_kv(self, key):
        self.q('DELETE FROM hub_kv WHERE key=?', key)

    def set_kv(self, key, value):
        self.q('INSERT INTO hub_kv(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', key, json.dumps(value))

    def save_sensor(self, sid, data):
        self.q('INSERT INTO sensors(id,data,updated) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data, updated=excluded.updated',
               sid, json.dumps(data), time.time())

    def sensors_all(self):
        return {r[0]: json.loads(r[1]) for r in self.q('SELECT id, data FROM sensors')}

    def add_event(self, t, kind, sev, title, detail='', sensor=None, raw=None):
        with self.lock:
            cur = self.db.execute('INSERT INTO events(t,kind,sev,title,detail,sensor,raw) VALUES(?,?,?,?,?,?,?)',
                                  (t, kind, sev, title, detail, sensor, json.dumps(raw) if raw is not None else None))
            return cur.lastrowid

    def events(self, limit=100, before=None, kinds=None, since=None):
        sql, args = 'SELECT id, t, kind, sev, title, detail, sensor, raw FROM events WHERE 1=1', []
        if before: sql += ' AND id < ?'; args.append(int(before))
        if since: sql += ' AND t >= ?'; args.append(float(since))
        if kinds: sql += ' AND kind IN (%s)' % ','.join('?' * len(kinds)); args += list(kinds)
        sql += ' ORDER BY id DESC LIMIT ?'; args.append(max(1, min(int(limit), 500)))
        return [dict(id=r[0], t=r[1], kind=r[2], sev=r[3], title=r[4], detail=r[5], sensor=r[6], raw=json.loads(r[7]) if r[7] else None)
                for r in self.q(sql, *args)]

    def prune_events(self, days):
        self.q('DELETE FROM events WHERE t < ?', time.time() - days * 86400)

    def alerts_all(self):
        return [json.loads(r[0]) for r in self.q('SELECT data FROM alerts')]

    def save_alert(self, kind, data):
        self.q('INSERT INTO alerts(kind,data) VALUES(?,?) ON CONFLICT(kind) DO UPDATE SET data=excluded.data', kind, json.dumps(data))

    def drop_alert(self, kind):
        self.q('DELETE FROM alerts WHERE kind=?', kind)

    # ---- sign-in throttling (persisted, so a restart doesn't reset it)
    def throttle_get(self, key):
        r = self.q('SELECT fails, locked FROM throttle WHERE key=?', key)
        return (json.loads(r[0][0]), r[0][1]) if r else ([], 0)

    def throttle_set(self, key, fails, locked):
        if not fails and not locked: self.q('DELETE FROM throttle WHERE key=?', key); return
        self.q('INSERT INTO throttle(key,fails,locked) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET fails=excluded.fails, locked=excluded.locked', key, json.dumps(fails), locked)

    # ---- audit
    def audit(self, user, ip, action, detail=''):
        self.q('INSERT INTO audit(t,user,ip,action,detail) VALUES(?,?,?,?,?)', time.time(), user or '-', ip or '-', action, str(detail)[:500])

    def audit_log(self, limit=200):
        return [dict(t=r[0], user=r[1], ip=r[2], action=r[3], detail=r[4]) for r in
                self.q('SELECT t, user, ip, action, detail FROM audit ORDER BY id DESC LIMIT ?', limit)]


class _Tx:
    def __init__(self, s): self.s = s

    def __enter__(self):
        self.s.lock.acquire(); self.s.db.execute('BEGIN IMMEDIATE')

    def __exit__(self, et, *_):
        try: self.s.db.execute('ROLLBACK' if et else 'COMMIT')
        finally: self.s.lock.release()


COMMON = {'password', 'password1', 'password123', '123456789012', 'qwertyuiop12', 'openroost360', 'letmein12345', 'iloveyou1234', 'administrator'}


def check_password(pw, username=''):
    if not isinstance(pw, str) or len(pw) < PASSWORD_MIN: raise ValidationError({'password': f'at least {PASSWORD_MIN} characters'})
    if len(pw) > 256: raise ValidationError({'password': 'at most 256 characters'})
    low = pw.lower()
    if low in COMMON or (username and username.lower() in low) or len(set(pw)) < 5:
        raise ValidationError({'password': 'too easy to guess'})
