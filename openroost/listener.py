"""Hub-facing listener: the stand-in for Roost's cloud (production version of roost_listen.py).

The SmartBase reaches it through Pi-hole (cloud names -> this server) and the port 443 -> 8883
redirect. On one TLS port it answers both:
  * HTTPS  POST /getCurrentTime  -> {"time": <epoch ms>}   (anything else -> 404)
  * MQTT 3.1.1: CONNECT/CONNACK, PUBLISH (+PUBACK), SUBSCRIBE (+SUBACK, then an empty /config,
    which is what keeps the hub connected), PINGREQ, DISCONNECT.
The hub doesn't validate certificates, so a self-signed one works (made once, kept in the data folder).

Safety: the hub only ever receives an empty /config. Nothing is sent on /commands (the format
isn't known; see PROTOCOL.md) — publish() exists for when it is.
"""
import collections, datetime, json, os, socket, ssl, threading, time
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

HOSTS = ['us-central1-mqtt.clearblade.com', 'us-central1-roostprod.cloudfunctions.net']
MAX_PACKET = 256 * 1024
MAX_CLIENTS = 16


def ensure_cert(data_dir):
    crt, key = os.path.join(data_dir, 'listener.crt'), os.path.join(data_dir, 'listener.key')
    if os.path.exists(crt) and os.path.exists(key): return crt, key
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOSTS[0])])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(h) for h in HOSTS + ['*.clearblade.com', '*.cloudfunctions.net']]), False)
            .sign(k, hashes.SHA256()))
    fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    with open(crt, 'wb') as f: f.write(cert.public_bytes(serialization.Encoding.PEM))
    return crt, key


def tls_context(crt, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1          # the hub's embedded TLS stack is old
    try: ctx.set_ciphers('ALL:@SECLEVEL=0')
    except ssl.SSLError: pass
    ctx.load_cert_chain(crt, key)
    return ctx


def _enc_len(n):
    out = b''
    while True:
        d, n = n % 128, n // 128
        out += bytes([d | (0x80 if n else 0)])
        if not n: return out


class Session:
    def __init__(self, conn, ip):
        self.conn, self.ip, self.lock, self.pid = conn, ip, threading.Lock(), 0
        self.config_topic = self.cmd_topic = None

    def send(self, data):
        with self.lock: self.conn.sendall(data)

    def read_exact(self, n):
        buf = b''
        while len(buf) < n:
            chunk = self.conn.recv(n - len(buf))
            if not chunk: raise ConnectionError('closed')
            buf += chunk
        return buf

    def read_packet(self, first=None):
        b0 = first if first is not None else self.read_exact(1)[0]
        mult, length = 1, 0
        for _ in range(4):
            d = self.read_exact(1)[0]; length += (d & 0x7F) * mult
            if not d & 0x80: break
            mult *= 128
        if length > MAX_PACKET: raise ConnectionError('packet too large')
        return b0, self.read_exact(length) if length else b''

    def publish(self, topic, payload, qos=1):
        self.pid = self.pid % 65535 + 1
        t = topic.encode()
        body = len(t).to_bytes(2, 'big') + t + (self.pid.to_bytes(2, 'big') if qos else b'') + payload
        self.send(bytes([0x30 | (qos << 1)]) + _enc_len(len(body)) + body)


def _mqtt_str(data, i):
    n = int.from_bytes(data[i:i + 2], 'big')
    return data[i + 2:i + 2 + n], i + 2 + n


WIRE_MAX = 3000                         # protocol-log entries kept in memory
WIRE_FILE_MAX = 20 * 1024 * 1024        # data/wire.jsonl rotates to wire.jsonl.1 at this size


def _show(payload):
    """A payload as the protocol log shows it: JSON if it parses, else text, else hex."""
    if not payload: return {'empty': True}
    try:
        txt = payload.decode()
        try: return {'json': json.loads(txt)}
        except ValueError: return {'text': txt[:4000]}
    except UnicodeDecodeError:
        return {'hex': payload[:2000].hex()}


def _jwt(tok):
    """Header and claims of a JWT (not the signature)."""
    try:
        import base64
        h, c, _ = tok.split('.')
        dec = lambda x: json.loads(base64.urlsafe_b64decode(x + '=' * (-len(x) % 4)))
        return {'header': dec(h), 'claims': dec(c)}
    except Exception:
        return None


class Listener:
    def __init__(self, hub, data_dir, port=8883, bind='0.0.0.0', log=print):
        self.hub, self.port, self.bind, self.log = hub, port, bind, log
        self.ctx = tls_context(*ensure_cert(data_dir))
        self.ctx.sni_callback = self._sni
        self.sessions, self.slots = set(), threading.BoundedSemaphore(MAX_CLIENTS)
        self.wire, self.wire_lock, self.seq = collections.deque(maxlen=WIRE_MAX), threading.Lock(), 0
        self.wire_path = os.path.join(data_dir, 'wire.jsonl')
        self.wire_stdout = os.environ.get('OPENROOST_WIRE_STDOUT') == '1'
        self._wire_file_on, self._wire_checked = False, 0
        hub.publish_hook = self.publish
        hub.wire = self

    # -------------------------------------------------- protocol log (for reverse-engineering)
    @staticmethod
    def _sni(sslsock, name, ctx):
        try: sslsock.sni = name
        except AttributeError: pass

    def trace(self, ip, kind, **data):
        with self.wire_lock:
            self.seq += 1
            e = {'seq': self.seq, 't': round(time.time(), 3), 'ip': ip, 'kind': kind, **data}
            self.wire.append(e)
        self.hub.bus.publish('wire', e)
        if self.wire_stdout:
            self.log('wire ' + json.dumps(e, separators=(',', ':'), ensure_ascii=False)[:2000])
        now = time.time()
        if now - self._wire_checked > 5:
            self._wire_checked = now
            self._wire_file_on = bool(self.hub.store.get_settings().get('wireFile'))
        if self._wire_file_on:
            try:
                if os.path.exists(self.wire_path) and os.path.getsize(self.wire_path) > WIRE_FILE_MAX:
                    os.replace(self.wire_path, self.wire_path + '.1')
                fd = os.open(self.wire_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                with os.fdopen(fd, 'a') as f: f.write(json.dumps(e, ensure_ascii=False) + '\n')
            except OSError: pass

    def recent(self, limit=1000, after=0):
        with self.wire_lock: items = [e for e in self.wire if e['seq'] > after]
        return items[-limit:]

    def start(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.bind, self.port)); srv.listen(16)
        self.hub.on_listening(self.port)
        threading.Thread(target=self._accept, args=(srv,), daemon=True, name='listener').start()
        return self

    def _accept(self, srv):
        while True:
            raw, addr = srv.accept()
            if not self.slots.acquire(blocking=False): raw.close(); continue
            threading.Thread(target=self._client, args=(raw, addr[0]), daemon=True).start()

    def _client(self, raw, ip):
        try:
            self.trace(ip, 'tcp', port=self.port)
            raw.settimeout(30)
            try: conn = self.ctx.wrap_socket(raw, server_side=True)
            except (ssl.SSLError, OSError) as e:                     # the hub drops its first attempt every time; harmless
                self.trace(ip, 'tls_failed', error=str(e)[:300]); raw.close(); return
            self.trace(ip, 'tls', version=conn.version(), cipher=(conn.cipher() or [None])[0], sni=getattr(conn, 'sni', None))
            sess = Session(conn, ip); reason = 'closed'
            try:
                first = sess.read_exact(1)[0]
                if first >> 4 == 1: self._mqtt(sess, first)
                else: self._http(sess, first)
            except (ConnectionError, OSError, ValueError, IndexError) as e:
                reason = str(e)[:200] or type(e).__name__
            finally:
                self.trace(ip, 'closed', reason=reason)
                if sess in self.sessions:
                    self.sessions.discard(sess); self.hub.on_disconnect()
                try: conn.close()
                except OSError: pass
        finally:
            self.slots.release()

    # -------------------------------------------------- HTTPS: getCurrentTime
    def _http(self, sess, first):
        data = bytes([first])
        while b'\r\n\r\n' not in data and len(data) < 16384:
            chunk = sess.conn.recv(4096)
            if not chunk: break
            data += chunk
        head, _, rest = data.partition(b'\r\n\r\n')
        lines = head.decode(errors='replace').split('\r\n')
        headers = dict((k.strip(), v.strip()) for k, _, v in (l.partition(':') for l in lines[1:]) if k)
        self.trace(sess.ip, 'http', request=lines[0][:500], headers=headers, **_show(rest))
        if 'getcurrenttime' in lines[0].lower():
            body = json.dumps({'time': int(time.time() * 1000)}).encode()
            sess.send(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body)
            self.trace(sess.ip, 'http_reply', status=200, body=body.decode())
            self.hub.on_time_request(sess.ip)
        else:
            sess.send(b'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            self.trace(sess.ip, 'http_reply', status=404)

    # -------------------------------------------------- MQTT
    def _mqtt(self, sess, first):
        sess.conn.settimeout(180)                              # keepalive is 60 s; 3 missed pings = gone
        ip = sess.ip
        while True:
            b0, body = sess.read_packet(first); first = None
            ptype, flags = b0 >> 4, b0 & 0x0F
            if ptype == 1:                                      # CONNECT
                proto, i = _mqtt_str(body, 0); level, cflags = body[i], body[i + 1]
                keepalive = int.from_bytes(body[i + 2:i + 4], 'big'); i += 4
                cid, i = _mqtt_str(body, i)
                info = {'protocol': proto.decode(errors='replace'), 'level': level, 'flags': cflags, 'keepalive': keepalive, 'clientId': cid.decode(errors='replace')}
                try:
                    if cflags & 0x04:
                        wt, i = _mqtt_str(body, i); wm, i = _mqtt_str(body, i)
                        info.update(willTopic=wt.decode(errors='replace'), willMessage=_show(wm))
                    if cflags & 0x80: u, i = _mqtt_str(body, i); info['username'] = u.decode(errors='replace')
                    if cflags & 0x40:
                        pw, i = _mqtt_str(body, i); j = _jwt(pw.decode(errors='replace'))
                        info['password'] = {'jwt': j} if j else {'length': len(pw)}
                except IndexError: info['truncated'] = True
                self.trace(ip, 'connect', **info)
                client_id = info['clientId']
                if not self.hub.accept_client(client_id, ip):
                    sess.send(b'\x20\x02\x00\x05'); self.trace(ip, 'connack', code=5, note='not the claimed hub'); return
                sess.send(b'\x20\x02\x00\x00'); self.trace(ip, 'connack', code=0)
                self.sessions.add(sess); self.hub.on_connect(client_id, ip)
            elif sess not in self.sessions:
                self.trace(ip, 'packet', type=ptype, note='before CONNECT', hex=body[:200].hex()); return
            elif ptype == 3:                                    # PUBLISH
                qos = (flags >> 1) & 3
                topic, i = _mqtt_str(body, 0); pid = None
                if qos: pid = body[i:i + 2]; i += 2
                self.trace(ip, 'publish', topic=topic.decode(errors='replace'), qos=qos, retain=bool(flags & 1), dup=bool(flags & 8),
                           pid=int.from_bytes(pid, 'big') if pid else None, **_show(body[i:]))
                if qos == 1: sess.send(b'\x40\x02' + pid)
                elif qos == 2: sess.send(b'\x50\x02' + pid)
                self.hub.on_publish(topic.decode(errors='replace'), body[i:])
            elif ptype == 4:                                    # PUBACK (for what we sent)
                self.trace(ip, 'puback', pid=int.from_bytes(body[:2], 'big'))
            elif ptype == 6:                                    # PUBREL
                sess.send(b'\x70\x02' + body[:2]); self.trace(ip, 'pubrel', pid=int.from_bytes(body[:2], 'big'))
            elif ptype == 8:                                    # SUBSCRIBE
                pid, i, topics = body[:2], 2, []
                while i < len(body):
                    t, i = _mqtt_str(body, i); topics.append((t.decode(errors='replace'), body[i])); i += 1
                self.trace(ip, 'subscribe', topics=[{'topic': t, 'qos': q} for t, q in topics])
                sess.send(bytes([0x90, 2 + len(topics)]) + pid + bytes(min(q, 1) for _, q in topics))
                sent = False
                for t, q in topics:
                    if t.endswith('/commands/#'): sess.cmd_topic = t[:-2]
                    if t.endswith('/config'):
                        sess.config_topic = t; sess.publish(t, b'', min(q, 1)); sent = True   # empty /config keeps the hub online
                        self.trace(ip, 'sent', topic=t, qos=min(q, 1), pid=sess.pid, empty=True, note='empty /config keeps the hub connected')
                self.hub.on_subscribe([t for t, _ in topics], sent)
            elif ptype == 12:                                   # PINGREQ
                sess.send(b'\xd0\x00'); self.trace(ip, 'ping')
            elif ptype == 14:                                   # DISCONNECT
                self.trace(ip, 'disconnect'); return
            else:
                self.trace(ip, 'packet', type=ptype, flags=flags, hex=body[:400].hex())

    def publish(self, sub, payload):
        """Send to the hub's /commands/<sub>. Unused until the command format is known (PROTOCOL.md)."""
        for s in list(self.sessions):
            if s.cmd_topic:
                topic = s.cmd_topic + ('/' + sub if sub else '')
                s.publish(topic, payload); self.trace(s.ip, 'sent', topic=topic, qos=1, pid=s.pid, **_show(payload)); return True
        return False
