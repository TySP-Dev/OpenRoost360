#!/usr/bin/env python3
"""
roost_listen.py - fake MQTT/HTTPS endpoint for probing a Roost Security360 SmartBase.

Point the hub's cloud hostname at this machine (Pi-hole Local DNS record), power-cycle
the hub, and this tells you:
  * whether the hub accepts a certificate we made  (if not: "alert unknown ca")
  * if it does: the MQTT client id, the JWT it signs in with, its topics, and every
    payload it publishes (sensor events), logged to the console and to roost_log.jsonl

It answers just enough MQTT (CONNACK/SUBACK/PUBACK/PINGRESP) to keep the hub connected.
No third-party packages; needs python3 and the openssl CLI.

Live control (no hub reboot needed):
  * edit config.payload  -> pushed to the hub's /config topic within ~1 s
  * write command.payload -> sent once to /devices/<id>/commands, then renamed .sent

Usage:
  sudo python3 roost_listen.py                      # listens on 8883
  sudo python3 roost_listen.py --ports 8883 8443    # extra ports
"""
import argparse, base64, json, os, socket, ssl, subprocess, sys, threading, time, warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

HOSTS = ["us-central1-mqtt.clearblade.com", "us-central1-roostprod.cloudfunctions.net"]
# Wildcard SANs let the hub's TLS accept us for S3 / other Roost hosts too, so we can
# see (and log) what it requests there. We answer those with 404 and touch nothing.
WILDCARDS = ["*.s3.amazonaws.com", "*.amazonaws.com", "*.clearblade.com",
             "*.cloudfunctions.net", "*.getroost.com"]
LOG = "roost_log.jsonl"
lock = threading.Lock()


def log(event, **kw):
    rec = {"t": time.strftime("%Y-%m-%d %H:%M:%S"), "event": event, **kw}
    with lock:
        print(json.dumps(rec, ensure_ascii=False), flush=True)
        with open(LOG, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def make_cert(cert="fake.crt", key="fake.key"):
    if os.path.exists(cert) and os.path.exists(key):
        return cert, key
    san = ",".join(f"DNS:{h}" for h in HOSTS + WILDCARDS)
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
         "-keyout", key, "-out", cert, "-subj", f"/CN={HOSTS[0]}",
         "-addext", f"subjectAltName={san}"],
        check=True, capture_output=True)
    return cert, key


# ---------- MQTT parsing (3.1.1) ----------
def read_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf


def read_packet(conn, first=None):
    b0 = first if first is not None else read_exact(conn, 1)[0]
    mult, length = 1, 0
    while True:
        d = read_exact(conn, 1)[0]
        length += (d & 0x7F) * mult
        if not d & 0x80:
            break
        mult *= 128
    return b0, read_exact(conn, length) if length else b""


def mqtt_str(data, i):
    n = int.from_bytes(data[i:i + 2], "big")
    return data[i + 2:i + 2 + n], i + 2 + n


def decode_jwt(tok):
    try:
        parts = tok.split(".")
        dec = lambda s: json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
        return {"header": dec(parts[0]), "claims": dec(parts[1])}
    except Exception:
        return None


def show(payload):
    try:
        txt = payload.decode()
        try:
            return {"json": json.loads(txt)}
        except ValueError:
            return {"text": txt}
    except UnicodeDecodeError:
        return {"hex": payload.hex()}


def enc_len(n):
    out = b""
    while True:
        d, n = n % 128, n // 128
        out += bytes([d | (0x80 if n else 0)])
        if not n:
            return out


def config_payload():
    # Edit config.payload next to this script to change what the hub receives; no restart needed.
    path = os.path.join(HERE, "config.payload")
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read().rstrip(b"\r\n")
    return b""


class Session:
    """A connected hub. Sends are locked so the watcher thread can push messages too."""
    def __init__(self, conn, peer):
        self.conn, self.peer, self.lock = conn, peer, threading.Lock()
        self.pid = 0
        self.config_topic = self.cmd_topic = None

    def sendall(self, data):
        with self.lock:
            self.conn.sendall(data)

    def recv(self, n):
        return self.conn.recv(n)

    def next_pid(self):
        self.pid = self.pid % 65535 + 1
        return self.pid

    def publish(self, topic, payload, qos=1):
        pid = self.next_pid()
        t = topic.encode()
        body = len(t).to_bytes(2, "big") + t + (pid.to_bytes(2, "big") if qos else b"") + payload
        self.sendall(bytes([0x30 | (qos << 1)]) + enc_len(len(body)) + body)
        return pid


SESSIONS = set()
HERE = os.path.dirname(os.path.abspath(__file__))


def watcher():
    """Push config.payload whenever it changes; send command.payload once, then rename it."""
    cfg = os.path.join(HERE, "config.payload")
    cmd = os.path.join(HERE, "command.payload")
    last = os.path.getmtime(cfg) if os.path.exists(cfg) else None
    while True:
        time.sleep(1)
        m = os.path.getmtime(cfg) if os.path.exists(cfg) else None
        if m != last:
            last = m
            payload = config_payload()
            for s in list(SESSIONS):
                if s.config_topic:
                    try:
                        pid = s.publish(s.config_topic, payload)
                        log("SENT_CONFIG", peer=s.peer, topic=s.config_topic, pid=pid, live=True,
                            **show(payload) if payload else {"empty": True})
                    except OSError as e:
                        log("SEND_FAILED", peer=s.peer, error=str(e))
        if os.path.exists(cmd):
            with open(cmd, "rb") as f:
                payload = f.read().rstrip(b"\r\n")
            os.replace(cmd, cmd + ".sent")
            if not SESSIONS:
                log("COMMAND_NOT_SENT", reason="no hub connected", **show(payload))
            for s in list(SESSIONS):
                if s.cmd_topic:
                    try:
                        pid = s.publish(s.cmd_topic, payload)
                        log("SENT_COMMAND", peer=s.peer, topic=s.cmd_topic, pid=pid, **show(payload))
                    except OSError as e:
                        log("SEND_FAILED", peer=s.peer, error=str(e))


def handle_mqtt(raw_conn, peer, first):
    conn = Session(raw_conn, peer)
    SESSIONS.add(conn)
    try:
        _handle_mqtt(conn, peer, first)
    finally:
        SESSIONS.discard(conn)


def _handle_mqtt(conn, peer, first):
    while True:
        b0, body = read_packet(conn, first)
        first = None
        ptype, flags = b0 >> 4, b0 & 0x0F
        if ptype == 1:  # CONNECT
            proto, i = mqtt_str(body, 0)
            level, cflags = body[i], body[i + 1]
            i += 4  # level, flags, keepalive
            cid, i = mqtt_str(body, i)
            info = {"peer": peer, "protocol": proto.decode(errors="replace"), "level": level,
                    "client_id": cid.decode(errors="replace")}
            if cflags & 0x04:  # will
                wt, i = mqtt_str(body, i); wm, i = mqtt_str(body, i)
                info["will_topic"] = wt.decode(errors="replace")
            if cflags & 0x80:
                u, i = mqtt_str(body, i); info["username"] = u.decode(errors="replace")
            if cflags & 0x40:
                p, i = mqtt_str(body, i)
                pw = p.decode(errors="replace")
                info["password"] = pw
                j = decode_jwt(pw)
                if j:
                    info["password_jwt"] = j
            log("MQTT_CONNECT", **info)
            conn.sendall(b"\x20\x02\x00\x00")  # CONNACK accepted
        elif ptype == 3:  # PUBLISH
            qos = (flags >> 1) & 3
            topic, i = mqtt_str(body, 0)
            pid = None
            if qos:
                pid = body[i:i + 2]; i += 2
            log("MQTT_PUBLISH", peer=peer, topic=topic.decode(errors="replace"), qos=qos,
                **show(body[i:]))
            if qos == 1:
                conn.sendall(b"\x40\x02" + pid)
            elif qos == 2:
                conn.sendall(b"\x50\x02" + pid)
        elif ptype == 6:  # PUBREL
            conn.sendall(b"\x70\x02" + body[:2])
        elif ptype == 8:  # SUBSCRIBE
            pid, i, topics = body[:2], 2, []
            while i < len(body):
                t, i = mqtt_str(body, i); topics.append((t.decode(errors="replace"), body[i])); i += 1
            log("MQTT_SUBSCRIBE", peer=peer, topics=[t for t, _ in topics])
            conn.sendall(bytes([0x90, 2 + len(topics)]) + pid + bytes(min(q, 1) for _, q in topics))
            for t, q in topics:
                if t.endswith("/commands/#"):
                    conn.cmd_topic = t[:-2]
                if t.endswith("/config"):
                    conn.config_topic = t
                    payload = config_payload()
                    pid = conn.publish(t, payload, min(q, 1))
                    log("SENT_CONFIG", peer=peer, topic=t, qos=min(q, 1), pid=pid,
                        **show(payload) if payload else {"empty": True})
        elif ptype == 4:  # PUBACK from hub
            log("MQTT_PUBACK", peer=peer, pid=int.from_bytes(body[:2], "big"))
        elif ptype == 12:  # PINGREQ
            conn.sendall(b"\xd0\x00")
            log("MQTT_PING", peer=peer)
        elif ptype == 14:  # DISCONNECT
            log("MQTT_DISCONNECT", peer=peer)
            return
        else:
            log("MQTT_OTHER", peer=peer, type=ptype, body=body.hex())


FILES = os.path.join(HERE, "files")   # files placed here are served by basename (S3 stand-in)


def serve_file(conn, peer, req_line, headers):
    """Serve files/<basename of path> if present. Returns True if served."""
    parts = req_line.split()
    if len(parts) < 2 or parts[0] not in ("GET", "HEAD"):
        return False
    name = os.path.basename(parts[1].split("?", 1)[0])
    path = os.path.join(FILES, name)
    if not name or not os.path.isfile(path):
        return False
    with open(path, "rb") as f:
        body = f.read()
    total, status, extra = len(body), b"200 OK", b""
    rng = headers.get("range", "")
    if rng.startswith("bytes="):
        a, _, b = rng[6:].split(",")[0].partition("-")
        start = int(a) if a else max(0, total - int(b))
        end = min(int(b), total - 1) if (a and b) else total - 1
        body = body[start:end + 1]
        status = b"206 Partial Content"
        extra = f"Content-Range: bytes {start}-{end}/{total}\r\n".encode()
    keep = headers.get("connection", "").lower() == "keep-alive"
    log("FILE_SERVED", peer=peer, file=name, bytes=len(body), total=total, range=rng or None)
    conn.sendall(b"HTTP/1.1 " + status + b"\r\nContent-Type: application/octet-stream\r\n"
                 + extra + b"Content-Length: " + str(len(body)).encode()
                 + (b"\r\nConnection: keep-alive" if keep else b"\r\nConnection: close")
                 + b"\r\n\r\n" + (b"" if parts[0] == "HEAD" else body))
    return keep


def handle_http(conn, peer, first):
    # Loop for keep-alive: after a served file the hub may issue more requests on this
    # connection, and we want every one of them in the log.
    data = bytes([first])
    while True:
        if not _handle_http_one(conn, peer, data):
            return
        conn.settimeout(15)
        try:
            data = conn.recv(4096)
        except (socket.timeout, OSError):
            return
        if not data:
            return
        log("HTTP_KEEPALIVE_NEXT", peer=peer)


def _handle_http_one(conn, peer, data):
    conn.settimeout(3)
    try:
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        clen = 0
        for line in head.split(b"\r\n")[1:]:
            k, _, v = line.partition(b":")
            if k.strip().lower() == b"content-length":
                clen = int(v.strip())
        while len(rest) < clen:
            rest += conn.recv(4096)
    except socket.timeout:
        head, rest = data, b""
    lines = head.split(b"\r\n")
    req_line = lines[0].decode(errors="replace")
    headers = {}
    for l in lines[1:]:
        k, _, v = l.partition(b":")
        headers[k.strip().lower().decode(errors="replace")] = v.strip().decode(errors="replace")
    host = headers.get("host", "")
    log("HTTP_REQUEST", peer=peer, request=req_line, host=host,
        head=head.decode(errors="replace"), **show(rest))
    if b"getcurrenttime" not in req_line.lower().encode():
        try:
            if os.path.isdir(FILES) and serve_file(conn, peer, req_line, headers):
                return True   # keep-alive: wait for the next request
        except Exception as e:
            log("FILE_SERVE_FAILED", peer=peer, error=repr(e))
    if b"getcurrenttime" in req_line.lower().encode():
        # Template in time.payload next to this script: {t} = epoch seconds, {ms} = epoch ms.
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "time.payload")
        tmpl = "{t}"
        if os.path.exists(path):
            with open(path) as f:
                tmpl = f.read().strip()
        now = time.time()
        reply = tmpl.replace("{t}", str(int(now))).replace("{ms}", str(int(now * 1000))).encode()
        log("TIME_REPLY", peer=peer, body=reply.decode())
        ctype = b"application/json" if reply[:1] in (b"{", b"[") else b"text/plain"
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: " + ctype + b"\r\nContent-Length: "
                     + str(len(reply)).encode() + b"\r\nConnection: close\r\n\r\n" + reply)
    else:
        # Anything else (e.g. an S3 firmware/config fetch): log the path, return 404 so the
        # hub treats it as "nothing here" and carries on without applying a bogus file.
        conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    return False


def serve(port, ctx):
    srv = socket.socket(socket.AF_INET)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(8)
    log("LISTENING", port=port)
    while True:
        raw, addr = srv.accept()
        threading.Thread(target=client, args=(raw, addr, port, ctx), daemon=True).start()


def client(raw, addr, port, ctx):
    peer = f"{addr[0]}:{port}"
    sni = {}
    log("TCP_CONNECT", peer=peer)
    raw.settimeout(30)
    try:
        ctx.sni_callback = lambda s, name, c: sni.__setitem__(id(s), name) or None
        conn = ctx.wrap_socket(raw, server_side=True)
    except ssl.SSLError as e:
        hint = ""
        if "unknown ca" in str(e).lower() or "bad certificate" in str(e).lower():
            hint = "Hub REJECTED our certificate -> it validates TLS; network route is closed."
        log("TLS_FAILED", peer=peer, error=str(e), hint=hint)
        raw.close(); return
    except Exception as e:
        log("TLS_FAILED", peer=peer, error=repr(e)); raw.close(); return
    log("TLS_OK", peer=peer, sni=next(iter(sni.values()), None), version=conn.version(),
        cipher=conn.cipher()[0], hint="Hub ACCEPTED our certificate!")
    conn.settimeout(None)
    try:
        first = read_exact(conn, 1)[0]
        if first >> 4 == 1:
            handle_mqtt(conn, peer, first)
        else:
            handle_http(conn, peer, first)
    except (ConnectionError, OSError) as e:
        log("CLOSED", peer=peer, reason=str(e))
    finally:
        try: conn.close()
        except Exception: pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ports", type=int, nargs="+", default=[8883])
    a = ap.parse_args()
    cert, key = make_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1   # old embedded TLS stacks
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    ctx.load_cert_chain(cert, key)
    for p in a.ports:
        threading.Thread(target=serve, args=(p, ctx), daemon=True).start()
    threading.Thread(target=watcher, daemon=True).start()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
