"""TEST TOOL ONLY: a stand-in Pi-hole v6 with the API calls OpenRoost uses, plus a DNS responder that answers
A queries from its Local DNS records. Not used by the app.

    python3 tests/fakepihole.py --http 8399 --dns 8353 --password app-pass
"""
import argparse, json, socket, struct, threading, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOSTS, SIDS, LINES = [], set(), []


def run(http_port, dns_port, password):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def reply(self, code, obj=None):
            b = json.dumps(obj or {}).encode(); self.send_response(code); self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
        def authed(self): return self.headers.get('X-FTL-SID') in SIDS
        def do_POST(self):
            n = int(self.headers.get('Content-Length') or 0); body = json.loads(self.rfile.read(n) or b'{}')
            if self.path == '/api/action/restartdns': return self.reply(200 if self.authed() else 401, {'status': 'ok'})
            if self.path == '/api/auth':
                if body.get('password') == password: sid = f'sid{len(SIDS) + 1}'; SIDS.add(sid); return self.reply(200, {'session': {'valid': True, 'sid': sid}})
                return self.reply(401, {'error': {'key': 'unauthorized'}})
            self.reply(404)
        def do_DELETE(self):
            if self.path == '/api/auth': SIDS.discard(self.headers.get('X-FTL-SID')); return self.reply(204)
            if not self.authed(): return self.reply(401)
            if self.path.startswith('/api/config/dns/hosts/'):
                e = urllib.parse.unquote(self.path.rsplit('/', 1)[1])
                if e in HOSTS: HOSTS.remove(e)
                return self.reply(204)
            self.reply(404)
        def do_PUT(self):
            if not self.authed(): return self.reply(401)
            if self.path.startswith('/api/config/dns/hosts/'):
                e = urllib.parse.unquote(self.path.rsplit('/', 1)[1])
                if e not in HOSTS: HOSTS.append(e)
                return self.reply(201)
            self.reply(404)
        def do_PATCH(self):
            if not self.authed(): return self.reply(401)
            n = int(self.headers.get('Content-Length') or 0); body = json.loads(self.rfile.read(n) or b'{}')
            if self.path == '/api/config':
                lines = body.get('config', {}).get('misc', {}).get('dnsmasq_lines')
                if lines is not None: LINES[:] = lines
                return self.reply(200, {'config': {}})
            self.reply(404)
        def do_GET(self):
            if not self.authed(): return self.reply(401)
            if self.path == '/api/config/misc/dnsmasq_lines': return self.reply(200, {'config': {'misc': {'dnsmasq_lines': LINES}}})
            if self.path == '/api/info/version': return self.reply(200, {'version': {'core': {'local': {'version': 'v6.1.4'}}}})
            if self.path == '/api/config/dns/hosts': return self.reply(200, {'config': {'dns': {'hosts': HOSTS}}})
            self.reply(404)

    def dns():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.1', dns_port))
        while True:
            q, addr = s.recvfrom(512)
            i, labels = 12, []
            while q[i]: labels.append(q[i + 1:i + 1 + q[i]].decode()); i += 1 + q[i]
            name, qend = '.'.join(labels), i + 5
            ips = [h.split()[0] for h in HOSTS if h.split()[-1] == name]
            for l in LINES:                                   # address=/<domain>/<ip> also matches sub-names
                parts = l.strip().split('/')
                if len(parts) == 3 and parts[0] == 'address=' and (name == parts[1] or name.endswith('.' + parts[1])) and parts[2]: ips.append(parts[2])
            ans = b''.join(b'\xc0\x0c' + struct.pack('>HHIH', 1, 1, 60, 4) + socket.inet_aton(ip) for ip in ips)
            s.sendto(q[:2] + b'\x81\x80' + q[4:6] + struct.pack('>HHH', len(ips), 0, 0) + q[12:qend] + ans, addr)
    threading.Thread(target=dns, daemon=True).start()
    ThreadingHTTPServer(('127.0.0.1', http_port), H).serve_forever()


if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('--lines', nargs='*', default=[], help='pre-existing dnsmasq lines'); ap.add_argument('--http', type=int, default=8399); ap.add_argument('--dns', type=int, default=8353); ap.add_argument('--password', default='app-pass')
    a = ap.parse_args(); LINES.extend(a.lines); run(a.http, a.dns, a.password)
