#!/usr/bin/env python3
"""Hub behaviour tests: online status across reconnects, hand-added sensors, low batteries, the hub as a device,
upgrade safety (database copy, settings migration) and Matrix homeserver discovery. Uses tests/fakehub.py against a
throwaway server.

    python3 tests/test_hub.py             # exit code 0 = all passed
"""
import http.server, json, os, sqlite3, sys, threading, time

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
from test_security import Server, setup_body, OWNER_PW, check, results      # noqa: E402
import fakehub                                                              # noqa: E402


def login(s):
    hd = s.req('POST', '/api/v1/auth/login', {'username': 'tyowner', 'password': OWNER_PW})[3]
    return next(v for k, v in hd if k.lower() == 'set-cookie').split(';')[0].split('=', 1)[1]


def wait_for(fn, secs=5):
    end = time.time() + secs
    while time.time() < end:
        v = fn()
        if v: return v
        time.sleep(0.1)
    return fn()


def main():
    print('\n== Hub online status')
    s = Server()
    st, js = s.req('POST', '/api/v1/setup/complete', setup_body(s.code))[:2]
    check('setup completes', st == 200, (st, js))
    ck = login(s)
    hub = lambda: s.req('GET', '/api/v1/hub', cookie=ck)[1]
    a = fakehub.FakeHub(s.lport); a.subscribe(); a.publish(fakehub.status(pw=1))
    h = wait_for(lambda: hub()['online'] and hub())
    check('hub online after connecting', h and h['online'] and h['connected'], h)
    check('power and backup battery reported', h['power'] == 'mains' and h['backupBatteryMv'] == 4087, h)
    check('hub has a default name', h['name'] == 'SmartBase', h)

    b = fakehub.FakeHub(s.lport); b.subscribe()                # the hub reconnects before its old connection timed out
    def closed_by_server(conn):              # in its own thread: OpenSSL's error queue is per thread, and a failed
        out = []                             # read here mustn't leak into the next socket's read in this thread
        def probe():
            conn.s.settimeout(3)
            try: out.append(conn.s.recv(1) == b'')
            except (OSError, ValueError): out.append(True)
        t = threading.Thread(target=probe); t.start(); t.join(5)
        return bool(out and out[0])
    still = not closed_by_server(a)
    check('the old connection is closed when the hub reconnects', not still)
    time.sleep(0.5)
    h = hub()
    check('…and the hub stays online (the old connection closing doesn\'t mark it offline)', h['online'] and h['connected'], h)
    before = h['lastSeen']; time.sleep(1.1); b.ping()
    check('a keepalive ping counts as hearing from the hub', wait_for(lambda: (hub()['lastSeen'] or 0) > before), hub())

    print('\n== Hand-added sensors')
    st, js = s.req('POST', '/api/v1/sensors', {'id': 9, 'type': 'door', 'name': 'Back Door', 'room': 'Kitchen'}, cookie=ck)[:2]
    check('owner can add a sensor by slot and type', st == 200 and js['waiting'] and js['manual'] and js['type'] == 'door' and js['displayName'] == 'Back Door', (st, js))
    st, js = s.req('POST', '/api/v1/sensors', {'id': 9, 'type': 'door', 'name': 'Again'}, cookie=ck)[:2]
    check('the same slot can\'t be added twice', st == 409, (st, js))
    st, js = s.req('POST', '/api/v1/sensors', {'id': 'x', 'type': 'door', 'name': 'Bad'}, cookie=ck)[:2]
    check('a bad slot number is refused', st == 400, (st, js))
    st, js = s.req('GET', '/api/v1/pairing', cookie=ck)[:2]
    check('a waiting hand-added sensor isn\'t offered as newly found', all(f['id'] != 9 for f in js['found']), js)
    b.publish(fakehub.sensor(9, 'door', 14))
    v = wait_for(lambda: (lambda x: not x['waiting'] and x)(s.req('GET', '/api/v1/sensors/9', cookie=ck)[1]))
    check('when the hub reports the slot it fills in and keeps its name', v and v['state'] == 'open' and v['displayName'] == 'Back Door' and v['room'] == 'Kitchen', v)
    b.publish(fakehub.sensor(12, 'door', 0, dt=123456))
    st, js = s.req('PATCH', '/api/v1/sensors/12', {'type': 'motion'}, cookie=ck)[:2]
    check('an unrecognised device\'s type can be set by hand', st == 200 and js['type'] == 'motion', (st, js))
    st, js = s.req('PATCH', '/api/v1/sensors/9', {'type': 'motion'}, cookie=ck)[:2]
    check('…but not a type the hub reports itself', st == 409, (st, js))

    print('\n== Low batteries (35 % and below by default)')
    b.publish(fakehub.sensor(20, 'leak', 0, bat=740, cl=[[int(time.time()), 19.5, 48]]))      # (740-600)/4.1 = 34 %
    b.publish(fakehub.sensor(21, 'leak', 0, bat=760))                                        # 39 %
    v20, v21 = s.req('GET', '/api/v1/sensors/20', cookie=ck)[1], s.req('GET', '/api/v1/sensors/21', cookie=ck)[1]
    check('34 % counts as low', v20['battery']['pct'] == 34 and v20['battery']['low'], v20['battery'])
    check('39 % doesn\'t', v21['battery']['pct'] == 39 and not v21['battery']['low'], v21['battery'])
    check('leak sensors report humidity', v20['humidity'] == 48 and v20['temp'] == 19.5, v20)
    ov = s.req('GET', '/api/v1/overview', cookie=ck)[1]
    check('overview counts low batteries', ov['sensors']['lowBattery'] == 1, ov['sensors'])

    print('\n== Devices heard from but not tracked')
    s.req('DELETE', '/api/v1/sensors/21', cookie=ck)
    b.publish({'ev': '1', 'as': 0, 't': int(time.time()), 'dj': {'id': 'x7', 'dt': 999, 'ev': 0}})
    st, js = s.req('GET', '/api/v1/sensors/untracked', cookie=ck)[:2]
    ids = {str(d['id']): d for d in js['devices']} if st == 200 else {}
    check('a removed sensor shows with its ID and type', '21' in ids and ids['21']['type'] == 'leak' and ids['21']['removed'] and ids['21']['usable'], ids.get('21'))
    check('an ID OpenRoost can\'t use as a slot shows too, marked unusable', 'x7' in ids and not ids['x7']['usable'], ids.get('x7'))
    check('sensors in the list are not repeated there', '9' not in ids and '20' not in ids, list(ids))
    st, js = s.req('POST', '/api/v1/sensors', {'id': 21, 'type': 'leak', 'name': 'Basement'}, cookie=ck)[:2]
    check('a removed sensor can be added back from it', st == 200 and js['displayName'] == 'Basement', (st, js))
    check('…and then leaves the list', all(str(d['id']) != '21' for d in s.req('GET', '/api/v1/sensors/untracked', cookie=ck)[1]['devices']))

    print('\n== The hub as a device')
    st, js = s.req('PATCH', '/api/v1/hub', {'name': 'Front Hall Hub', 'location': 'Hall closet'}, cookie=ck)[:2]
    check('owner can rename the hub and set its location', st == 200 and js['name'] == 'Front Hall Hub' and js['location'] == 'Hall closet', (st, js))
    check('there is no way to delete the hub', s.req('DELETE', '/api/v1/hub', cookie=ck)[0] in (404, 405))
    b.close()

    print('\n== Updates keep everything')
    data = s.data; s.close(keep=True)
    db = sqlite3.connect(os.path.join(data, 'openroost.db'))
    db.execute("UPDATE meta SET value='0.1.0' WHERE key='version'")
    db.execute("DELETE FROM meta WHERE key='mig.lowbat35'")
    db.execute("UPDATE settings SET value='20' WHERE key='lowBat'")
    if not db.execute("SELECT 1 FROM settings WHERE key='lowBat'").fetchall():
        db.execute("INSERT INTO settings(key,value,updated) VALUES('lowBat','20',0)")
    db.commit(); db.close()
    s = Server(data=data)
    snaps = os.listdir(os.path.join(data, 'backups')) if os.path.isdir(os.path.join(data, 'backups')) else []
    check('a new version copies the database to data/backups first', any(f.endswith('.db') and '0.1.0' in f for f in snaps), snaps)
    check('…privately', all(oct(os.stat(os.path.join(data, 'backups', f)).st_mode & 0o777) == '0o600' for f in snaps))
    ck = login(s)
    st, js = s.req('GET', '/api/v1/settings', cookie=ck)[:2]
    check('the old 20 % low-battery default becomes 35 %', js['settings'].get('lowBat') == 35, js['settings'].get('lowBat'))
    sens = s.req('GET', '/api/v1/sensors', cookie=ck)[1]['sensors']
    check('sensors, names and rooms survive a restart on a new version', any(x['id'] == 9 and x['displayName'] == 'Back Door' and x['room'] == 'Kitchen' for x in sens), sens)
    check('hub name survives', s.req('GET', '/api/v1/hub', cookie=ck)[1]['name'] == 'Front Hall Hub')
    check('the list of devices heard from survives too', any(str(d['id']) == 'x7' for d in s.req('GET', '/api/v1/sensors/untracked', cookie=ck)[1]['devices']))
    s.close()

    print('\n== Matrix homeserver discovery')
    from openroost.notify import Notifier, NotifyError
    class HS(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            if self.path == '/.well-known/matrix/client' and self.server.delegate:
                body = json.dumps({'m.homeserver': {'base_url': self.server.delegate}}).encode()
            elif self.path == '/_matrix/client/versions' and not self.server.delegate:
                body = b'{"versions":["v1.11"]}'
            else:
                self.send_response(404); self.send_header('Content-Length', '0'); self.end_headers(); return
            self.send_response(200); self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
        def do_POST(self):
            self.send_response(301); self.send_header('Location', 'http://example.invalid/'); self.send_header('Content-Length', '0'); self.end_headers()
    real = http.server.HTTPServer(('127.0.0.1', 0), HS); real.delegate = None
    name = http.server.HTTPServer(('127.0.0.1', 0), HS); name.delegate = f'http://127.0.0.1:{real.server_port}'
    for srv in (real, name): threading.Thread(target=srv.serve_forever, daemon=True).start()
    got = Notifier.matrix_base(f'http://127.0.0.1:{name.server_port}/')
    check('the server name\'s .well-known leads to the real homeserver', got == f'http://127.0.0.1:{real.server_port}', got)
    check('a homeserver without .well-known is used as is', Notifier.matrix_base(f'http://127.0.0.1:{real.server_port}') == f'http://127.0.0.1:{real.server_port}')
    from openroost.notify import _http
    try: _http('POST', f'http://127.0.0.1:{real.server_port}/_matrix/client/v3/login', {}); red = 'no error'
    except NotifyError as e: red = str(e)
    check('a redirected POST is refused with a clear message (not silently turned into a GET)', 'redirects to' in red, red)

    print('\n== DNS for OpenRoost itself (OPENROOST_DNS)')
    import socket, struct
    from openroost import resolver
    dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); dns.bind(('127.0.0.1', 0))
    def answer():
        while True:
            q, addr = dns.recvfrom(512)
            end = q.index(b'\0', 12) + 5
            dns.sendto(q[:2] + b'\x81\x80' + q[4:6] + b'\x00\x01\x00\x00\x00\x00' + q[12:end] + b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + bytes([10, 1, 2, 3]), addr)
    threading.Thread(target=answer, daemon=True).start()
    info = resolver.configure(f'127.0.0.1:{dns.getsockname()[1]}')
    got = {a[4][0] for a in socket.getaddrinfo('matrix.example.test', 443, type=socket.SOCK_STREAM)}
    check('names resolve through the configured server', got == {'10.1.2.3'} and info['mode'] == 'custom', (got, info))
    check('IP addresses never touch DNS', {a[4][0] for a in socket.getaddrinfo('192.0.2.7', 80)} == {'192.0.2.7'})
    resolver.configure('127.0.0.1:9')                         # nothing answers there
    try: socket.getaddrinfo('localhost', 80); fell = True
    except OSError: fell = False
    check('if the configured server doesn\'t answer, the system resolver is used', fell)
    check('"system" turns it off', resolver.configure('system')['mode'] == 'system' and socket.getaddrinfo is resolver._orig_getaddrinfo)
    check('blank uses OpenRoost\'s own Pi-hole when it runs', resolver.configure('', bundled_port=5353, bundled_on=True)['servers'] == ['127.0.0.1:5353'])
    resolver.configure('system')

    bad = [r for r in results if not r[1]]
    print(f'\n{len(results) - len(bad)}/{len(results)} passed')
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()
