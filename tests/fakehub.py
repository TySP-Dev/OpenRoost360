"""TEST TOOL ONLY: a stand-in SmartBase that talks to the OpenRoost listener exactly like the real hub
(TLS getCurrentTime, MQTT 3.1.1 connect/subscribe/publish, PROTOCOL.md message formats).
Not used by the app. Used by tests/test_hub.py and for trying the dashboard without hardware.

    python3 tests/fakehub.py --port 8883 scenario      # connect, report sensors, run a short alarm sequence
"""
import argparse, json, socket, ssl, sys, time

DEV = 'z0a1b2c3d4e5f'
CID = f'projects/roostprod/locations/us-central1/registries/baseregistry/devices/{DEV}'
DT = {'keypad': 2883353816, 'door': 588387123, 'motion': 2455340117, 'leak': 287458440, 'smoke': 1149772305}


def _ctx():
    c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
    return c


def get_time(port, host='127.0.0.1'):
    with socket.create_connection((host, port), 5) as raw, _ctx().wrap_socket(raw, server_hostname='us-central1-roostprod.cloudfunctions.net') as s:
        s.sendall(b'POST /getCurrentTime HTTP/1.1\r\nHost: us-central1-roostprod.cloudfunctions.net\r\nContent-Length: 0\r\n\r\n')
        data = b''
        while True:
            c = s.recv(4096)
            if not c: break
            data += c
    return json.loads(data.split(b'\r\n\r\n', 1)[1])['time']


def _len(n):
    out = b''
    while True:
        d, n = n % 128, n // 128; out += bytes([d | (0x80 if n else 0)])
        if not n: return out


def _s(b): return len(b).to_bytes(2, 'big') + b


class FakeHub:
    def __init__(self, port, host='127.0.0.1', client_id=CID):
        raw = socket.create_connection((host, port), 5)
        self.s = _ctx().wrap_socket(raw, server_hostname='us-central1-mqtt.clearblade.com')
        self.dev = client_id.rsplit('/', 1)[-1]; self.pid = 0
        var = _s(b'MQTT') + bytes([4, 0xC2]) + (60).to_bytes(2, 'big')
        payload = _s(client_id.encode()) + _s(b'unused') + _s(b'eyJhbGciOiJFUzI1NiJ9.e30.sig')
        self.s.sendall(bytes([0x10]) + _len(len(var + payload)) + var + payload)
        self.connack = self._read()

    def _read(self):
        b0 = self.s.recv(1)[0]; mult, n = 1, 0
        while True:
            d = self.s.recv(1)[0]; n += (d & 0x7F) * mult
            if not d & 0x80: break
            mult *= 128
        body = b''
        while len(body) < n: body += self.s.recv(n - len(body))
        return b0, body

    def subscribe(self):
        t1, t2 = f'/devices/{self.dev}/config'.encode(), f'/devices/{self.dev}/commands/#'.encode()
        body = (1).to_bytes(2, 'big') + _s(t1) + b'\x01' + _s(t2) + b'\x00'
        self.s.sendall(bytes([0x82]) + _len(len(body)) + body)
        suback = self._read(); config = self._read()
        return suback, config

    def publish(self, msg):
        self.pid += 1
        t = f'/devices/{self.dev}/events'.encode(); p = json.dumps(msg).encode()
        body = _s(t) + self.pid.to_bytes(2, 'big') + p
        self.s.sendall(bytes([0x32]) + _len(len(body)) + body)
        return self._read()                                    # PUBACK

    def ping(self):
        self.s.sendall(b'\xc0\x00'); return self._read()

    def close(self):
        try: self.s.sendall(b'\xe0\x00'); self.s.close()
        except OSError: pass


def status(as_=0, pw=1, **kw):
    m = {'ev': '2', 'as': as_, 'pw': pw, 'bat': 4087, 't': int(time.time()), 'co': 'w', 'ss': 'TestNet', 'wc': 6, 'rs': -54, 'cs': 99,
         'cl': [[int(time.time()), 21.6, 43]], 'bfw': 'xb.5.0.1', 'wfw': 'wiced', 'sfw': 'xs.4.5.0', 'cfw': 'BG95', 'hw': 'cm4', 'cv': '0.0.7', 'mo': 0, 'la': 0}
    m.update(kw); return m


def sensor(sid, kind, ev, **kw):
    dj = {'id': sid, 'dt': DT[kind], 'ev': ev, 'mac': f'aabbcc{sid:06x}', 'bat': 2940 if kind == 'keypad' else 900, 'rs': -60,
          'fw': 'xs.4.4.0', 'hw': '1.0', 'as': {'keypad': 7, 'leak': 7, 'door': 6, 'motion': 4, 'smoke': 7}[kind], 'pi': 0, 'tok': 'abcdefgh'}
    hub_as = kw.pop('hub_as', 0); dj.update(kw)
    return {'ev': '1', 'as': hub_as, 't': int(time.time()), 'dj': dj}


def scenario(port):
    print('time', get_time(port))
    h = FakeHub(port); print('connack', h.connack)
    print('subscribe', h.subscribe())
    h.publish(status())
    for sid, kind in [(1, 'keypad'), (2, 'door'), (3, 'door'), (5, 'motion'), (7, 'leak'), (8, 'smoke')]:
        h.publish(sensor(sid, kind, 0 if kind != 'door' else 15))
    h.publish(sensor(2, 'door', 14)); h.publish(sensor(2, 'door', 15))
    h.ping(); h.close(); print('done')


if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('--port', type=int, default=8883); ap.add_argument('cmd', nargs='?', default='scenario')
    a = ap.parse_args()
    if a.cmd == 'scenario': scenario(a.port)
