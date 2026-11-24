"""Server-side services: Pi-hole (v6 API), DNS checks, the port 443 -> 8883 redirect, the bundled services
started by the Docker Compose profiles, and self-tests.

Pi-hole: the two Roost cloud names are pointed at this server with dnsmasq lines
(Settings → All settings → Misc → misc.dnsmasq_lines: `address=/<name>/<server-ip>`), which also covers any
sub-names. Other lines are left alone.
"""
import json, os, random, re, shutil, socket, ssl, struct, subprocess, time, urllib.error, urllib.parse, urllib.request

HOSTS = ['us-central1-mqtt.clearblade.com', 'us-central1-roostprod.cloudfunctions.net']


class ServiceError(Exception):
    pass


SKIP_IF = ('lo', 'docker', 'br-', 'veth', 'tun', 'tap', 'wg', 'proton', 'pvpn', 'tailscale', 'zt', 'virbr', 'cni', 'flannel')


def interface_addresses():
    """IPv4 address and netmask of each real network interface (skips loopback, Docker, VPN)."""
    import fcntl
    out = []
    for _, name in socket.if_nameindex():
        if name.startswith(SKIP_IF): continue
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            req = struct.pack('256s', name[:15].encode())
            addr = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, req)[20:24])      # SIOCGIFADDR
            mask = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x891b, req)[20:24])      # SIOCGIFNETMASK
            out.append((name, addr, mask))
        except OSError: pass
        finally: s.close()
    return out


def lan_ip(near=None):
    """This server's LAN address: the one on the hub's subnet if known, else a private LAN address."""
    import ipaddress
    addrs = interface_addresses()
    if near:
        try:
            target = ipaddress.ip_address(near)
            for _, a, m in addrs:
                if target in ipaddress.ip_network(f'{a}/{m}', strict=False): return a
        except ValueError: pass
    private = [a for _, a, _ in addrs if ipaddress.ip_address(a).is_private and not ipaddress.ip_address(a).is_link_local]
    if private: return sorted(private, key=lambda a: (not a.startswith('192.168.'), a))[0]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.connect(('192.0.2.1', 9)); return s.getsockname()[0]          # no packet is sent
    except OSError: return '127.0.0.1'
    finally: s.close()


def server_ip(settings, near=None):
    return settings.get('serverIp') or lan_ip(near or settings.get('hubIp'))


# ---------------------------------------------------------------- DNS (one A query, no dependencies)
DNS_PORT = int(os.environ.get('OPENROOST_DNS_PORT', '53'))   # tests only: a non-root stand-in Pi-hole can't use 53

# Bundled services (docker compose --profile pihole / --profile mailrelay); set by compose.yaml
BUNDLED_PIHOLE_URL = os.environ.get('OPENROOST_BUNDLED_PIHOLE_URL', '')
BUNDLED_PIHOLE_DNS_PORT = int(os.environ.get('OPENROOST_BUNDLED_PIHOLE_DNS_PORT', '53') or 53)
BUNDLED_RELAY = os.environ.get('OPENROOST_BUNDLED_RELAY', '')          # host:port


def bundled_pihole_password():
    return os.environ.get('OPENROOST_BUNDLED_PIHOLE_PASSWORD', '')


def bundled():
    """Which bundled services are configured and answering."""
    out = {'pihole': {'configured': bool(BUNDLED_PIHOLE_URL), 'available': False, 'url': BUNDLED_PIHOLE_URL or None, 'dnsPort': BUNDLED_PIHOLE_DNS_PORT},
           'relay': {'configured': bool(BUNDLED_RELAY), 'available': False, 'address': BUNDLED_RELAY or None}}
    if BUNDLED_PIHOLE_URL and not bundled_pihole_password():
        out['pihole']['error'] = 'Set PIHOLE_PASSWORD in .env (the bundled Pi-hole and OpenRoost share it), then docker compose up -d'
    elif BUNDLED_PIHOLE_URL:
        try:
            with PiHole(BUNDLED_PIHOLE_URL, bundled_pihole_password()) as p: out['pihole'].update(available=True, version=p.version())
        except ServiceError as e: out['pihole']['error'] = str(e)
    if BUNDLED_RELAY:
        host, _, port = BUNDLED_RELAY.rpartition(':')
        try:
            with socket.create_connection((host, int(port)), 3) as c:
                c.settimeout(3); banner = c.recv(200).decode(errors='replace')
            out['relay'].update(available=banner.startswith('220'), banner=banner.strip()[:80])
        except (OSError, ValueError) as e: out['relay']['error'] = f'Relay not answering at {BUNDLED_RELAY}: {e}'
    return out


def dns_a(server, name, timeout=3, port=None):
    qid = random.randint(0, 0xFFFF)
    q = struct.pack('>HHHHHH', qid, 0x0100, 1, 0, 0, 0) + b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\0' + struct.pack('>HH', 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
    try:
        s.sendto(q, (server, port or DNS_PORT)); data, _ = s.recvfrom(2048)
    except OSError as e:
        raise ServiceError(f'No DNS answer from {server}: {e}') from None
    finally: s.close()
    rid, flags, qd, an = struct.unpack('>HHHH', data[:8])
    if rid != qid: raise ServiceError('Mismatched DNS reply')
    i = 12
    for _ in range(qd):
        while data[i]: i += 1 + data[i]
        i += 5
    out = []
    for _ in range(an):
        i = i + 2 if data[i] & 0xC0 == 0xC0 else _skip_name(data, i)
        typ, _cls, _ttl, ln = struct.unpack('>HHIH', data[i:i + 10]); i += 10
        if typ == 1 and ln == 4: out.append(socket.inet_ntoa(data[i:i + 4]))
        i += ln
    return out


def _skip_name(data, i):
    while data[i]:
        if data[i] & 0xC0 == 0xC0: return i + 2
        i += 1 + data[i]
    return i + 1


# ---------------------------------------------------------------- Pi-hole v6
class PiHole:
    def __init__(self, url, password):
        p = urllib.parse.urlsplit(url or '')
        if p.scheme not in ('http', 'https') or not p.netloc: raise ServiceError('Enter the address you open Pi-hole at, e.g. http://192.168.1.2/admin')
        self.base, self.host, self.password, self.sid = f'{p.scheme}://{p.netloc}/api', p.hostname, password, None

    def _req(self, method, path, body=None):
        h = {'Content-Type': 'application/json', 'User-Agent': 'OpenRoost360'}
        if self.sid: h['X-FTL-SID'] = self.sid
        req = urllib.request.Request(self.base + path, method=method, headers=h, data=json.dumps(body).encode() if body is not None else None)
        ctx = ssl.create_default_context()
        try:
            with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
                raw = r.read(); return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            msg = e.read()[:300].decode(errors='replace')
            if e.code == 401: raise ServiceError('Pi-hole refused the app password.') from None
            raise ServiceError(f'Pi-hole answered {e.code}: {msg}') from None
        except (urllib.error.URLError, OSError) as e:
            raise ServiceError(f'Couldn\'t reach Pi-hole at {self.base}: {getattr(e, "reason", e)}') from None

    def __enter__(self):
        r = self._req('POST', '/auth', {'password': self.password or ''})
        s = r.get('session') or {}
        if not s.get('valid'): raise ServiceError('Pi-hole refused the app password.')
        self.sid = s.get('sid'); return self

    def __exit__(self, *a):
        try: self._req('DELETE', '/auth')            # end the session; Pi-hole limits concurrent ones
        except ServiceError: pass

    def version(self):
        v = self._req('GET', '/info/version').get('version', {})
        return (v.get('core', {}).get('local', {}) or {}).get('version') or (v.get('ftl', {}).get('local', {}) or {}).get('version') or 'v6'

    def hosts(self):
        return self._req('GET', '/config/dns/hosts').get('config', {}).get('dns', {}).get('hosts', [])

    def add_host(self, ip, name):
        self._req('PUT', '/config/dns/hosts/' + urllib.parse.quote(f'{ip} {name}', safe=''))

    def remove_host(self, ip, name):
        self._req('DELETE', '/config/dns/hosts/' + urllib.parse.quote(f'{ip} {name}', safe=''))

    def dnsmasq_lines(self):
        return self._req('GET', '/config/misc/dnsmasq_lines').get('config', {}).get('misc', {}).get('dnsmasq_lines', [])

    def set_dnsmasq_lines(self, lines):
        self._req('PATCH', '/config', {'config': {'misc': {'dnsmasq_lines': lines}}})

    def restart_dns(self):
        try: self._req('POST', '/action/restartdns')
        except ServiceError: pass              # Pi-hole applies dnsmasq_lines changes by itself; this just makes it immediate

    def dns_ip(self):
        try: return socket.gethostbyname(self.host)
        except OSError: return self.host


def pihole_for(store, ph=None):
    ph = ph or store.get_settings().get('ph') or {}
    if ph.get('mode') == 'existing': return PiHole(ph.get('url'), store.get_secret('ph.pass'))
    if ph.get('mode') == 'bundled':
        if not BUNDLED_PIHOLE_URL: raise ServiceError('OpenRoost\'s own Pi-hole isn\'t running. Start it with: docker compose --profile pihole up -d')
        return PiHole(BUNDLED_PIHOLE_URL, bundled_pihole_password())
    raise ServiceError('No Pi-hole chosen yet')


def dns_target(store, ph=None):
    """(address, port) to ask when checking the redirect."""
    ph = ph or store.get_settings().get('ph') or {}
    if ph.get('mode') == 'bundled': return server_ip(store.get_settings()), BUNDLED_PIHOLE_DNS_PORT
    try: host = urllib.parse.urlsplit(ph.get('url') or '').hostname or ''
    except ValueError: host = ''
    try: return socket.gethostbyname(host), DNS_PORT
    except OSError: return host, DNS_PORT


def _ours(line):
    m = re.fullmatch(r'\s*address=/([^/]+)/([^/\s]*)\s*', line or '')
    return (m.group(1), m.group(2)) if m and m.group(1) in HOSTS else None


def pihole_test(url, password):
    with PiHole(url, password) as p:
        try: lines = p.dnsmasq_lines()
        except ServiceError: lines = []
        return {'version': p.version(), 'records': [l for l in lines if _ours(l)]}


BUNDLED_DNSMASQ_DIR = os.environ.get('OPENROOST_BUNDLED_DNSMASQ_DIR', '')
DNSMASQ_FILE = '99-openroost.conf'


def wanted_lines(store):
    ip = server_ip(store.get_settings())
    return [f'address=/{n}/{ip}' for n in HOSTS]


def manual_steps(store, ph=None):
    """Pi-hole only accepts misc.dnsmasq_lines from its config file, environment or CLI (not the API), so for a
    Pi-hole OpenRoost doesn't run, it hands over the exact lines and a command that keeps the existing ones."""
    want = wanted_lines(store); existing = []
    try:
        with pihole_for(store, ph) as p: existing = [l for l in p.dnsmasq_lines() if not _ours(l)]
    except ServiceError: pass
    merged = json.dumps(existing + want)
    return {'manual': True, 'lines': want, 'keep': existing,
            'docker': f"docker exec <pihole-container> pihole-FTL --config misc.dnsmasq_lines '{merged}' && docker exec <pihole-container> pihole reloaddns",
            'native': f"sudo pihole-FTL --config misc.dnsmasq_lines '{merged}' && sudo pihole reloaddns"}


def ensure_records(store, ph=None):
    """Point the two Roost cloud names at this server with dnsmasq address= lines.
    OpenRoost's own Pi-hole: written to its dnsmasq.d folder and DNS restarted. Another Pi-hole: exact steps."""
    ph = ph or store.get_settings().get('ph') or {}
    if ph.get('mode') != 'bundled': return manual_steps(store, ph)
    if not BUNDLED_DNSMASQ_DIR or not os.path.isdir(BUNDLED_DNSMASQ_DIR):
        raise ServiceError('OpenRoost\'s Pi-hole config folder isn\'t mounted (OPENROOST_BUNDLED_DNSMASQ_DIR)')
    want = wanted_lines(store); path = os.path.join(BUNDLED_DNSMASQ_DIR, DNSMASQ_FILE)
    body = '# Written by OpenRoost360: send the hub\'s Roost cloud lookups to this server\n' + '\n'.join(want) + '\n'
    old = open(path).read() if os.path.exists(path) else ''
    if old != body:
        tmp = path + '.tmp'
        with open(tmp, 'w') as f: f.write(body)
        os.chmod(tmp, 0o644); os.replace(tmp, path)                  # Pi-hole's FTL runs as its own user and must read it
    with pihole_for(store, ph) as p: p.restart_dns()
    ip, (dns_host, dns_port) = server_ip(store.get_settings()), dns_target(store, ph)
    for _ in range(30):                                          # Pi-hole's DNS restarts in a few seconds
        try:
            if all(ip in dns_a(dns_host, n, 1, dns_port) for n in HOSTS): break
        except ServiceError: pass
        time.sleep(0.5)
    return {'added': want if old != body else [], 'replaced': [], 'manual': False}


def remove_records(store, ph_or_url, password=None):
    cfg = ph_or_url if isinstance(ph_or_url, dict) else {'mode': 'existing', 'url': ph_or_url}
    if cfg.get('mode') == 'bundled' and BUNDLED_DNSMASQ_DIR:
        path = os.path.join(BUNDLED_DNSMASQ_DIR, DNSMASQ_FILE)
        if os.path.exists(path):
            os.remove(path)
            try:
                with pihole_for(store, cfg) as p: p.restart_dns()
            except ServiceError: pass
    # another Pi-hole: its lines are the owner's to remove (Pi-hole doesn't allow it over the API)


# ---------------------------------------------------------------- port 443 -> 8883 redirect for the hub
def nat_rule(hub_ip, port):
    return ['-t', 'nat', '{op}', 'PREROUTING', '-s', hub_ip, '-p', 'tcp', '--dport', '443', '-j', 'REDIRECT', '--to-ports', str(port)]


def nat_check(hub_ip, port):
    exe = shutil.which('iptables')
    if not exe: return 'unknown', 'iptables isn\'t installed here, so the rule can\'t be checked'
    args = [exe] + [a.replace('{op}', '-C') for a in nat_rule(hub_ip, port)]
    try: r = subprocess.run(args, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired) as e: return 'unknown', str(e)
    if r.returncode == 0: return 'ok', f'Hub {hub_ip}: port 443 → {port}'
    if 'Permission denied' in r.stderr or 'you must be root' in r.stderr: return 'unknown', 'OpenRoost needs the NET_ADMIN permission to check the rule'
    return 'fail', f'No redirect for hub {hub_ip}'


def nat_add(hub_ip, port):
    exe = shutil.which('iptables')
    if not exe: raise ServiceError('iptables isn\'t installed here')
    args = [exe] + [a.replace('{op}', '-I') for a in nat_rule(hub_ip, port)]
    args.insert(args.index('PREROUTING') + 1, '1')
    r = subprocess.run(args, capture_output=True, text=True, timeout=5)
    if r.returncode: raise ServiceError(r.stderr.strip() or 'iptables failed (needs NET_ADMIN)')


# ---------------------------------------------------------------- listener self-test
def time_selftest(port):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(('127.0.0.1', port), timeout=5) as raw, ctx.wrap_socket(raw, server_hostname=HOSTS[1]) as s:
        s.sendall(b'POST /getCurrentTime HTTP/1.1\r\nHost: ' + HOSTS[1].encode() + b'\r\nContent-Length: 0\r\n\r\n')
        data = b''
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            data += chunk
    body = data.split(b'\r\n\r\n', 1)[-1]
    t = json.loads(body).get('time', 0)
    if abs(t / 1000 - time.time()) > 5: raise ServiceError('Time reply is wrong')
    return t


# ---------------------------------------------------------------- the checks list
def checks(store, hub, listener_port):
    st = store.get_settings(); ip = server_ip(st); out = []

    def add(cid, title, status, detail, fix=None):
        out.append({'id': cid, 'title': title, 'status': status, 'detail': detail, 'fix': fix})

    lv = hub.listener_view()
    add('listener', 'Listener running', 'ok' if lv['listening'] else 'fail', f'Port {lv["port"]} on this server ({ip})' if lv['listening'] else 'The hub listener isn\'t running')
    try:
        time_selftest(listener_port); add('time', 'Time reply', 'ok', 'POST /getCurrentTime answers {"time": …} over TLS')
    except Exception as e:
        add('time', 'Time reply', 'fail', f'Self-test failed: {e}')
    ph = st.get('ph') or {}
    dns_server = dns_port = None
    if ph.get('mode') in ('existing', 'bundled'):
        title = 'Connected to your Pi-hole' if ph['mode'] == 'existing' else 'OpenRoost\'s own Pi-hole'
        try:
            with pihole_for(store) as p:
                add('pihole', title, 'ok', f'Pi-hole {p.version()} at {p.base[:-4]}')
            dns_server, dns_port = dns_target(store)
        except ServiceError as e:
            add('pihole', title, 'fail', str(e))
    else:
        add('pihole', 'Pi-hole', 'fail', 'No Pi-hole chosen yet')
    for name in HOSTS:
        if not dns_server: add('dns:' + name, f'DNS: {name}', 'unknown', 'Needs a working Pi-hole'); continue
        try:
            got = dns_a(dns_server, name, port=dns_port)
            if ip in got: add('dns:' + name, f'DNS: {name}', 'ok', f'→ {ip}')
            else: add('dns:' + name, f'DNS: {name}', 'fail', f'Resolves to {", ".join(got) or "nothing"}, not this server', 'dns')
        except ServiceError as e:
            add('dns:' + name, f'DNS: {name}', 'fail', str(e))
    hub_ip = (hub.claim() or {}).get('ip') or st.get('hubIp')
    if hub_ip:
        status, detail = nat_check(hub_ip, listener_port)
        add('nat', 'Port 443 → listener for the hub', status, detail, 'nat' if status == 'fail' else None)
    else:
        add('nat', 'Port 443 → listener for the hub', 'wait', 'Set once the hub is found')
    sess = hub.session
    add('session', 'Hub connected', 'ok' if sess else 'wait', f'{sess["id"]} at {sess["ip"]}' if sess else 'No hub connected right now')
    if os.environ.get('OPENROOST_IN_DOCKER') == '1':
        add('boot', 'Starts on boot', 'ok', 'Runs as a Docker service that restarts with the server; the port redirect is re-added on every start')
    else:
        add('boot', 'Starts on boot', 'unknown', 'Not running under Docker: start it at boot with the Docker Compose stack or a service manager')
    return out
