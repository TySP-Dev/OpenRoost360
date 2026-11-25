"""Which DNS server OpenRoost itself uses for its own lookups (Matrix, email, Authentik, ntfy, update check…).

Under Docker with host networking the container can't be given its own DNS server (Compose refuses `dns:` together
with `network_mode: host`), and copying the host's /etc/resolv.conf doesn't always work (a 127.0.0.53 stub, a VPN
resolver…). So OpenRoost resolves names itself:

    OPENROOST_DNS=192.168.1.2            one or more servers, comma-separated (host or host:port)
    OPENROOST_DNS=                       blank: OpenRoost's own Pi-hole when its Docker profile runs, else the system resolver
    OPENROOST_DNS=system                 always the system resolver (/etc/resolv.conf)

If the chosen server doesn't answer, the system resolver is tried, so a stopped Pi-hole never cuts OpenRoost off.
Only IPv4 (A records) is looked up this way; IP addresses and localhost never touch DNS.
"""
import ipaddress, os, socket, threading, time

_orig_getaddrinfo = socket.getaddrinfo
_servers, _cache, _lock = [], {}, threading.Lock()
_info = {'mode': 'system', 'servers': [], 'lastError': None, 'lastServer': None}
TTL = 120


def _parse(spec):
    out = []
    for part in (spec or '').split(','):
        part = part.strip()
        if not part: continue
        host, _, port = part.rpartition(':') if part.count(':') == 1 else (part, '', '')
        try: ipaddress.ip_address(host)
        except ValueError: continue                         # servers must be IP addresses (no chicken-and-egg)
        out.append((host, int(port) if port.isdigit() else 53))
    return out


def configure(spec=None, bundled_port=None, bundled_on=False):
    """Pick the servers once at start-up (see the module notes)."""
    spec = os.environ.get('OPENROOST_DNS', '') if spec is None else spec
    if spec.strip().lower() == 'system':
        servers, mode = [], 'system'
    elif spec.strip():
        servers, mode = _parse(spec), 'custom'
    elif bundled_on:
        servers, mode = [('127.0.0.1', int(bundled_port or 53))], 'bundled'
    else:
        servers, mode = [], 'system'
    _servers[:] = servers
    _info.update(mode=mode if servers else 'system', servers=[f'{h}:{p}' if p != 53 else h for h, p in servers])
    socket.getaddrinfo = _getaddrinfo if servers else _orig_getaddrinfo
    return info()


def info():
    return dict(_info)


def _lookup(name):
    from .services import dns_a, ServiceError               # services imports nothing from here: no cycle
    now = time.time()
    with _lock:
        hit = _cache.get(name)
        if hit and hit[0] > now: return hit[1]
    for host, port in _servers:
        try:
            ips = dns_a(host, name, 2, port)
        except (ServiceError, OSError, IndexError, ValueError) as e:
            _info['lastError'] = f'{host}: {e}'; continue
        if ips:
            _info.update(lastServer=host, lastError=None)
            with _lock: _cache[name] = (now + TTL, ips)
            return ips
    return None


def _getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    name = host.decode() if isinstance(host, bytes) else host
    if not name or family == socket.AF_INET6 or name == 'localhost' or name.endswith('.localhost'):
        return _orig_getaddrinfo(host, port, family, type, proto, flags)
    try:
        ipaddress.ip_address(name.strip('[]')); return _orig_getaddrinfo(host, port, family, type, proto, flags)
    except ValueError: pass
    ips = _lookup(name.rstrip('.').lower())
    if not ips: return _orig_getaddrinfo(host, port, family, type, proto, flags)   # fall back to the system resolver
    out = []
    for ip in ips:
        try: out.extend(_orig_getaddrinfo(ip, port, socket.AF_INET, type, proto, flags | socket.AI_NUMERICHOST))
        except socket.gaierror: pass
    return out or _orig_getaddrinfo(host, port, family, type, proto, flags)
