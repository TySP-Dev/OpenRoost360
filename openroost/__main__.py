"""Run OpenRoost360.

    python3 -m openroost [--https-port 8443] [--port 8362] [--listener-port 8883] [--data ./data]
    python3 -m openroost restore backup.orb --data ./data        (server stopped)

HTTPS is on by default (own self-signed certificate, or OPENROOST_TLS_CERT / OPENROOST_TLS_KEY); the HTTP port only
redirects to it. OPENROOST_TLS=off serves plain HTTP (only behind a TLS-terminating reverse proxy listed in
OPENROOST_PROXY_IPS). Every option also has an environment variable (see README.md), which is how Docker sets them.
"""
import argparse, getpass, os, sys, threading, time

from . import __version__, resolver, services, tls
from .bus import Bus
from .hub import Hub
from .listener import Listener
from .notify import Notifier
from .store import Store
from .update import Updates
from .web import App

HERE = os.path.dirname(os.path.abspath(__file__))
env = os.environ.get


def log(msg):
    print(time.strftime('%Y-%m-%d %H:%M:%S'), msg, flush=True)


def run(a):
    os.umask(0o077)
    store = Store(a.data)
    bus = Bus()
    notifier = Notifier(store, log)
    hub = Hub(store, bus, notifier)
    notifier.attach(bus)

    resolver.configure(bundled_port=services.BUNDLED_PIHOLE_DNS_PORT, bundled_on=bool(services.BUNDLED_PIHOLE_URL and services.bundled_pihole_password()))
    r = resolver.info()
    log('DNS for OpenRoost\'s own lookups: ' + (', '.join(r['servers']) + ' (system resolver as fallback)' if r['servers'] else 'system resolver'))

    nat_lock = threading.Lock()

    def keep_nat(extra=None, why=''):
        """Keep the hub's port 443 redirected to the listener (needs NET_ADMIN; the Docker stack grants it). Runs at
        start-up, every minute, and whenever the hub's address is learned or changed, so a firewall reload, a reboot or
        a new DHCP lease never leaves the hub cut off."""
        if store.get_settings().get('manageNat', True) is False: return
        with nat_lock:
            for ip in services.hub_targets(store, hub) + ([extra] if extra else []):
                try:
                    import ipaddress
                    if ipaddress.ip_address(ip).is_loopback: continue           # a hub is never on loopback (tests are)
                except ValueError: continue
                try:
                    if services.nat_ensure(ip, a.listener_port) == 'added':
                        log(f'Port 443 -> {a.listener_port} redirect added for hub {ip}{" (" + why + ")" if why else ""}')
                        store.add_event(time.time(), 'system', 'info', 'Port redirect added', f'Hub {ip}: 443 → {a.listener_port}')
                except services.ServiceError as e:
                    if not nat_warned.get(ip): log(f'Couldn\'t add the port redirect for {ip}: {e}')
                    nat_warned[ip] = True
    nat_warned = {}

    def find_hub():
        """No hub connected and no address known? Look for it in Pi-hole's query log."""
        if hub.session or (hub.hub_view() or {}).get('online'): return
        if (store.get_settings().get('ph') or {}).get('mode') not in ('bundled', 'existing'): return
        ip = services.find_hub_in_pihole(store)
        if ip and ip not in services.hub_targets(store, hub):
            store.set_kv('hubSeen', {'ip': ip, 't': time.time()})
            log(f'Spotted the hub at {ip} in Pi-hole\'s query log')
            store.add_event(time.time(), 'system', 'info', 'Hub spotted in Pi-hole', f'{ip} looked up Roost\'s cloud')
            keep_nat(why='found in Pi-hole')

    hub.nat_hook = lambda ip: threading.Thread(target=keep_nat, args=(ip, 'hub address learned'), daemon=True).start()
    Listener(hub, a.data, a.listener_port, a.bind, log).start()
    log(f'Hub listener on {a.bind}:{a.listener_port} (TLS: MQTT + getCurrentTime)')
    threading.Thread(target=keep_nat, kwargs={'why': 'start-up'}, daemon=True).start()

    if not store.setup_done():
        code = store.new_setup_code()
        path = os.path.join(a.data, 'SETUP-CODE.txt')
        with open(path, 'w') as f: f.write(code + '\n')
        os.chmod(path, 0o600)
        log(f'First-time setup code: {code}  (also in {path}; changes on every restart until setup is done)')

    def ticker():
        n = 0
        while True:
            time.sleep(60); n += 1
            try: hub.tick()
            except Exception as e: log(f'tick failed: {e!r}')
            try: keep_nat()
            except Exception as e: log(f'port redirect check failed: {e!r}')
            if n % 2 == 1:
                try: find_hub()
                except Exception as e: log(f'hub search failed: {e!r}')
    threading.Thread(target=ticker, daemon=True, name='tick').start()
    updates = Updates(store, log).start()

    hosts = [h.strip().lower() for h in env('OPENROOST_HOSTS', '').split(',') if h.strip()]
    proxies = [h.strip() for h in env('OPENROOST_PROXY_IPS', '').split(',') if h.strip()]
    use_tls = env('OPENROOST_TLS', 'on').lower() not in ('off', '0', 'false', 'no')
    ctx = fp = None
    if use_tls:
        crt, key, own = tls.ensure_web_cert(a.data, hosts)
        ctx, fp = tls.server_context(crt, key), tls.fingerprint(crt)
    app = App(store, hub, notifier, a.web, a.listener_port, hosts, a.https_port if use_tls else None, proxies, fp, updates)
    app.keep_nat = lambda: threading.Thread(target=keep_nat, kwargs={'why': 'settings changed'}, daemon=True).start()
    app.find_hub = find_hub
    servers = []
    if use_tls:
        servers.append(app.serve(a.bind, a.https_port, ctx))
        log(f'OpenRoost360 {__version__} on https://{a.bind}:{a.https_port}/  (certificate SHA-256 {fp})')
        log(f'http://{a.bind}:{a.port}/ redirects to HTTPS' + (f' (plain HTTP allowed from proxies {", ".join(proxies)})' if proxies else ''))
    else:
        log(f'OpenRoost360 {__version__} on http://{a.bind}:{a.port}/  (TLS off: put a TLS reverse proxy in front and list it in OPENROOST_PROXY_IPS)')
    servers.append(app.serve(a.bind, a.port))
    log(f'Data: {os.path.realpath(a.data)}')
    for srv in servers[:-1]: threading.Thread(target=srv.serve_forever, daemon=True).start()
    try: servers[-1].serve_forever()
    except KeyboardInterrupt: pass


def main():
    ap = argparse.ArgumentParser(prog='openroost', description='OpenRoost360 server')
    ap.add_argument('--data', default=env('OPENROOST_DATA', os.path.join(os.getcwd(), 'data')))
    sub = ap.add_subparsers(dest='cmd')
    r = sub.add_parser('restore', help='restore an encrypted backup into --data (server must be stopped)')
    r.add_argument('file')
    ap.add_argument('--https-port', type=int, default=int(env('OPENROOST_HTTPS_PORT', '8443')))
    ap.add_argument('--port', type=int, default=int(env('OPENROOST_HTTP_PORT', '8362')))
    ap.add_argument('--listener-port', type=int, default=int(env('OPENROOST_LISTENER_PORT', '8883')))
    ap.add_argument('--bind', default=env('OPENROOST_BIND', '0.0.0.0'))
    ap.add_argument('--web', default=env('OPENROOST_WEB', os.path.join(os.path.dirname(HERE), 'web')))
    ap.add_argument('--version', action='version', version=f'OpenRoost360 {__version__}')
    a = ap.parse_args()
    if a.cmd == 'restore':
        from . import backup
        backup.restore(a.file, getpass.getpass('Backup passphrase: '), a.data)
        print(f'Restored into {a.data}. Start the server again.'); return
    run(a)


if __name__ == '__main__':
    main()
