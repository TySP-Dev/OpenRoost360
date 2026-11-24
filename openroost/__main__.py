"""Run OpenRoost360.

    python3 -m openroost [--https-port 8443] [--port 8362] [--listener-port 8883] [--data ./data]
    python3 -m openroost restore backup.orb --data ./data        (server stopped)

HTTPS is on by default (own self-signed certificate, or OPENROOST_TLS_CERT / OPENROOST_TLS_KEY); the HTTP port only
redirects to it. OPENROOST_TLS=off serves plain HTTP (only behind a TLS-terminating reverse proxy listed in
OPENROOST_PROXY_IPS). Every option also has an environment variable (see README.md), which is how Docker sets them.
"""
import argparse, getpass, os, sys, threading, time

from . import __version__, services, tls
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

    def ensure_nat(ip):
        """Keep the hub's port 443 redirected to the listener (needs NET_ADMIN; the Docker stack grants it)."""
        if store.get_settings().get('manageNat', True) is False or not ip: return
        try:
            import ipaddress
            if ipaddress.ip_address(ip).is_loopback: return            # a hub is never on loopback (tests are)
        except ValueError: return
        def work():
            status, detail = services.nat_check(ip, a.listener_port)
            if status != 'fail': return
            try:
                services.nat_add(ip, a.listener_port); log(f'Port 443 -> {a.listener_port} redirect added for hub {ip}')
                store.add_event(time.time(), 'system', 'info', 'Port redirect added', f'Hub {ip}: 443 → {a.listener_port}')
            except services.ServiceError as e:
                log(f'Couldn\'t add the port redirect for {ip}: {e}')
        threading.Thread(target=work, daemon=True).start()
    hub.nat_hook = ensure_nat
    Listener(hub, a.data, a.listener_port, a.bind, log).start()
    log(f'Hub listener on {a.bind}:{a.listener_port} (TLS: MQTT + getCurrentTime)')
    claim = hub.claim()
    if claim and claim.get('ip'): ensure_nat(claim['ip'])

    if not store.setup_done():
        code = store.new_setup_code()
        path = os.path.join(a.data, 'SETUP-CODE.txt')
        with open(path, 'w') as f: f.write(code + '\n')
        os.chmod(path, 0o600)
        log(f'First-time setup code: {code}  (also in {path}; changes on every restart until setup is done)')

    def ticker():
        while True:
            time.sleep(60)
            try: hub.tick()
            except Exception as e: log(f'tick failed: {e!r}')
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
