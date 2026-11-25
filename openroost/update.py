"""Update check: compares this build's version with the newest release tag on the project's git server.

Releases are git tags named vMAJOR.MINOR.PATCH (e.g. v0.2.0). The server checks twice a day (Settings → System →
Check for updates; on by default) and owners see "Update available" in the dashboard and in GET /api/v1/version.
It only asks the git server's public API for tag names: no data about this home is sent.

Environment: OPENROOST_UPDATE_URL (tags API), OPENROOST_UPDATE_TOKEN (if the repository is private).
"""
import json, os, re, threading, time, urllib.error, urllib.request

from . import __version__

REPO_WEB = os.environ.get('OPENROOST_REPO_URL', 'https://git.tysstech.com/TySS-Dev/OpenRoost360')
TAGS_URL = os.environ.get('OPENROOST_UPDATE_URL', 'https://git.tysstech.com/api/v1/repos/TySS-Dev/OpenRoost360/tags?limit=50')
BRANCH_URL = TAGS_URL.split('/tags')[0] + '/branches/main'
INTERVAL = 12 * 3600


def parse(v):
    m = re.fullmatch(r'v?(\d+)\.(\d+)\.(\d+)', (v or '').strip())
    return tuple(int(x) for x in m.groups()) if m else None


class Updates:
    def __init__(self, store, log=print):
        self.store, self.log, self.lock = store, log, threading.Lock()

    def build(self):
        return {'version': __version__, 'commit': os.environ.get('OPENROOST_BUILD', '') or None, 'docker': os.environ.get('OPENROOST_IN_DOCKER') == '1'}

    def status(self):
        s = self.store.kv('update') or {}
        latest, b = s.get('latest'), self.build()
        avail = bool(latest and parse(latest) and parse(__version__) and parse(latest) > parse(__version__))
        main = s.get('mainCommit') if not latest else None
        mine = (b['commit'] or '').strip()
        newer_main = bool(main and mine and mine != 'unknown' and not main.startswith(mine))
        return {**b, 'latest': latest, 'updateAvailable': avail or newer_main, 'mainCommit': main and main[:7], 'onMain': bool(main), 'note': s.get('note'),
                'checked': s.get('checked'), 'error': s.get('error'),
                'releaseUrl': f'{REPO_WEB}/releases/tag/{latest}' if latest else (f'{REPO_WEB}/commits/branch/main' if main else None),
                'enabled': self.store.get_settings().get('updates', True) is not False}

    def check(self):
        with self.lock:
            rec = {'checked': time.time()}
            try:
                req = urllib.request.Request(TAGS_URL, headers={'Accept': 'application/json', 'User-Agent': f'OpenRoost360/{__version__}'})
                tok = os.environ.get('OPENROOST_UPDATE_TOKEN')
                if tok: req.add_header('Authorization', 'token ' + tok)
                with urllib.request.urlopen(req, timeout=10) as r: tags = json.loads(r.read(512 * 1024))
                versions = [t.get('name') for t in tags if isinstance(t, dict) and parse(t.get('name'))]
                rec['latest'] = max(versions, key=parse) if versions else None
                if not versions:
                    # No release published yet: compare with the newest commit on main instead, so a server built from
                    # main still hears about new work. (Publishing a release: git tag v0.2.0 && git push origin v0.2.0)
                    rec['note'] = 'No releases have been published yet, so this compares with the newest commit on main.'
                    try:
                        req = urllib.request.Request(BRANCH_URL, headers={'Accept': 'application/json', 'User-Agent': f'OpenRoost360/{__version__}'})
                        if tok: req.add_header('Authorization', 'token ' + tok)
                        with urllib.request.urlopen(req, timeout=10) as r: br = json.loads(r.read(256 * 1024))
                        rec['mainCommit'] = ((br.get('commit') or {}).get('id') or '')[:40] or None
                    except (urllib.error.URLError, OSError, ValueError):
                        rec['error'] = 'Couldn\'t read the main branch from the git server'
            except urllib.error.HTTPError as e:
                rec['error'] = f'The git server answered {e.code}' + (' (private repository? set OPENROOST_UPDATE_TOKEN)' if e.code in (401, 403, 404) else '')
            except (urllib.error.URLError, OSError, ValueError) as e:
                rec['error'] = f'Couldn\'t reach the git server: {getattr(e, "reason", e)}'
            prev = self.store.kv('update') or {}
            if 'latest' not in rec and prev.get('latest'): rec['latest'] = prev['latest']     # keep the last good answer
            if prev.get('notified'): rec['notified'] = prev['notified']                         # don't announce the same update twice
            self.store.set_kv('update', rec)
            st = self.status()
            what = st['latest'] or st.get('mainCommit')
            if st['updateAvailable'] and prev.get('notified') != what:
                rec['notified'] = what; self.store.set_kv('update', rec)
                self.store.add_event(time.time(), 'system', 'info', f'Update available: {what}', f'This server runs {__version__}')
            return st

    def run(self):
        time.sleep(60)
        while True:
            if self.store.get_settings().get('updates', True) is not False:
                try: self.check()
                except Exception as e: self.log(f'update check failed: {e!r}')
            time.sleep(INTERVAL)

    def start(self):
        threading.Thread(target=self.run, daemon=True, name='updates').start()
        return self
