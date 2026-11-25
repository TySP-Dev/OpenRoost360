"""Emergency countdown: a break-in, fire alarm or distress (hostage) PIN first warns the household, who get a set time
to cancel before the emergency contacts are told.

1. The alarm starts a countdown (Settings -> Notifications -> Emergency countdown: on/off and seconds per alarm).
2. Right away, the people listed there get the countdown by email (with their own cancel link) and Matrix DM, and the
   household Matrix room gets it too if chosen:
       BREAK IN
       PLEASE RESPOND "N" WITHIN 60 SECONDS TO CANCEL THE EMERGENCY EMAIL / MATRIX MESSAGE
3. Cancelling: reply "N" in that room or DM (only people on the list count), open the email's link, or press Cancel
   in the app (members and owners).
4. Not cancelled in time: the emergency contacts get their usual alert, and the household is told it went out.

A countdown only runs when someone can cancel it (a listed person, or the room with a listed Matrix ID) and someone
would be told (a contact on that alarm's tier); otherwise alarms go out as before. Countdowns are saved, so a restart
sends anything overdue instead of dropping it. The alarm itself, household email/push/webhooks and repeats are
unchanged; only the contacts wait.
"""
import secrets, threading, time

from . import emails

KINDS = {'intrusion': ('BREAK IN', 60, 'alarms'), 'fire': ('FIRE ALARM', 120, 'distress'), 'duress': ('DISTRESS PIN USED', 60, 'distress')}
CANCEL_WORDS = ('n', 'no', '"n"', 'n.')
KEEP_FOR = 7 * 86400


def instruction(secs):
    return f'PLEASE RESPOND "N" WITHIN {secs} SECONDS TO CANCEL THE EMERGENCY EMAIL / MATRIX MESSAGE'


class Escalations:
    def __init__(self, store, notifier, bus=None, log=print):
        self.store, self.notifier, self.bus, self.log = store, notifier, bus, log
        self.lock, self._pruned = threading.RLock(), 0
        threading.Thread(target=self._tick, daemon=True, name='escalations').start()

    # ---- config
    def _cfg(self, st, kind):
        esc = st.get('esc') or {}; k = esc.get(kind) or {}
        return esc, bool(k.get('on', True)), int(k.get('secs') or KINDS[kind][1])

    def blocker(self, kind, st):
        """Why a countdown for this alarm won't run: None (it will), 'off', 'unset' (nobody on its list), or a sentence
        saying what's missing."""
        if kind not in KINDS: return 'off'
        esc, on, _ = self._cfg(st, kind)
        if not on: return 'off'
        resp = esc.get('responders') or []
        mx_ok = bool(st.get('mxOn') and st.get('mxHs') and self.store.get_secret('mxToken'))
        mail_ok = self.notifier._email_ready(st)
        can_cancel = (mail_ok and any(r.get('email') for r in resp)) or (mx_ok and any(r.get('mx') for r in resp))
        tier = KINDS[kind][2]
        someone_to_tell = any((c.get('tiers') or {}).get(tier) and (c.get('email') or c.get('mx')) for c in st.get('contacts') or [])
        if not resp: return 'unset'                                 # never set up: alarms go out as usual, no note needed
        if not can_cancel: return 'nobody under "Who is warned and can cancel" can be reached (email or Matrix isn\'t set up)'
        if not someone_to_tell:
            return f'no emergency contact has "{ {"alarms": "Alarms", "distress": "Distress"}[tier] }" ticked (Family & emergency contacts), so there\'s nobody to tell at the end'
        return None

    def applies(self, kind, st):
        return self.blocker(kind, st) is None

    def warn_responders(self, kind, title, detail):
        """No countdown is running: the people on the cancel list still hear about the alarm, right away (once each, and
        not twice if they're already a household email recipient)."""
        st = self.store.get_settings(); esc = st.get('esc') or {}
        site = st.get('siteName') or 'Home'
        mx_ok = bool(st.get('mxOn') and st.get('mxHs') and self.store.get_secret('mxToken'))
        household = {a.lower() for a in self.notifier._email_list(st)}
        errors, told = [], []
        for r in esc.get('responders') or []:
            ok = []
            if r.get('email') and r['email'].lower() not in household and self.notifier._email_ready(st):
                t, html = emails.alert(site, kind, title, detail, 'crit', time.strftime('%A %d %B, %H:%M'), (st.get('publicUrl') or '').rstrip('/') or None,
                                       'You are receiving this notice because you are labeled as someone to warn about alarms in OpenRoost360.')
                try: self.notifier.send_email(st, [r['email']], f'[{site}] {title}', t, html); ok.append('email')
                except Exception as e: errors.append(f"email to {r['email']}: {e}")
            if r.get('mx') and mx_ok:
                try: self.notifier.send_matrix_dm(st, r['mx'], f'{KINDS[kind][0]}\n{title}: {detail} · {site}'); ok.append('Matrix')
                except Exception as e: errors.append(f"Matrix DM to {r['mx']}: {e}")
            if ok: told.append(f"{r.get('name') or r.get('email') or r.get('mx')} ({', '.join(ok)})")
        if errors: self._problem('Alarm warning: some messages failed', '; '.join(errors), kind)
        return told

    # ---- records
    def _all(self):
        return [v for _, v in self.store.kv_prefix('esc:')]

    def _save(self, rec):
        self.store.set_kv('esc:' + rec['id'], rec)
        if self.bus: self.bus.publish('escalation', self.view(rec))

    def get(self, eid):
        return self.store.kv('esc:' + eid)

    def pending(self, kind=None):
        return [r for r in self._all() if r['state'] == 'pending' and (kind is None or r['kind'] == kind)]

    @staticmethod
    def view(rec):
        return {k: rec.get(k) for k in ('id', 'kind', 'label', 'title', 'detail', 'start', 'deadline', 'secs', 'state', 'by', 'via', 'at', 'silent', 'told')}

    def recent(self, hours=24):
        cut = time.time() - hours * 3600
        return sorted((self.view(r) for r in self._all() if r['start'] > cut), key=lambda r: -r['start'])

    def contacts_allowed(self, kind):
        """Repeats and the first alert reach contacts only if no countdown for this alarm is pending or was cancelled."""
        recent = [r for r in self._all() if r['kind'] == kind and r['start'] > time.time() - 6 * 3600]
        if not recent: return True
        return max(recent, key=lambda r: r['start'])['state'] == 'sent'

    # ---- start
    def start(self, kind, title, detail, sev):
        st = self.store.get_settings()
        with self.lock:
            if self.pending(kind): return None
            esc, _, secs = self._cfg(st, kind)
            now = time.time()
            rec = {'id': secrets.token_hex(6), 'kind': kind, 'label': KINDS[kind][0], 'title': title, 'detail': detail, 'sev': sev,
                   'start': now, 'deadline': now + secs, 'secs': secs, 'state': 'pending', 'by': None, 'via': None, 'at': None,
                   'silent': kind == 'duress' and st.get('duressSilent', True), 'rooms': [], 'emails': [],
                   'mx': sorted({r['mx'] for r in esc.get('responders') or [] if r.get('mx')})}
            self._save(rec)
        threading.Thread(target=self._announce, args=(rec['id'],), daemon=True).start()
        return rec['id']

    def _announce(self, eid):
        rec = self.get(eid); st = self.store.get_settings(); esc = st.get('esc') or {}
        site = st.get('siteName') or 'Home'; base = (st.get('publicUrl') or '').rstrip('/')
        until = time.strftime('%H:%M:%S', time.localtime(rec['deadline']))
        text = f"{rec['label']}\n{instruction(rec['secs'])}\n{rec['detail']} · {site} · cancel by {until}"
        errors, rooms, mailed = [], [], []
        mx_ok = bool(st.get('mxOn') and st.get('mxHs') and self.store.get_secret('mxToken'))
        if mx_ok and esc.get('room', True) and st.get('mxRoom'):
            try: rooms.append(self.notifier.send_matrix_text(st, ('@room ' if st.get('mxMention', True) else '') + text))
            except Exception as e: errors.append(f'Matrix room: {e}')
        for r in esc.get('responders') or []:
            if r.get('mx') and mx_ok:
                try: rooms.append(self.notifier.send_matrix_dm(st, r['mx'], text))
                except Exception as e: errors.append(f"Matrix DM to {r['mx']}: {e}")
            if r.get('email') and self.notifier._email_ready(st):
                tok = secrets.token_urlsafe(32)
                self.store.set_kv('esctok:' + self.store.keys.token_hash(tok), {'eid': eid, 'name': r.get('name') or r['email'], 'exp': rec['deadline'] + 86400})
                link = f'{base}/?cancel={tok}' if base else None
                t, html = emails.countdown(site, rec['label'], rec['detail'], rec['secs'], until, link)
                try: self.notifier.send_email(st, [r['email']], f"[{site}] {rec['label']}: respond within {rec['secs']} seconds", t, html); mailed.append(r['email'])
                except Exception as e: errors.append(f"email to {r['email']}: {e}")
        with self.lock:
            cur = self.get(eid); cur['rooms'] = [x for x in rooms if x]; cur['emails'] = mailed; self.store.set_kv('esc:' + eid, cur)
        if errors: self._problem('Emergency countdown: some messages failed', '; '.join(errors), rec['kind'])

    # ---- cancel
    def cancel(self, eid, by, via):
        with self.lock:
            rec = self.get(eid)
            if not rec: return None
            if rec['state'] != 'pending': return rec
            if time.time() > rec['deadline'] + 2: return rec          # the tick is about to send it
            rec.update(state='cancelled', by=by, via=via, at=time.time()); self._save(rec)
        self.store.add_event(time.time(), 'duress' if rec['kind'] == 'duress' else 'system', 'info', f"Emergency messages cancelled: {rec['label'].title()}", f'By {by} ({via}). Emergency contacts were not told.')
        threading.Thread(target=self._confirm, args=(rec, f"CANCELLED: {rec['label']}\nCancelled by {by} ({via}). Emergency contacts were not told."), daemon=True).start()
        return rec

    def by_token(self, tok):
        if not isinstance(tok, str) or not 30 <= len(tok) <= 64: return None, None
        t = self.store.kv('esctok:' + self.store.keys.token_hash(tok))
        if not t or t['exp'] < time.time(): return None, None
        return self.get(t['eid']), t['name']

    def on_matrix(self, room, sender, body, ts):
        if body.strip().lower() not in CANCEL_WORDS: return
        for rec in self.pending():
            if room in rec.get('rooms', []) and sender in rec.get('mx', []) and ts >= rec['start'] - 5:
                self.cancel(rec['id'], sender, 'Matrix')

    # ---- deadline
    def _tick(self):
        first = True
        while True:
            time.sleep(0 if first else 1)
            try:
                now = time.time()
                for rec in self.pending():
                    if rec['deadline'] <= now: self._send(rec, late=first and now - rec['deadline'] > 5)
                if now - self._pruned > 3600: self._pruned = now; self._prune()
            except Exception as e:
                self.log(f'escalations: {e!r}')
            first = False

    def _send(self, rec, late=False):
        with self.lock:
            cur = self.get(rec['id'])
            if not cur or cur['state'] != 'pending': return
            cur.update(state='sent', at=time.time()); self._save(cur)
        told, errors = self.notifier.send_contacts(cur['kind'], cur['title'], cur['detail'], cur.get('sev', 'crit'))
        note = ' (the server restarted during the countdown)' if late else ''
        who = '; '.join(f"{n} ({' + '.join(ch)})" for n, ch in told) or 'nobody could be reached'
        with self.lock:
            cur = self.get(rec['id']); cur.update(told=[n for n, _ in told], failed=errors); self._save(cur)
        self.store.add_event(time.time(), 'duress' if cur['kind'] == 'duress' else 'system', 'crit', f"Emergency contacts told: {cur['label'].title()}", f"No one cancelled within {cur['secs']} seconds{note}. Told: {who}.")
        text = (f"EMERGENCY MESSAGES SENT: {cur['label']}\nNo one cancelled within {cur['secs']} seconds{note}.\nTold: {who}."
                + (f"\nCouldn't reach: {'; '.join(errors)}" if errors else ''))
        self._confirm(cur, text)
        if errors: self._problem('Emergency messages: some failed', '; '.join(errors), cur['kind'])

    def _confirm(self, rec, text):
        st = self.store.get_settings()
        for room in rec.get('rooms') or []:
            try: self.notifier.send_matrix_text(st, text, room)
            except Exception as e: self.log(f'escalations: confirmation to {room} failed: {e}')
        if rec.get('emails') and self.notifier._email_ready(st):
            site = st.get('siteName') or 'Home'; title, body = text.split('\n', 1); body = body.replace('\n', ' ')
            t, html = emails.countdown_result(site, title, body, rec['state'] == 'cancelled')
            try: self.notifier.send_email(st, rec['emails'], f'[{site}] {title}', t, html)
            except Exception as e: self.log(f'escalations: confirmation email failed: {e}')

    def _problem(self, title, detail, kind=None):
        self.log(f'escalations: {title}: {detail}')
        self.store.add_event(time.time(), 'duress' if kind == 'duress' else 'system', 'warn', title, detail[:400])   # silent duress stays hidden

    def _prune(self):
        cut = time.time() - KEEP_FOR
        for k, v in self.store.kv_prefix('esc:'):
            if v['start'] < cut: self.store.del_kv(k)
        for k, v in self.store.kv_prefix('esctok:'):
            if v['exp'] < time.time(): self.store.del_kv(k)
