#!/usr/bin/env python3
"""Emergency countdown wiring, in-process with sending stubbed out (no mail server, homeserver or vodozemac needed):
when a countdown runs, when it can't and why, that the people on its list are still warned, and that silent duress
stays out of the household's history.

    python3 tests/test_countdown.py             # exit code 0 = all passed
"""
import os, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
from openroost.bus import Bus                     # noqa: E402
from openroost.notify import Notifier             # noqa: E402
from openroost.store import Store                 # noqa: E402

results = []


def check(name, ok, detail=''):
    results.append((name, bool(ok)))
    print(('  PASS ' if ok else '  FAIL ') + name + (f'  [{detail}]' if detail and not ok else ''))


def wait_for(fn, secs=4):
    end = time.time() + secs
    while time.time() < end:
        v = fn()
        if v: return v
        time.sleep(0.05)
    return fn()


class Sent(list):
    pass


def setup(settings):
    st = Store(tempfile.mkdtemp())
    st.save_settings(settings); st.set_secret('mxToken', 'tok')
    n = Notifier(st, lambda *a: None); n.attach(Bus()); n.sync.store = None          # no Matrix polling in tests
    sent = Sent()
    n.send_email = lambda s, rcpts, subj, text, html=None: sent.append(('email', tuple(rcpts), subj)) or 'ok'
    n.send_matrix_dm = lambda s, mx, text, report=False: sent.append(('dm', mx, text.split('\n')[0])) or '!dm'
    n.send_matrix = lambda s, title, detail=None, mention=False: sent.append(('room', title)) or 'ok'
    n.send_matrix_text = lambda s, text, room=None: sent.append(('room', text.split('\n')[0])) or '!room'
    return st, n, sent


BASE = {'siteName': 'Home', 'mail': {'mode': 'relay-existing', 'host': 'x', 'port': '25', 'from': 'a@example.com'}, 'smtpTo': 'house@example.com',
        'mxOn': True, 'mxHs': 'https://matrix.example.org', 'mxRoom': '!room:example.org', 'duressSilent': True,
        'routing': {'intrusion': [1, 0, 1, 0], 'duress': [1, 0, 1, 0]},
        'esc': {'intrusion': {'on': True, 'secs': 60}, 'duress': {'on': True, 'secs': 60}, 'fire': {'on': True, 'secs': 120}, 'room': True,
                'responders': [{'id': 1, 'name': 'Dee', 'email': 'dee@example.com', 'mx': '@dee:example.org'}, {'id': 2, 'name': 'Al', 'email': 'al@example.com'}]}}


def main():
    print('\n== No emergency contacts (what happened on the server)')
    st, n, sent = setup({**BASE, 'contacts': []})
    why = n.esc.blocker('intrusion', st.get_settings())
    check('the countdown says why it can\'t run', why and 'no emergency contact' in why and 'Alarms' in why, why)
    n.dispatch('intrusion', 'Intrusion alarm', 'Alarm sounding after Back Door opened.', 'crit')
    ev = wait_for(lambda: [e for e in st.events(20) if e['title'] == "Emergency countdown didn't run"])
    check('history says the countdown didn\'t run, and why', ev and 'no emergency contact' in ev[0]['detail'], st.events(20))
    wait_for(lambda: any(x[0] == 'dm' for x in sent))
    check('the people on the countdown list are still warned straight away', ('dm', '@dee:example.org', 'BREAK IN') in sent
          and any(x[0] == 'email' and x[1] == ('dee@example.com',) for x in sent) and any(x[0] == 'email' and x[1] == ('al@example.com',) for x in sent), sent)
    check('…and that\'s recorded', wait_for(lambda: any(e['title'] == 'Warned' for e in st.events(20))))
    check('no countdown was started', not n.esc.pending())

    print('\n== With an emergency contact ticked for Alarms')
    st, n, sent = setup({**BASE, 'contacts': [{'id': 9, 'name': 'Neighbour', 'email': 'nb@example.com', 'tiers': {'alarms': 1, 'distress': 1, 'info': 0}}]})
    check('the countdown can run', n.esc.blocker('intrusion', st.get_settings()) is None)
    n.dispatch('intrusion', 'Intrusion alarm', 'Alarm sounding.', 'crit')
    p = wait_for(lambda: n.esc.pending('intrusion'))
    check('an alarm starts a countdown', p and p[0]['secs'] == 60, p)
    wait_for(lambda: any(x[0] == 'email' and 'respond within' in x[2] for x in sent))
    check('the people on the list get the countdown with a way to cancel', any(x[0] == 'email' and x[1] == ('dee@example.com',) and 'respond within 60 seconds' in x[2] for x in sent)
          and ('dm', '@dee:example.org', 'BREAK IN') in sent, sent)
    time.sleep(0.5)
    check('the emergency contact isn\'t told while it counts down', not any(x[0] == 'email' and x[1] == ('nb@example.com',) for x in sent), sent)

    print('\n== Silent duress stays off the household\'s screens')
    st, n, sent = setup({**BASE, 'contacts': []})
    n.dispatch('duress', 'Hostage PIN used', 'Disarmed under duress.', 'crit')
    wait_for(lambda: any(e['title'] == 'Warned' for e in st.events(20)))
    evs = st.events(20)
    check('the skipped-countdown and warned entries are filed as duress (hidden from history when silent)',
          evs and all(e['kind'] == 'duress' for e in evs if e['title'] in ("Emergency countdown didn't run", 'Warned')) and any(e['title'] == 'Warned' for e in evs), evs)

    print('\n== Countdown never set up (nobody on its list)')
    st, n, sent = setup({**BASE, 'contacts': [], 'esc': {**BASE['esc'], 'responders': []}})
    n.dispatch('intrusion', 'Intrusion alarm', 'x', 'crit'); time.sleep(0.5)
    check('no "didn\'t run" note for a countdown nobody set up', not any(e['title'] == "Emergency countdown didn't run" for e in st.events(20)))

    print('\n== Countdown switched off')
    st, n, sent = setup({**BASE, 'contacts': [], 'esc': {**BASE['esc'], 'intrusion': {'on': False, 'secs': 60}}})
    n.dispatch('intrusion', 'Intrusion alarm', 'x', 'crit'); time.sleep(0.5)
    check('off means no "didn\'t run" note and no extra warning', not any(e['title'] == "Emergency countdown didn't run" for e in st.events(20)) and not any(x[0] == 'dm' for x in sent), sent)

    bad = [r for r in results if not r[1]]
    print(f'\n{len(results) - len(bad)}/{len(results)} passed')
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()
