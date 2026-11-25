"""Hub state engine: turns what the listener receives from the SmartBase into hub status, sensors,
arm state, alerts and history. Every rule here comes from docs/PROTOCOL.md.

Inputs (called by openroost.listener): on_time_request, on_connect, on_subscribe, on_publish,
on_disconnect. Outputs: the store (persisted), the bus (live updates) and the notifier.
"""
import json, threading, time

DT = {2883353816: 'keypad', 588387123: 'door', 2455340117: 'motion', 287458440: 'leak', 1149772305: 'smoke'}
TYPE_LABEL = {'keypad': 'Keypad', 'door': 'Entry sensor', 'motion': 'Motion sensor', 'leak': 'Water leak / temp',
              'smoke': 'Smoke listener', 'unknown': 'Sensor'}
AS_MODE = {0: 'off', 2: 'home', 8: 'arming', 4: 'away'}
AS_LABEL = {0: 'Disarmed', 2: 'Armed Home', 8: 'Arming Away', 4: 'Armed Away'}
DA_LABEL = {'ow': 'owner PIN', 'gu': 'guest PIN', 'ho': 'hostage PIN'}
STATE_LABEL = {'open': 'Open', 'closed': 'Closed', 'motion': 'Motion', 'clear': 'Clear', 'wet': 'Wet', 'dry': 'Dry', 'ok': 'OK'}
URGENT = ('intrusion', 'fire', 'panic', 'duress', 'leak')
DEFAULT_EXIT, DEFAULT_ENTRY = 60, 45          # seen on a real hub (docs/PROTOCOL.md "Example alarm sequence")
DEFAULT_LOWBAT = 35                           # % at or below which a battery counts as low
ONLINE_GRACE = 150                            # s: the hub pings every 60 s, so this long without a word means it's gone
KIND_DT = {v: k for k, v in DT.items()}
MANUAL_TYPES = ('door', 'motion', 'leak', 'smoke', 'keypad', 'unknown')


def bat_pct(kind, raw):
    if raw is None: return None
    p = (raw - 2400) / 6 if kind == 'keypad' else (raw - 600) / 4.1
    return max(0, min(100, round(p)))


def infer_kind(dj):
    """Work out a sensor's type from what it reports, for a device code that isn't in DT (docs/PROTOCOL.md: door
    14/15, motion 17/18, panic 12 from a keypad, a climate reading from the water/temperature sensor, xe firmware on
    the smoke listener). None when nothing tells yet: a routine check-in (event 0) says nothing."""
    try: code = int(dj.get('ev'))
    except (TypeError, ValueError): code = None
    if code in (14, 15): return 'door'
    if code in (17, 18): return 'motion'
    if code == 12: return 'keypad'
    if isinstance(dj.get('cl'), list) and dj['cl']: return 'leak'
    if str(dj.get('fw') or '').startswith('xe.'): return 'smoke'
    return None


def low_limit(settings):
    try: return int(settings.get('lowBat') or DEFAULT_LOWBAT)
    except (TypeError, ValueError): return DEFAULT_LOWBAT


def bars(rs):
    if rs is None: return 0
    return 4 if rs > -55 else 3 if rs > -65 else 2 if rs > -75 else 1


def device_id(client_id):
    return (client_id or '').rsplit('/', 1)[-1][:40]


class Hub:
    def __init__(self, store, bus, notifier=None):
        self.store, self.bus, self.notifier = store, bus, notifier
        self.lock = threading.RLock()
        self.status = store.kv('hub', {})                 # last status fields from the hub
        self.arm = store.kv('arm', {'as': None, 'since': None, 'countdown': None, 'lastDisarm': None})
        self.sensors = store.sensors_all()                # id -> live data from dj reports
        self.alerts = {a['kind']: a for a in store.alerts_all()}
        self.session = None                               # live MQTT session info
        self._seen_saved = 0                              # last time lastSeen was written for a ping (limits disk writes)
        self._online = None                               # last online state published (tick() notices a hub going quiet)
        self.listener = {'listening': False, 'port': None, 'lastTime': None, 'lastConnect': None, 'rejected': None}
        self.pairing = store.kv('pairing', {'until': 0, 'since': 0})
        self.seen = store.kv('seenDevices', None)         # every device ID the hub has reported, tracked or not
        if self.seen is None: self.seen = self._backfill_seen()
        self.flags = store.kv('flags', {})                # notification de-duplication (missing, low battery, climate…)
        self.last_trip = None                             # last door/motion trip, used as the alarm's likely cause
        self.publish_hook = None                          # listener sets this: publish(topic, payload) to the hub
        self.nat_hook = None                              # keeps the port 443 -> listener redirect for the hub's address
        self.wire = None                                  # the listener's protocol log (set by the listener)

    # ------------------------------------------------------------- helpers
    def settings(self):
        return self.store.get_settings()

    def meta(self):
        return self.settings().get('sensorMeta', {})

    def claim(self):
        return self.store.kv('claim')

    def _event(self, kind, sev, title, detail='', sensor=None, raw=None, t=None):
        t = t or time.time()
        eid = self.store.add_event(t, kind, sev, title, detail, sensor, raw)
        ev = {'id': eid, 't': t, 'kind': kind, 'sev': sev, 'title': title, 'detail': detail, 'sensor': sensor}
        if not self._hidden(ev): self.bus.publish('event', ev)
        return ev

    def _hidden(self, ev):
        return ev['kind'] == 'duress' and self.settings().get('duressSilent', True)

    def _notify(self, kind, title, detail, sev='info'):
        if self.notifier: self.notifier.dispatch(kind, title, detail, sev)

    def _alert(self, kind, title, detail):
        silent = kind == 'duress' and self.settings().get('duressSilent', True)
        a = {'kind': kind, 'title': title, 'detail': detail, 'since': time.time(), 'active': True, 'silent': silent}
        self.alerts[kind] = a; self.store.save_alert(kind, a)
        self.bus.publish('alert', a)   # silent duress is tagged so the stream hides it from everyone but owners

    def _end_alert(self, kind):
        a = self.alerts.get(kind)
        if a and a.get('active'):
            a['active'] = False; a['ended'] = time.time(); self.store.save_alert(kind, a); self.bus.publish('alert', a)

    def _save_hub(self):
        self.store.set_kv('hub', self.status); self.bus.publish('hub', self.hub_view())

    def _save_arm(self):
        self.store.set_kv('arm', self.arm); self.bus.publish('arm', self.arm_view())

    def _set_flag(self, key, value):
        self.flags[key] = value; self.store.set_kv('flags', self.flags)

    # ------------------------------------------------------------- listener inputs
    def on_listening(self, port):
        self.listener.update(listening=True, port=port); self.bus.publish('listener', {'listening': True, 'port': port})

    def on_time_request(self, peer):
        self.listener['lastTime'] = {'t': time.time(), 'peer': peer}
        self.bus.publish('listener', {'step': 'time', 'peer': peer})

    def on_activity(self, token=None):
        """Any packet from the live session (pings included) means the hub is there."""
        with self.lock:
            if token is not None and (not self.session or self.session.get('token') != token): return
            now = time.time(); self.status['lastSeen'] = now
            if now - self._seen_saved > 30 or self._online is False:
                self._seen_saved = now; self._save_hub()

    def accept_client(self, client_id, peer_ip):
        """Only the claimed hub may connect once one is claimed (stops another device faking events)."""
        dev, claim = device_id(client_id), self.claim()
        if not dev.startswith('z'): return False
        if claim and claim.get('id') != dev:
            self.listener['rejected'] = {'t': time.time(), 'id': dev, 'ip': peer_ip}
            self._event('system', 'warn', 'Unknown hub refused', f'{dev} from {peer_ip} is not the claimed hub')
            return False
        return True

    def claim_hub(self, dev, ip=None):
        self.store.set_kv('claim', {'id': dev, 'ip': ip, 't': time.time()})
        self._event('system', 'info', 'Hub claimed', dev)
        if self.nat_hook and ip: self.nat_hook(ip)

    def on_connect(self, client_id, peer_ip, token=None):
        dev = device_id(client_id)
        with self.lock:
            self.session = {'id': dev, 'ip': peer_ip, 'since': time.time(), 'subscribed': [], 'configSent': False, 'token': token}
            self.status.update(id=dev, ip=peer_ip, lastSeen=time.time())
            self.listener['lastConnect'] = {'t': time.time(), 'id': dev, 'ip': peer_ip}
            if self.claim() and self.claim().get('ip') != peer_ip:
                c = self.claim(); c['ip'] = peer_ip; self.store.set_kv('claim', c)
                if self.nat_hook: self.nat_hook(peer_ip)
            was_offline = self.flags.get('offline')
            self._save_hub()
        self.bus.publish('listener', {'step': 'connect', 'id': dev, 'ip': peer_ip})
        if was_offline:
            self._set_flag('offline', False)
            self._event('system', 'info', 'Hub reconnected', f'{dev} at {peer_ip}')
            self._notify('offline', 'Hub back online', f'The SmartBase reconnected from {peer_ip}.')

    def on_subscribe(self, topics, config_sent, token=None):
        if self.session and (token is None or self.session.get('token') == token):
            self.session['subscribed'] = topics; self.session['configSent'] = config_sent
        self.bus.publish('listener', {'step': 'subscribe', 'topics': topics, 'configSent': config_sent})

    def on_disconnect(self, reason='', token=None):
        """A connection ended. Only the current session counts: the hub often opens a new connection before the old
        one has timed out, and that old one closing must not mark the hub offline."""
        with self.lock:
            if token is not None and (not self.session or self.session.get('token') != token): return
            if self.session: self.status['lastSeen'] = time.time()
            self.session = None
            self._save_hub()

    def on_publish(self, topic, payload):
        try: msg = json.loads(payload.decode())
        except (ValueError, UnicodeDecodeError): return
        if not isinstance(msg, dict): return
        with self.lock:
            self._record_seen(msg)
            self._handle(msg)

    def _backfill_seen(self):
        """First start with this feature: rebuild the list from the sensors table and the raw hub messages kept with
        past events."""
        seen = {}
        for sid, x in self.sensors.items():
            if x.get('lastSeen'):
                seen[str(sid)] = {'id': str(sid), 'first': x.get('firstSeen') or x['lastSeen'], 'last': x['lastSeen'], 'count': 1,
                                  **{k: x[k] for k in ('dt', 'mac') if x.get(k) is not None}, **({'fw': x['fw']} if x.get('fw') else {})}
        for (t, raw) in self.store.q("SELECT t, raw FROM events WHERE raw LIKE '%\"dj\"%' ORDER BY id DESC LIMIT 5000"):
            try: dj = json.loads(raw).get('dj')
            except (ValueError, AttributeError): continue
            if not isinstance(dj, dict) or dj.get('id') is None or isinstance(dj['id'], (dict, list)): continue
            key = str(dj['id'])[:20]
            e = seen.setdefault(key, {'id': key, 'first': t, 'last': t, 'count': 0})
            e['first'], e['last'], e['count'] = min(e['first'], t), max(e['last'], t), e['count'] + 1
            for k in ('dt', 'mac', 'fw'):
                if dj.get(k) is not None and k not in e: e[k] = dj[k]
        self.store.set_kv('seenDevices', seen)
        return seen

    def _record_seen(self, msg):
        """Remember each device ID the hub reports (with its type code), whatever happens to the message next, so the
        owner can see devices that talk to the server but aren't in the sensor list."""
        djs = msg.get('dj'); djs = [djs] if isinstance(djs, dict) else [d for d in djs if isinstance(d, dict)] if isinstance(djs, list) else []
        now = time.time()
        for dj in djs:
            raw = dj.get('id')
            if raw is None or isinstance(raw, (dict, list)): continue
            key = str(raw)[:20]
            e = self.seen.get(key) or {'id': key, 'first': now, 'count': 0}
            e.update(last=now, count=e['count'] + 1)
            for k in ('dt', 'mac', 'fw'):
                if dj.get(k) is not None: e[k] = dj[k] if not isinstance(dj[k], str) else dj[k][:40]
            if dj.get('ev') is not None: e['ev'] = dj['ev']
            self.seen[key] = e
        if djs:
            if len(self.seen) > 300:                              # keep the newest
                self.seen = dict(sorted(self.seen.items(), key=lambda kv: -kv[1]['last'])[:300])
            self.store.set_kv('seenDevices', self.seen)

    def untracked_view(self):
        """Devices the hub has reported that aren't in the sensor list (removed, or with an ID OpenRoost couldn't use)."""
        out = []
        for key, e in self.seen.items():
            try: sid = int(key)
            except ValueError: sid = None
            s = self.sensors.get(sid) if sid is not None else None
            if s and s.get('lastSeen') and not self.meta().get(str(sid), {}).get('removed'): continue
            kind = DT.get(e.get('dt'), 'unknown')
            out.append({'id': sid if sid is not None else key, 'usable': sid is not None and 1 <= sid <= 999999, 'type': kind,
                        'typeLabel': TYPE_LABEL.get(kind, 'Device'), 'dt': e.get('dt'), 'mac': e.get('mac'), 'firmware': e.get('fw'),
                        'firstSeen': e['first'], 'lastSeen': e['last'], 'reports': e['count'],
                        'removed': bool(s and self.meta().get(str(sid), {}).get('removed'))})
        return sorted(out, key=lambda x: -x['lastSeen'])

    # ------------------------------------------------------------- message handling (docs/PROTOCOL.md)
    def _handle(self, m):
        now = time.time()
        ev = str(m.get('ev', ''))
        self.status['lastSeen'] = now
        for k in ('pw', 'bat', 'co', 'ss', 'wc', 'rs', 'cs', 'bfw', 'wfw', 'sfw', 'cfw', 'hw', 'cv'):
            if k in m: self.status[k] = m[k]
        if isinstance(m.get('cl'), list) and m['cl'] and isinstance(m['cl'][-1], list) and len(m['cl'][-1]) >= 3:
            _, tc, hum = m['cl'][-1][:3]; self.status['temp'], self.status['hum'] = tc, hum
            self._climate('hub', 'Hub', tc, hum)
        if 'pw' in m and self.status.get('_pw') is not None and m['pw'] != self.status.get('_pw'):
            on = bool(m['pw'])
            self._event('power', 'info' if on else 'warn', 'Mains power restored' if on else 'Hub on battery', '' if on else 'Events are only sent when it reconnects')
        if 'pw' in m: self.status['_pw'] = m['pw']
        if ev == '2': self.status['lastStatus'] = now
        # fire: hub flag, sent with ev 0, regardless of arm state
        if 'fr' in m:
            fire = bool(m['fr']); was = bool(self.status.get('fr'))
            self.status['fr'] = int(fire)
            if fire and not was:
                self._event('fire', 'crit', 'Smoke alarm', 'The smoke listener hears an alarm', raw=m)
                self._alert('fire', 'Fire alarm', 'The smoke listener hears a smoke alarm.')
                self._notify('fire', 'Fire alarm', 'The smoke listener hears a smoke alarm.', 'crit')
            elif was and not fire:
                self._event('fire', 'info', 'Smoke alarm stopped', raw=m); self._end_alert('fire')
        # arm state
        if 'as' in m: self._arm(m, now)
        if isinstance(m.get('dj'), dict): self._sensor(m['dj'], m, now)
        if ev == '4':
            cause = ''
            if self.last_trip and now - self.last_trip[0] < 180: cause = self.last_trip[1]
            self.arm['countdown'] = None; self._save_arm()
            self._event('alarm', 'crit', 'Intrusion alarm', cause and f'After {cause}', raw=m)
            self._alert('intrusion', 'Intrusion alarm', f'Alarm sounding{" after " + cause if cause else ""}.')
            self._notify('intrusion', 'Intrusion alarm', f'The alarm is sounding{" after " + cause if cause else ""}.', 'crit')
        self._save_hub()

    def _arm(self, m, now):
        a = m['as']
        try: a = int(a)
        except (TypeError, ValueError): return
        prev = self.arm.get('as')
        if a == prev and 'da' not in m: return
        st = self.settings()
        self.arm.update({'as': a, 'since': now})
        if a == 8:
            self.arm['countdown'] = {'kind': 'exit', 'ends': now + int(st.get('exitDelay') or DEFAULT_EXIT)}
        elif a in (2, 4) or a == 0:
            self.arm['countdown'] = None
        if a == 0:
            src = m.get('da')
            self.arm['lastDisarm'] = {'source': src, 't': now}
            silent = st.get('duressSilent', True)
            shown = 'keypad' if (src == 'ho' and silent) else DA_LABEL.get(src, 'keypad')
            self._event('disarm', 'info', 'Disarmed', f'At the keypad · {shown}' if src else 'Disarmed', raw=m)
            self._end_alert('intrusion')
            if src == 'ho':
                self._event('duress', 'crit', 'Hostage PIN used', 'Disarmed under duress', raw=m)
                self._alert('duress', 'Hostage PIN used', 'Someone disarmed with the hostage PIN.')
                self._notify('duress', 'Hostage PIN used', 'The alarm was disarmed with the hostage (duress) PIN. Check on the household.', 'crit')
            elif prev not in (None, 0):
                self._notify('armchange', 'Disarmed', f'Disarmed with the {shown}.')
        elif prev != a:
            self._event('arm', 'info', AS_LABEL.get(a, f'Arm state {a}'), 'Exit delay running' if a == 8 else '', raw=m)
            if a != 8: self._notify('armchange', AS_LABEL.get(a, 'Armed'), 'Armed at the keypad.')
        self._save_arm()

    def _sensor(self, dj, m, now):
        try: sid = int(dj.get('id'))
        except (TypeError, ValueError): return
        meta = self.meta().get(str(sid), {})
        s = self.sensors.get(sid) or {'id': sid, 'firstSeen': now, 'state': None}
        is_new = sid not in self.sensors
        if meta.get('removed'):                                  # a removed sensor reported again: offer it for set-up
            self._forget_removed(sid); is_new = True
        kind, how = self._kind(dj, s)
        if how == 'inferred' and not s.get('inferred'):
            s['inferred'] = True
            if not is_new: self._event('pair', 'info', f'{self._name(sid, {**s, "type": kind})}: type worked out', f'{TYPE_LABEL[kind]}, from what it reports', sid, m)
        elif how != 'inferred': s.pop('inferred', None)
        is_new = is_new or (s.get('manual') and not s.get('lastSeen'))
        s.update(type=kind, lastSeen=now)
        for k in ('dt', 'mac', 'bat', 'rs', 'fw', 'hw', 'as'):
            if k in dj: s[k] = dj[k]
        if isinstance(dj.get('cl'), list) and dj['cl'] and isinstance(dj['cl'][-1], list) and len(dj['cl'][-1]) >= 3:
            s['temp'], s['hum'] = dj['cl'][-1][1], dj['cl'][-1][2]
            self._climate(f's{sid}', self._name(sid, s), s['temp'], s['hum'])
        code = dj.get('ev')
        try: code = int(code)
        except (TypeError, ValueError): code = None
        name = self._name(sid, s)
        title = None
        # When it happened: the sensor's own time (dj.t). On battery the hub keeps events and sends them once it's back
        # on power, minutes later, so the arrival time would be wrong.
        at, late = self._when(dj, now)
        lnote = f' · happened at {self._clock(at)}, sent late' if late else ''
        if kind == 'door' and code in (14, 15):
            s['state'] = 'open' if code == 14 else 'closed'; title = f'{name} {"opened" if code == 14 else "closed"}'
            if code == 14:
                self.last_trip = (at, f'{name} opened')
                if self.arm.get('as') in (2, 4) and not self.arm.get('countdown') and not late:
                    self.arm['countdown'] = {'kind': 'entry', 'ends': now + int(self.settings().get('entryDelay') or DEFAULT_ENTRY)}; self._save_arm()
        elif kind == 'motion' and code in (17, 18):
            s['state'] = 'motion' if code == 17 else 'clear'
            if code == 17: title = f'Motion: {name}'; self.last_trip = (at, f'motion at {name}')
        elif kind == 'leak' and code in (0, 1):
            wet = code == 1; was = s.get('state') == 'wet'; s['state'] = 'wet' if wet else 'dry'
            if wet and not was:
                self._event('leak', 'crit', 'Water leak', name + lnote, sid, m, at)
                self._alert('leak', 'Water leak', f'{name} detects water.{lnote and " (" + lnote[3:] + ")"}')
                self._notify('leak', 'Water leak', f'{name} detects water.{lnote and " (" + lnote[3:] + ")"}', 'crit')
            elif was and not wet:
                self._event('leak', 'info', 'Leak cleared', f'{name} is dry again{lnote}', sid, m, at); self._end_alert('leak')
        elif kind == 'keypad':
            s['state'] = 'ok'
            if code == 12:
                self._event('panic', 'crit', 'Panic button', f'{name}: X + OK held{lnote}', sid, m, at)
                self._alert('panic', 'Panic button pressed', f'Someone held X + OK on {name}.{lnote and " (" + lnote[3:] + ")"}')
                self._notify('panic', 'Panic button pressed', f'Someone held X + OK on {name}.{lnote and " (" + lnote[3:] + ")"}', 'crit')
        elif kind == 'smoke':
            s['state'] = 'ok'
        if s.get('state') is None: s['state'] = {'door': 'closed', 'motion': 'clear', 'leak': 'dry'}.get(kind, 'ok')
        if title: self._event('sensor', 'info', title, (meta.get('room', '') + lnote).lstrip(' ·'), sid, m, at)
        elif code == 0 and kind != 'leak': pass                 # routine check-in: no history entry
        if is_new and s.get('manual'):
            self._event('pair', 'info', f'{name} reported in', f'Added manually; the hub reports it in slot {sid}', sid, m)
        elif is_new:
            self._event('pair', 'info', 'New sensor found', f'{TYPE_LABEL.get(kind, "Device")} in slot {sid}'
                        + (' (type worked out from what it reports)' if how == 'inferred' else ' (type not known yet)' if kind == 'unknown' else ''), sid, m)
        self._battery(sid, s, name)
        if self.flags.get(f'missing:{sid}'):
            self._set_flag(f'missing:{sid}', False); self._event('system', 'info', f'{name} is back', '', sid)
        self.sensors[sid] = s; self.store.save_sensor(sid, s)
        self.bus.publish('sensor', self.sensor_view(sid))

    @staticmethod
    def type_editable(s):
        """The owner may say what a sensor is while the hub hasn't reported it, or when the hub's device code isn't known."""
        return not s.get('lastSeen') or s.get('dt') not in DT

    def add_manual(self, sid, kind):
        """A sensor the owner adds by hand (its slot ID and type), e.g. one that's paired with the hub but hasn't
        reported since OpenRoost started. It shows as "waiting" until the hub reports that slot."""
        with self.lock:
            s = self.sensors.get(sid)
            if s and not self.meta().get(str(sid), {}).get('removed'): raise ValueError(f'Slot {sid} is already in use')
            now = time.time()
            s = s or {'id': sid, 'firstSeen': now, 'state': None, 'lastSeen': None}
            s.update(manual=True)
            if not s.get('lastSeen') or s.get('type') in (None, 'unknown'): s.update(type=kind, dt=KIND_DT.get(kind))
            self.sensors[sid] = s; self.store.save_sensor(sid, s)
        return s

    def _kind(self, dj, s):
        """(type, how): 'hub' when the device code is in OpenRoost's table, 'owner' when the owner set it, 'inferred' when
        worked out from what the sensor reports, 'unknown' otherwise. A device code worked out once is remembered, so
        other sensors of the same model are recognised straight away."""
        dt = dj.get('dt', s.get('dt'))
        if dt in DT: return DT[dt], 'hub'
        if s.get('manual') and s.get('type') in MANUAL_TYPES and s['type'] != 'unknown': return s['type'], 'owner'
        learned = (self.store.kv('learnedDt') or {}).get(str(dt)) if dt is not None else None
        if learned in DT.values(): return learned, 'inferred'
        kind = infer_kind(dj) or (s.get('type') if s.get('inferred') else None)
        if kind:
            if dt is not None:
                ld = dict(self.store.kv('learnedDt') or {}); ld[str(dt)] = kind; self.store.set_kv('learnedDt', ld)
            return kind, 'inferred'
        return 'unknown', 'unknown'

    @staticmethod
    def _when(dj, now):
        """(time it happened, sent late?) from the sensor's own clock, if it's believable (not 0, not ahead, < 7 days)."""
        try: t = float(dj.get('t') or 0)
        except (TypeError, ValueError): t = 0
        if not (now - 7 * 86400 < t <= now + 60): return now, False
        return min(t, now), now - t > 60

    def _clock(self, t):
        try:
            from zoneinfo import ZoneInfo
            d = __import__('datetime').datetime.fromtimestamp(t, ZoneInfo(self.settings().get('tz') or 'UTC'))
        except Exception:
            d = __import__('datetime').datetime.fromtimestamp(t)
        return d.strftime('%H:%M' if self.settings().get('timeFmt') == '24' else '%I:%M %p').lstrip('0')

    def _forget_removed(self, sid):
        st = self.settings(); m = dict(st.get('sensorMeta', {}))
        m.pop(str(sid), None)
        self.store.save_settings({'sensorMeta': m}, merge=False)

    def _name(self, sid, s=None):
        m = self.meta().get(str(sid), {})
        if m.get('name'): return m['name']
        s = s or self.sensors.get(sid, {})
        return f"{TYPE_LABEL.get(s.get('type'), 'Sensor')} {sid}"

    def _battery(self, sid, s, name):
        """Low battery: a history entry when a sensor first drops to the limit, a notification (if on), and a reminder
        every few days while it stays low (Settings → Notifications → Low batteries). The flag holds when it last notified."""
        pct = bat_pct(s.get('type'), s.get('bat'))
        if pct is None: return
        st = self.settings(); low = low_limit(st)
        key = f'lowbat:{sid}'
        if pct <= low and not self.flags.get(key):
            self._event('system', 'warn', 'Low battery', f'{name} · about {pct}%', sid)
            if st.get('lowBatNotify', True) is not False:
                self._notify('lowbat', 'Low battery', f'{name} is at about {pct}%. Replace its battery soon.')
            self._set_flag(key, time.time())
        elif pct > low + 5 and self.flags.get(key):
            self._set_flag(key, False)

    def _battery_reminders(self, now):
        st = self.settings()
        if st.get('lowBatNotify', True) is False: return
        try: days = float(st.get('lowBatRemindDays', 7) or 0)
        except (TypeError, ValueError): days = 7
        if days <= 0: return
        low = low_limit(st)
        for sid, s in self.sensors.items():
            last = self.flags.get(f'lowbat:{sid}')
            if not last or self.meta().get(str(sid), {}).get('removed'): continue
            if last is True: self._set_flag(f'lowbat:{sid}', now); continue          # flag from before reminders existed
            pct = bat_pct(s.get('type'), s.get('bat'))
            if pct is not None and pct <= low and now - last >= days * 86400:
                self._set_flag(f'lowbat:{sid}', now)
                self._notify('lowbat', 'Battery still low', f'{self._name(sid, s)} is at about {pct}%. Replace its battery soon.')

    def _climate(self, key, where, tc, hum):
        st = self.settings()
        if tc is None: return
        unit = st.get('tempUnit', 'F'); t = tc * 9 / 5 + 32 if unit == 'F' else tc
        checks = []
        if st.get('tempAlert') and st.get('tl') is not None and st.get('th') is not None:
            checks.append(('temp', t < st['tl'] or t > st['th'], f'{round(t)}°{unit}'))
        if st.get('humAlert') and hum is not None and st.get('hl') is not None and st.get('hh') is not None:
            checks.append(('hum', hum < st['hl'] or hum > st['hh'], f'{round(hum)}% humidity'))
        for what, out, txt in checks:
            fk = f'climate:{key}:{what}'
            if out and not self.flags.get(fk):
                self._set_flag(fk, True)
                self._event('climate', 'warn', 'Temperature out of range' if what == 'temp' else 'Humidity out of range', f'{where} · {txt}')
                self._notify('climate', 'Climate alert', f'{where}: {txt}, outside your set range.')
            elif not out and self.flags.get(fk):
                self._set_flag(fk, False)

    # ------------------------------------------------------------- periodic checks (every minute)
    def tick(self):
        now = time.time(); st = self.settings()
        with self.lock:
            # countdowns end on their own
            cd = self.arm.get('countdown')
            if cd and cd['ends'] < now - 5: self.arm['countdown'] = None; self._save_arm()
            # hub offline (on battery the hub disconnects on purpose; don't alarm for that)
            last = self.status.get('lastSeen')
            online = self.is_online(now)
            if online != self._online: self._online = online; self.bus.publish('hub', self.hub_view())   # gone quiet / back
            limit = int(st.get('offlineMin') or 10) * 60
            if not self.session and last and now - last > limit and self.status.get('pw', 1) == 1 and not self.flags.get('offline'):
                self._set_flag('offline', True)
                self._event('system', 'warn', 'Hub offline', f'No connection for {limit // 60} minutes')
                self._notify('offline', 'Hub offline', f'The SmartBase hasn\'t connected for {limit // 60} minutes. Check its power and Wi-Fi.')
            # sensors that stopped checking in
            hours = int(st.get('sensorMissingH') or 24)
            for sid, s in self.sensors.items():
                if self.meta().get(str(sid), {}).get('removed'): continue
                if now - (s.get('lastSeen') or now) > hours * 3600 and not self.flags.get(f'missing:{sid}'):
                    self._set_flag(f'missing:{sid}', True)
                    name = self._name(sid, s)
                    self._event('system', 'warn', f'{name} is missing', f'No check-in for over {hours} h', sid)
                    self._notify('missing', 'Sensor missing', f'{name} hasn\'t checked in for over {hours} hours. Try a fresh battery.')
                    self.bus.publish('sensor', self.sensor_view(sid))
        with self.lock: self._battery_reminders(now)
        days = int(st.get('retention') or 90)
        self.store.prune_events(days)

    # ------------------------------------------------------------- pairing window (the hub's gray button is pressed by hand)
    def start_pairing(self):
        now = time.time(); self.pairing = {'since': now, 'until': now + 600}
        self.store.set_kv('pairing', self.pairing); self.bus.publish('pairing', self.pairing_view())
        return self.pairing_view()

    def stop_pairing(self):
        self.pairing['until'] = 0; self.store.set_kv('pairing', self.pairing); self.bus.publish('pairing', self.pairing_view())

    # ------------------------------------------------------------- views (API shapes)
    def is_online(self, now=None):
        """Connected now, or heard from within the last couple of minutes (on battery the hub connects, reports and
        hangs up on purpose)."""
        last = self.status.get('lastSeen')
        return bool(self.session) or bool(last and (now or time.time()) - last < ONLINE_GRACE)

    def hub_view(self):
        s, sess = self.status, self.session
        st = self.settings()
        return {
            'id': s.get('id'), 'claimed': (self.claim() or {}).get('id'), 'online': self.is_online(), 'connected': bool(sess),
            'name': st.get('hubName') or 'SmartBase', 'location': st.get('hubLoc') or '',
            'connectedSince': sess and sess['since'], 'lastSeen': s.get('lastSeen'), 'ip': s.get('ip'),
            'power': None if s.get('pw') is None else ('mains' if s.get('pw') == 1 else 'battery'),
            'backupBatteryMv': s.get('bat'),          # no percentage: the pack's voltage range isn't known yet (seen: ~5.3 V on mains)
            'connection': {'w': 'wifi'}.get(s.get('co'), s.get('co')),
            'wifi': {'ssid': s.get('ss'), 'channel': s.get('wc'), 'rssi': s.get('rs')} if s.get('ss') is not None else None,
            'cellular': None if s.get('cs') is None else {'signal': None if s.get('cs') == 99 else s.get('cs')},
            'climate': None if s.get('temp') is None else {'tempC': s.get('temp'), 'humidity': s.get('hum')},
            'firmware': {'hub': s.get('bfw'), 'wifi': s.get('wfw'), 'radio': s.get('sfw'), 'modem': s.get('cfw'), 'hardware': s.get('hw'), 'certBundle': s.get('cv')},
            'fireAlarm': bool(s.get('fr')),
        }

    def arm_view(self):
        a = self.arm; cd = a.get('countdown'); now = time.time()
        src = (a.get('lastDisarm') or {}).get('source')
        if src == 'ho' and self.settings().get('duressSilent', True): src = None
        return {'state': a.get('as'), 'mode': AS_MODE.get(a.get('as')), 'label': AS_LABEL.get(a.get('as'), 'Unknown'), 'since': a.get('since'),
                'countdown': cd and {'kind': cd['kind'], 'ends': cd['ends'], 'seconds': max(0, round(cd['ends'] - now))},
                'lastDisarm': a.get('lastDisarm') and {'source': src, 'label': DA_LABEL.get(src, 'keypad'), 't': a['lastDisarm']['t']}}

    def sensor_view(self, sid):
        s = self.sensors.get(sid)
        if not s: return None
        meta = self.meta().get(str(sid), {}); st = self.settings()
        pct = bat_pct(s.get('type'), s.get('bat')); hours = int(st.get('sensorMissingH') or 24); last = s.get('lastSeen')
        return {'id': sid, 'type': s.get('type'), 'typeLabel': TYPE_LABEL.get(s.get('type'), 'Device'), 'dt': s.get('dt'),
                'name': meta.get('name') or '', 'displayName': self._name(sid, s), 'room': meta.get('room', ''), 'named': bool(meta.get('name')),
                'removed': bool(meta.get('removed')), 'state': s.get('state'), 'stateLabel': STATE_LABEL.get(s.get('state'), s.get('state') or ''),
                'battery': {'raw': s.get('bat'), 'pct': pct, 'low': pct is not None and pct <= low_limit(st)},
                'signal': {'rssi': s.get('rs'), 'bars': bars(s.get('rs'))}, 'firmware': s.get('fw'), 'hardware': s.get('hw'), 'mac': s.get('mac'),
                'alertMode': s.get('as'), 'temp': s.get('temp'), 'humidity': s.get('hum'), 'firstSeen': s.get('firstSeen'),
                'lastSeen': last, 'manual': bool(s.get('manual')), 'waiting': not last, 'typeEditable': self.type_editable(s),
                'typeFrom': 'hub' if s.get('dt') in DT else 'owner' if s.get('manual') and s.get('type') != 'unknown' else 'inferred' if s.get('inferred') else 'unknown',
                'missing': bool(last) and time.time() - last > hours * 3600}

    def sensors_view(self, include_removed=False):
        out = [self.sensor_view(i) for i in sorted(self.sensors)]
        return [x for x in out if x and (include_removed or not x['removed'])]

    def alerts_view(self, owner=False):
        silent = self.settings().get('duressSilent', True)
        return sorted([a for a in self.alerts.values() if owner or not (a['kind'] == 'duress' and silent)], key=lambda a: -a['since'])

    def ack_alert(self, kind, who):
        a = self.alerts.pop(kind, None)
        if not a: return False
        self.store.drop_alert(kind); self.bus.publish('alert', {'kind': kind, 'acknowledged': True})
        self._event('system', 'info', f'{a["title"]} acknowledged', f'by {who}')
        if self.notifier: self.notifier.acknowledged(kind, who, 'app')
        return True

    def pairing_view(self):
        p = self.pairing; now = time.time(); active = p.get('until', 0) > now
        found = [self.sensor_view(i) for i, s in self.sensors.items() if s.get('firstSeen', 0) >= p.get('since', now) or not self.meta().get(str(i), {}).get('name')]
        found = [f for f in found if f and not (f['manual'] and f['waiting'])]
        return {'active': active, 'until': p.get('until') if active else None, 'since': p.get('since'),
                'found': [f for f in found if f and not f['removed'] and not f['named']]}

    def overview(self, owner=False):
        sensors = self.sensors_view()
        return {'hub': self.hub_view(), 'arm': self.arm_view(), 'alerts': self.alerts_view(owner),
                'sensors': {'total': len(sensors), 'missing': sum(s['missing'] for s in sensors), 'lowBattery': sum(bool(s['battery']['low']) for s in sensors),
                            'open': sum(s['state'] in ('open', 'wet') for s in sensors), 'unnamed': sum(not s['named'] for s in sensors)},
                'listener': self.listener_view()}

    def listener_view(self):
        sess = self.session
        return {**self.listener, 'session': sess and {k: sess[k] for k in ('id', 'ip', 'since', 'subscribed', 'configSent')}}
