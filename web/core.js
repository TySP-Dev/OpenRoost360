/* OpenRoost360 web app core: API client, live state (REST + server-sent events) and shared widgets.
 * Used by index.html (app.js) and setup.html (setup.js). Talks only to the OpenRoost server's /api/v1.
 * Features the server marks "planned" are shown greyed out with a "Planned, unsupported" tooltip.
 */
(function () {
  'use strict';

  // ---------- protocol vocabulary (from PROTOCOL.md) ----------
  const TYPE_LABEL = { keypad: 'Keypad', door: 'Entry sensor', motion: 'Motion sensor', leak: 'Water leak / temp', smoke: 'Smoke listener', unknown: 'Unrecognised device' };
  const AS_LABEL = { 0: 'Disarmed', 2: 'Armed Home', 8: 'Arming Away', 4: 'Armed Away' };
  const DA_LABEL = { ow: 'Owner PIN', gu: 'Guest PIN', ho: 'Hostage PIN' };
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const now = () => Date.now();

  // ---------- icons (feather-style strokes) ----------
  const ICONS = {
    shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    home: '<path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/>',
    door: '<path d="M5 21V4a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v17"/><path d="M3 21h18"/><circle cx="15" cy="12" r="1"/>',
    motion: '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
    leak: '<path d="M12 2.69l5.66 5.66a8 8 0 1 1-11.31 0z"/>',
    fire: '<path d="M12 2c1 3.5 5 6 5 11a5 5 0 0 1-10 0c0-2.5 1.5-4 2.5-5.5C10 9.5 11 11 12 11c0-3-1-6 0-9z"/>',
    keypad: '<rect x="4" y="2" width="16" height="20" rx="2"/><path d="M8 7h.01M12 7h.01M16 7h.01M8 11h.01M12 11h.01M16 11h.01M8 15h.01M12 15h.01M16 15h.01M12 19h.01"/>',
    smoke: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="3"/>',
    bell: '<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/>',
    wifi: '<path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/>',
    battery: '<rect x="1" y="6" width="18" height="12" rx="2"/><line x1="23" y1="13" x2="23" y2="11"/>',
    power: '<path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/>',
    sliders: '<line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/>',
    user: '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
    mail: '<path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/>',
    palette: '<circle cx="12" cy="12" r="10"/><circle cx="8" cy="10" r="1.5"/><circle cx="12" cy="7" r="1.5"/><circle cx="16" cy="10" r="1.5"/>',
    server: '<rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>',
    list: '<line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/>',
    plus: '<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>',
    lock: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    unlock: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/>',
    alert: '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    check: '<polyline points="20 6 9 17 4 12"/>',
    x: '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
    thermo: '<path d="M14 14.76V3.5a2.5 2.5 0 0 0-5 0v11.26a4.5 4.5 0 1 0 5 0z"/>',
    chip: '<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3"/>',
    signal: '<path d="M2 20h.01M7 20v-4M12 20v-8M17 20V8M22 4v16"/>',
    grid: '<rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>',
    terminal: '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>',
    link: '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
    eye: '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>',
    edit: '<path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z"/>',
    trash: '<polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>',
    zap: '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
    moon: '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>',
    play: '<polygon points="5 3 19 12 5 21 5 3"/>',
  };
  const icon = (n, cls = '') => `<svg class="ic ${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[n] || ''}</svg>`;
  const TYPE_ICON = { keypad: 'keypad', door: 'door', motion: 'motion', leak: 'leak', smoke: 'smoke', unknown: 'chip', other: 'chip' };
  const KIND_ICON = { arm: 'lock', disarm: 'unlock', sensor: 'motion', alarm: 'alert', fire: 'fire', panic: 'zap', duress: 'alert', leak: 'leak', pair: 'link', system: 'server', power: 'power', climate: 'thermo' };

  // ---------- state (filled from the server) ----------
  const S = {
    hub: {}, as: null, countdown: null, lastDisarm: null, alerts: [], sensors: [], events: [], pairing: { active: false, found: [] },
    listener: {}, settings: {}, contacts: [], rooms: [], features: {}, live: false, version: '', update: null, tlsFingerprint: null, wire: [], wirePaused: false, esc: [], escSkew: 0,
  };
  const allRooms = () => [...new Set([...S.rooms, ...S.sensors.map(x => x.room).filter(Boolean)])].sort((a, b) => a.localeCompare(b));
  function createRoom(name) { name = name.trim(); if (!name) return ''; const ex = allRooms().find(r => r.toLowerCase() === name.toLowerCase()); if (ex) return ex; S.rooms.push(name); if (SV_STATE.user) persist().catch(() => {}); return name; }

  // ---------- pub/sub ----------
  const subs = new Set();
  const on = fn => (subs.add(fn), () => subs.delete(fn));
  let emitQueued = false;
  function emit() { if (emitQueued) return; emitQueued = true; requestAnimationFrame(() => { emitQueued = false; subs.forEach(f => { try { f(S); } catch (e) { console.error(e); } }); }); }
  function mount(el, fn) { fn(S); const off = on(st => { if (!document.body.contains(el)) return off(); fn(st); }); return off; }

  // ---------- server API ----------
  const SV_STATE = { user: null, sid: null, role: null, secretsSet: {} };
  async function api(method, path, body) {
    const opt = { method, credentials: 'same-origin', headers: { 'X-OpenRoost': '1' } };
    if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
    const r = await fetch('/api/v1' + path, opt);
    let data = {}; try { data = await r.json(); } catch (e) { /* empty body */ }
    if (!r.ok) {
      const err = new Error(data.fields ? Object.entries(data.fields).map(([k, v]) => `${k}: ${v}`).join('; ') : (data.error || 'Request failed (' + r.status + ')'));
      err.status = r.status; err.fields = data.fields; err.data = data; throw err;
    }
    return data;
  }
  const hasSecret = path => !!SV_STATE.secretsSet[path];
  const isOwner = () => SV_STATE.role === 'owner';

  // ---------- API shapes -> UI objects ----------
  const toSensor = v => ({ ...v, name: v.displayName, rawName: v.name, bat: v.battery.raw, pct: v.battery.pct, low: v.battery.low, rs: v.signal.rssi,
    as: v.alertMode, last: (v.lastSeen || 0) * 1000, hum: v.humidity, fw: v.firmware, hw: v.hardware });
  const toEvent = e => ({ ...e, t: e.t * 1000 });
  const toAlert = a => ({ ...a, since: a.since * 1000 });
  function toHub(h) {
    return { ...h, pw: h.power === 'mains' ? 1 : h.power === 'battery' ? 0 : null, bat: h.backupBatteryMv, ss: h.wifi?.ssid, wc: h.wifi?.channel, rs: h.wifi?.rssi,
      cs: h.cellular ? (h.cellular.signal ?? 99) : null, temp: h.climate?.tempC, hum: h.climate?.humidity, since: h.connectedSince ? h.connectedSince * 1000 : null,
      lastSeen: h.lastSeen ? h.lastSeen * 1000 : null, bfw: h.firmware?.hub, wfw: h.firmware?.wifi, sfw: h.firmware?.radio, cfw: h.firmware?.modem, hw: h.firmware?.hardware, cv: h.firmware?.certBundle };
  }
  function applyArm(a) {
    S.as = a.state ?? null;
    S.countdown = a.countdown ? { kind: a.countdown.kind, ends: a.countdown.ends * 1000, total: a.countdown.kind === 'exit' ? (+S.settings.exitDelay || 60) : (+S.settings.entryDelay || 45) } : null;
    S.lastDisarm = a.lastDisarm;
  }
  function applyOverview(o) { S.hub = toHub(o.hub); applyArm(o.arm); S.alerts = o.alerts.map(toAlert); S.listener = o.listener; }
  function upsertSensor(v) {
    if (!v) return;
    const i = S.sensors.findIndex(x => x.id === v.id);
    if (v.removed) { if (i >= 0) S.sensors.splice(i, 1); return; }
    if (i >= 0) S.sensors[i] = toSensor(v); else S.sensors.push(toSensor(v));
  }
  async function loadFeatures() {
    const f = await api('GET', '/features'); S.features = Object.fromEntries(f.features.map(x => [x.id, x])); return S.features;
  }
  async function loadAll() {
    const [ov, sens, ev, pair] = await Promise.all([api('GET', '/overview'), api('GET', '/sensors'), api('GET', '/events?limit=200'), api('GET', '/pairing'), loadFeatures()]);
    applyOverview(ov); S.sensors = sens.sensors.map(toSensor); S.events = ev.events.map(toEvent); S.pairing = pair;
    try { S.update = await api('GET', '/version'); S.version = S.update.version; } catch (e) { /* not fatal */ }
    await loadEsc();
    emit();
  }
  async function loadEsc() {
    try { const r = await api('GET', '/escalations'); S.esc = r.escalations; S.escSkew = r.now * 1000 - Date.now(); } catch (e) { /* not fatal */ }
  }
  setInterval(() => { if (S.esc.some(x => x.state === 'pending')) emit(); }, 1000);
  let stream = null;
  function connectStream() {
    if (stream) stream.close();
    stream = new EventSource('/api/v1/stream');
    const j = e => JSON.parse(e.data);
    stream.addEventListener('hello', e => { applyOverview(j(e)); S.live = true; api('GET', '/sensors').then(r => { S.sensors = r.sensors.map(toSensor); emit(); }).catch(() => {}); emit(); });
    stream.addEventListener('hub', e => { S.hub = toHub(j(e)); emit(); });
    stream.addEventListener('arm', e => { applyArm(j(e)); emit(); });
    stream.addEventListener('sensor', e => { upsertSensor(j(e)); emit(); });
    stream.addEventListener('event', e => { S.events.unshift(toEvent(j(e))); if (S.events.length > 500) S.events.length = 500; emit(); });
    stream.addEventListener('escalation', e => {
      const x = j(e), i = S.esc.findIndex(y => y.id === x.id);
      if (i >= 0) S.esc[i] = x; else { S.esc.unshift(x); if (x.state === 'pending') toast(`${esc(x.label)}: ${x.secs} s to cancel the emergency messages`, 'err', 6000); }
      emit();
    });
    stream.addEventListener('alert', e => {
      const a = j(e); S.alerts = S.alerts.filter(x => x.kind !== a.kind);
      if (!a.acknowledged) { S.alerts.unshift(toAlert(a)); if (a.active && S.settings.alarmSound !== false) chime(); }
      emit();
    });
    stream.addEventListener('pairing', () => { api('GET', '/pairing').then(p => { S.pairing = p; emit(); }).catch(() => {}); });
    stream.addEventListener('wire', e => { const w = j(e); S.wire.push(w); if (S.wire.length > 3000) S.wire.splice(0, S.wire.length - 3000); if (!S.wirePaused) emit(); });
    stream.addEventListener('listener', () => { api('GET', '/overview').then(o => { S.listener = o.listener; emit(); }).catch(() => {}); });
    stream.onerror = () => { S.live = false; emit(); };
  }
  // countdowns tick in the browser; the hub reports the state changes
  setInterval(() => { if (S.countdown || S.pairing.active) emit(); }, 1000);
  function chime() {
    try {
      const ctx = new (window.AudioContext || window.webkitAudioContext)(), o = ctx.createOscillator(), g = ctx.createGain();
      o.frequency.value = 880; o.connect(g); g.connect(ctx.destination); g.gain.setValueAtTime(.2, ctx.currentTime); g.gain.exponentialRampToValueAtTime(.001, ctx.currentTime + 1.2);
      o.start(); o.stop(ctx.currentTime + 1.2);
    } catch (e) { /* no audio */ }
  }

  // ---------- planned features: greyed out, "Planned, unsupported" on hover / focus / tap ----------
  const PLANNED = 'Planned, unsupported';
  const isPlanned = id => (S.features[id]?.status || 'supported') === 'planned';
  const plannedAttrs = id => ` data-planned="${esc(PLANNED)}" data-feature="${esc(id)}" aria-disabled="true" tabindex="0" aria-description="${esc(PLANNED + (S.features[id] ? ': ' + S.features[id].summary : ''))}"`;
  let tip = null, tipTimer = null;
  function showTip(el) {
    if (!tip) { tip = document.createElement('div'); tip.className = 'planned-tip'; tip.setAttribute('role', 'tooltip'); document.body.appendChild(tip); }
    const f = S.features[el.dataset.feature];
    tip.innerHTML = `<b>${esc(PLANNED)}</b>${f ? `<span>${esc(f.summary)}</span>` : ''}`;
    tip.hidden = false;
    const r = el.getBoundingClientRect(), tw = Math.min(280, window.innerWidth - 24);
    tip.style.maxWidth = tw + 'px';
    const left = Math.max(12, Math.min(window.innerWidth - tip.offsetWidth - 12, r.left + r.width / 2 - tip.offsetWidth / 2));
    const top = r.top - tip.offsetHeight - 8 < 8 ? r.bottom + 8 : r.top - tip.offsetHeight - 8;
    tip.style.left = left + 'px'; tip.style.top = (top + window.scrollY) + 'px';
  }
  const hideTip = () => { if (tip) tip.hidden = true; };
  window.addEventListener('hashchange', hideTip); window.addEventListener('scroll', hideTip, { passive: true });
  document.addEventListener('mouseover', e => { const p = e.target.closest?.('[data-planned]'); if (p) showTip(p); });
  document.addEventListener('mouseout', e => { const p = e.target.closest?.('[data-planned]'); if (p && !p.contains(e.relatedTarget)) hideTip(); });
  document.addEventListener('focusin', e => { const p = e.target.closest?.('[data-planned]'); if (p) showTip(p); else hideTip(); });
  document.addEventListener('click', e => {
    const p = e.target.closest?.('[data-planned]');
    if (!p) return;
    e.preventDefault(); e.stopPropagation(); showTip(p); clearTimeout(tipTimer); tipTimer = setTimeout(hideTip, 2500);
  }, true);
  document.addEventListener('keydown', e => { const p = e.target.closest?.('[data-planned]'); if (p && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); showTip(p); } }, true);

  // ---------- formatting ----------
  function fmtTime(t) { const d = new Date(t); const h24 = S.settings.timeFmt === '24'; return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: !h24 }); }
  function fmtDate(t) { const d = new Date(t); const today = new Date(); return d.toDateString() === today.toDateString() ? 'Today' : d.toLocaleDateString([], { month: 'short', day: 'numeric' }); }
  function ago(t) { if (!t) return 'never'; const s = Math.round((now() - t) / 1000); if (s < 10) return 'just now'; if (s < 60) return s + 's ago'; if (s < 3600) return Math.round(s / 60) + 'm ago'; if (s < 86400) return Math.round(s / 3600) + 'h ago'; return Math.round(s / 86400) + 'd ago'; }
  const batPct = s => s.pct ?? 0;
  const bars = rs => rs == null ? 0 : rs > -55 ? 4 : rs > -65 ? 3 : rs > -75 ? 2 : 1;
  function temp(c) { if (c == null) return '—'; return S.settings.tempUnit === 'C' ? (+c).toFixed(1) + '°C' : (c * 9 / 5 + 32).toFixed(0) + '°F'; }
  function remaining() { return S.countdown ? Math.max(0, Math.ceil((S.countdown.ends - now()) / 1000)) : 0; }
  const sensorState = s => s.stateLabel || s.state || '';
  const isAlertState = s => ['open', 'motion', 'wet'].includes(s.state);
  const isMissing = s => !!s.missing;
  function uptime() { if (!S.hub.since) return '—'; const s = (now() - S.hub.since) / 1000; return `${Math.floor(s / 86400)}d ${Math.floor(s % 86400 / 3600)}h ${Math.floor(s % 3600 / 60)}m`; }
  const sensor = id => S.sensors.find(s => s.id === id);

  // ---------- toast ----------
  function toast(msg, kind = 'ok', ms = 3200) {
    let host = document.querySelector('.toasts');
    if (!host) { host = document.createElement('div'); host.className = 'toasts'; host.setAttribute('role', 'status'); document.body.appendChild(host); }
    const t = document.createElement('div'); t.className = 'toast toast-' + kind; t.innerHTML = msg; host.appendChild(t);
    setTimeout(() => t.classList.add('out'), ms); setTimeout(() => t.remove(), ms + 500);
    return t;
  }
  function download(name, data, type = 'application/json') { const a = document.createElement('a'); a.href = URL.createObjectURL(data instanceof Blob ? data : new Blob([data], { type })); a.download = name; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); }
  async function busy(b, fn) { const t = b.innerHTML; b.disabled = true; b.innerHTML = '<span class="spin"></span> Working…'; try { return await fn(); } finally { b.disabled = false; b.innerHTML = t; } }

  // ---------- sensors (names, rooms, removal) ----------
  async function renameSensor(id, name, room) {
    const v = await api('PATCH', '/sensors/' + id, { name, room: room ? createRoom(room) : '' });
    upsertSensor(v); emit(); return v;
  }
  async function removeSensor(id) {
    await api('DELETE', '/sensors/' + id);
    const i = S.sensors.findIndex(x => x.id === id); if (i >= 0) S.sensors.splice(i, 1); emit();
    return async () => { upsertSensor(await api('PATCH', '/sensors/' + id, { removed: false })); emit(); };
  }
  const MODE_BITS = [[1, 'Always (24 h)'], [2, 'Home'], [4, 'Away']];
  function sensorDetails(id) {
    const s = sensor(id); if (!s) return;
    const miss = isMissing(s), sig = ['unknown', 'weak', 'fair', 'good', 'great'][bars(s.rs)];
    const modes = s.as == null ? 'Unknown' : MODE_BITS.filter(([b]) => s.as & b).map(([, l]) => l).join(', ') || 'Never';
    const when = s.last ? new Date(s.last).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : '—';
    const row = (k, v, code) => `<div><dt>${k}${code ? ` <code class="code">${code}</code>` : ''}</dt><dd>${v}</dd></div>`;
    const ov = document.createElement('div'); ov.className = 'kp-ov';
    ov.innerHTML = `<form class="cf sd" role="dialog" aria-modal="true" aria-labelledby="sd-t">
      <div class="sd-head"><span class="ico sd-ico ${miss ? 'is-missing' : ''}">${icon(TYPE_ICON[s.type] || 'chip')}</span><div><h3 id="sd-t">${esc(s.name)}</h3><div class="f-help">${esc(s.typeLabel)}</div></div>
        <button type="button" class="btn btn-icon sd-x" data-cancel aria-label="Close">${icon('x')}</button></div>
      <div class="sd-sec">Name &amp; location</div>
      <label class="sd-f"><span>Name</span><input class="in" name="n" value="${esc(s.rawName || '')}" placeholder="${esc(s.name)}" required maxlength="40"></label>
      <label class="sd-f"><span>Room</span><div class="combo"><input class="in" name="r" value="${esc(s.room || '')}" placeholder="Room — search or create" autocomplete="off" role="combobox" aria-expanded="false" aria-autocomplete="list" aria-label="Room"><ul class="combo-list" role="listbox" hidden></ul></div></label>
      <div class="sd-sec">Status</div>
      <dl class="kv">
        ${row('Status', miss ? '<span class="sd-pill warn">Missing</span>' : `<span class="sd-pill">${esc(sensorState(s))}</span>`)}
        ${row('Last check-in', `${ago(s.last)} · ${esc(when)}`)}
        ${row('Battery', s.pct == null ? '—' : `${s.pct}% <span class="sd-raw">(${s.bat})</span>`, 'bat')}
        ${row('Signal at hub', `${sig} <span class="sd-raw">(${s.rs ?? '—'} dBm)</span>`, 'rs')}
        ${s.temp != null ? row('Temperature / humidity', `${temp(s.temp)} · ${s.hum ?? '—'}%`, 'cl') : ''}
        ${row('Triggers alarm when', esc(modes) + ` <span class="sd-chg"${plannedAttrs('sensors.alertMode')}>Change</span>`, 'as')}
      </dl>
      <div class="sd-sec">As reported to the listener</div>
      <dl class="kv">
        ${row('Sensor slot', esc(String(s.id)), 'id')}
        ${row('Radio address', `<span class="sd-mono">${esc(s.mac || '—')}</span>`, 'mac')}
        ${row('Device type', `${esc(s.typeLabel)} <span class="sd-raw">(${s.dt ?? '—'})</span>`, 'dt')}
        ${row('Firmware', `<span class="sd-mono">${esc(s.fw || '—')}</span>`, 'fw')}
        ${row('Hardware', `<span class="sd-mono">${esc(s.hw || '—')}</span>`, 'hw')}
      </dl>
      <div class="sd-actions">${isOwner() ? `<button type="button" class="btn btn-danger" data-remove>${icon('trash')} Remove</button>` : ''}<span class="sd-sp"></span><button type="button" class="btn" data-cancel>${isOwner() ? 'Cancel' : 'Close'}</button>${isOwner() ? '<button class="btn btn-primary">Save</button>' : ''}</div>
    </form>`;
    document.body.appendChild(ov);
    const form = ov.querySelector('form'); roomCombo(form.querySelector('.combo'));
    if (!isOwner()) form.querySelectorAll('input').forEach(i => { i.disabled = true; });
    const close = () => { ov.remove(); document.removeEventListener('keydown', key); };
    const key = e => { if (e.key === 'Escape' && !ov.querySelector('.combo-list:not([hidden])')) close(); };
    document.addEventListener('keydown', key);
    ov.addEventListener('click', e => { if (e.target === ov || e.target.closest('[data-cancel]')) close(); });
    form.querySelector('[data-remove]')?.addEventListener('click', () => { close(); confirmRemoveSensor(id); });
    form.addEventListener('submit', async e => {
      e.preventDefault();
      try { const v = await renameSensor(id, form.n.value.trim(), form.r.value.trim()); toast(`Saved ${esc(v.displayName)}`); close(); }
      catch (err) { toast(esc(err.message), 'err'); }
    });
    if (isOwner() && !matchMedia('(pointer: coarse)').matches) { form.n.focus(); form.n.select(); } else form.querySelector('.sd-x').focus({ preventScroll: true });
  }
  function confirmRemoveSensor(id) {
    const s = sensor(id); if (!s) return;
    const ov = document.createElement('div'); ov.className = 'kp-ov';
    const quiet = isMissing(s) ? `Last heard from <b>${ago(s.last)}</b>.` : `It checked in <b>${ago(s.last)}</b>, so it still seems to be working.`;
    ov.innerHTML = `<div class="cf" role="alertdialog" aria-modal="true" aria-labelledby="cf-t" aria-describedby="cf-d">
      <div class="cf-ico">${icon('trash')}</div><h3 id="cf-t">Remove ${esc(s.name)}?</h3>
      <div id="cf-d"><p>${quiet} It will no longer appear in your device list or count towards alerts. Its past activity stays in History.</p>
      <p class="cf-note">${icon('alert')} <span>OpenRoost can't unpair it from the hub yet (that needs the hub's command format). If this sensor checks in again, it shows up under <b>Add a sensor</b> to set up again.</span></p></div>
      <div class="cf-actions"><button type="button" class="btn" data-cancel>Cancel</button><button type="button" class="btn btn-danger-solid" data-ok>Remove</button></div></div>`;
    document.body.appendChild(ov);
    const close = () => { ov.remove(); document.removeEventListener('keydown', key); };
    const key = e => { if (e.key === 'Escape') close(); };
    document.addEventListener('keydown', key);
    ov.addEventListener('click', e => { if (e.target === ov || e.target.closest('[data-cancel]')) close(); });
    ov.querySelector('[data-ok]').addEventListener('click', async () => {
      close();
      try {
        const undo = await removeSensor(id);
        const t = toast(`Removed ${esc(s.name)} <button type="button" class="toast-act">Undo</button>`, 'ok', 6000);
        t.querySelector('.toast-act').addEventListener('click', async () => { t.remove(); try { await undo(); } catch (e) { toast(esc(e.message), 'err'); } });
      } catch (e) { toast(esc(e.message), 'err'); }
    });
    ov.querySelector('[data-cancel]').focus();
  }

  // ---------- Pi-hole & email (shared by setup and Settings) ----------
  const PH_OPTS = [
    { v: 'bundled', icon: 'server', title: 'The one included with OpenRoost', desc: 'A Pi-hole that runs next to OpenRoost on this server (Docker profile “pihole”). Best if you don\'t have one.' },
    { v: 'existing', icon: 'link', title: 'My existing Pi-hole', desc: 'You add two DNS lines to it (OpenRoost gives you the exact command) and OpenRoost checks them. Needs Pi-hole v6 or newer.' },
  ];
  const MAIL_OPTS = [
    { v: 'relay-existing', icon: 'link', title: 'My existing mail relay', desc: 'Send through a relay you already run, such as Postfix or a relay container forwarding to Resend.' },
    { v: 'relay-start', icon: 'server', title: 'OpenRoost\'s own mail relay', desc: 'A relay that runs next to OpenRoost (Docker profile “mailrelay”) and hands mail to Resend or another service.' },
    { v: 'account', icon: 'mail', title: 'Email account', desc: 'Send from Gmail, iCloud or another mailbox using an app password. Quickest to set up.' },
    { v: 'off', icon: 'x', title: 'Don\'t send email', desc: 'Matrix and push alerts still work. You can turn email on later.' },
  ];
  const MAIL_PROV = {
    gmail: { label: 'Gmail', host: 'smtp.gmail.com', port: 587, sec: 'starttls', user: 'you@gmail.com', help: 'Gmail needs an <b>app password</b>: Google Account → Security → 2-Step Verification → App passwords. Your normal Gmail password won\'t work.' },
    icloud: { label: 'iCloud Mail', host: 'smtp.mail.me.com', port: 587, sec: 'starttls', user: 'you@icloud.com', help: 'iCloud needs an <b>app-specific password</b> from account.apple.com → Sign-In and Security. Mail must come <i>from</i> your iCloud address or one of its aliases.' },
    other: { label: 'Other', host: '', port: 587, sec: 'starttls', user: 'you@example.com', help: 'Use the SMTP settings from your email provider\'s help pages.' },
  };
  const SEC_OPTS = [['none', 'None'], ['starttls', 'STARTTLS'], ['tls', 'SSL/TLS']];
  const newPihole = () => ({ mode: null, url: '', pass: '', ok: false, ver: '' });
  const newMail = () => ({ mode: null, up: 'resend', prov: 'gmail', host: '', port: '', sec: '', auth: false, user: '', pass: '', key: '', from: '', to: '' });
  const clone = o => JSON.parse(JSON.stringify(o));
  const stored = (cfg, path) => !cfg._fresh && hasSecret(path);
  const secretPh = (cfg, path, ph) => stored(cfg, path) ? 'Saved · type to replace' : ph;

  function choiceCards(opts, val, name) {
    return `<div class="su-choices${opts.length > 2 ? ' su-choices-3' : ''}" role="radiogroup">${opts.map(o => {
      const planned = o.feature && isPlanned(o.feature);
      return `<button type="button" role="radio" aria-checked="${val === o.v}" class="su-choice${val === o.v ? ' on' : ''}" data-choice="${name}" data-v="${o.v}"${planned ? plannedAttrs(o.feature) : ''}><b>${icon(o.icon)} ${o.title}</b><span>${o.desc}</span></button>`;
    }).join('')}</div>`;
  }
  const cfgField = (k, label, val, type = 'text', ph = '', help = '') => `<label class="su-f"><span>${label}</span><input class="in" data-c="${k}" data-nosave type="${type}" value="${esc(val ?? '')}" placeholder="${esc(ph)}" autocomplete="off"></label>${help ? `<span class="f-help su-help">${help}</span>` : ''}`;
  const cfgSeg = (k, val, opts) => `<span class="seg" role="radiogroup">${opts.map(([v, l]) => `<label><input type="radio" name="c-${k}" data-cseg="${k}" data-nosave value="${v}"${val === v ? ' checked' : ''}><span>${l}</span></label>`).join('')}</span>`;
  function bindCfg(el, cfg, redraw, changed) {
    el.querySelectorAll('[data-c]').forEach(i => i.addEventListener('input', () => { cfg[i.dataset.c] = i.value.trim(); changed(i.dataset.c); }));
    el.querySelectorAll('[data-cseg]').forEach(r => r.addEventListener('change', () => { cfg[r.dataset.cseg] = r.value; changed(r.dataset.cseg, true); redraw(); }));
  }

  const phHostOf = cfg => { try { return new URL(cfg.url).hostname; } catch (e) { return ''; } };
  const piholeReady = cfg => ['existing', 'bundled'].includes(cfg.mode) && !!cfg.ok;
  const piholeWhy = cfg => !cfg.mode ? 'Choose which Pi-hole to use.' : cfg.ok ? '' : cfg.mode === 'bundled' ? 'Start OpenRoost\'s Pi-hole first.' : 'Connect to your Pi-hole first.';
  const startHelp = (profile, vars) => `<ol class="steps"><li>In the OpenRoost folder on the server, edit <code>.env</code>: add <b>${profile}</b> to <code>COMPOSE_PROFILES</code> and set ${vars}.</li><li>Run <code>docker compose up -d</code>.</li><li>Press <b>Check again</b>.</li></ol>`;
  // opts.test(url, password) -> {version}: setup and Settings call different endpoints
  function renderPiholeSetup(el, cfg, changed = () => {}, opts = {}) {
    const draw = () => {
      if (cfg.mode === 'existing') {
        el.innerHTML = `${cfgField('url', 'Pi-hole address', cfg.url, 'url', 'http://192.168.1.2/admin')}
          ${cfgField('pass', 'App password', cfg.pass, 'password', secretPh(cfg, 'ph.pass', 'From Pi-hole → Settings → Web interface / API'), 'Create an <b>app password</b> in Pi-hole under Settings → Web interface / API (expert mode). It\'s not your Pi-hole login password, and you can revoke it any time.')}
          <div class="su-row"><button type="button" class="btn btn-primary btn-sm" data-ph-test>${cfg.ok ? 'Test again' : 'Connect'}</button><span data-ph-msg role="status">${cfg.ok ? `<b class="ok-t">${icon('check')} Connected to Pi-hole ${esc(cfg.ver)}</b>` : ''}</span></div>
          <div class="note">${icon('alert')} <span>OpenRoost signs in with this app password only to read your existing DNS lines and check the result. It changes nothing in your Pi-hole.</span></div>`;
      } else if (cfg.mode === 'bundled') {
        el.innerHTML = '<div class="scan-wait"><span class="spin"></span> Looking for OpenRoost\'s Pi-hole…</div>';
        (opts.bundled ? opts.bundled() : Promise.reject(new Error('Not available here'))).then(r => {
          const p = r.pihole;
          if (p.available) {
            const changed2 = !cfg.ok || cfg.url !== p.url; Object.assign(cfg, { ok: true, url: p.url, ver: p.version });
            el.innerHTML = `<div class="su-hub"><div class="su-hub-h">${icon('check')}<div><b>OpenRoost's Pi-hole is running</b><div class="f-help">Pi-hole ${esc(p.version)} · admin page <code>${esc(p.url)}</code> · DNS on port ${p.dnsPort}</div></div></div></div>
              <div class="note">${icon('alert')} <span>Point your router's DNS (or just the hub's) at this server so the hub uses this Pi-hole.</span></div>`;
            if (changed2) changed();
          } else {
            cfg.ok = false;
            el.innerHTML = `<div class="note note-blocked">${icon('alert')} <span><b>OpenRoost's Pi-hole isn't running.</b> ${esc(p.error || '')}</span></div>${startHelp('pihole', '<code>PIHOLE_PASSWORD</code> (and <code>PIHOLE_DNS_PORT</code> if port 53 is taken)')}
              <div><button type="button" class="btn btn-sm" data-again>Check again</button></div>`;
            el.querySelector('[data-again]').onclick = draw; changed();
          }
        }).catch(err => { el.innerHTML = `<div class="f-help err-t">${esc(err.message)}</div>`; });
        return;
      } else el.innerHTML = '';
      bindCfg(el, cfg, draw, k => { if (cfg.mode === 'existing' && cfg.ok && (k === 'url' || k === 'pass')) { cfg.ok = false; const m = el.querySelector('[data-ph-msg]'); if (m) m.innerHTML = ''; const b = el.querySelector('[data-ph-test]'); if (b) b.textContent = 'Connect'; } changed(); });
      el.querySelector('[data-ph-test]')?.addEventListener('click', async e => {
        const msg = el.querySelector('[data-ph-msg]'), b = e.currentTarget;
        if (!phHostOf(cfg) || !/^https?:/.test(cfg.url)) { msg.innerHTML = '<b class="err-t">Enter the address you open Pi-hole at, e.g. http://192.168.1.2/admin</b>'; return; }
        if (!cfg.pass && !stored(cfg, 'ph.pass')) { msg.innerHTML = '<b class="err-t">Enter an app password.</b>'; return; }
        b.disabled = true; msg.innerHTML = '<span class="spin"></span> Connecting…';
        try { const r = await opts.test(cfg.url, cfg.pass); cfg.ok = true; cfg.ver = r.version; draw(); changed(); }
        catch (err) { cfg.ok = false; b.disabled = false; msg.innerHTML = `<b class="err-t">${esc(err.message)}</b>`; changed(); }
      });
    };
    draw();
  }

  function mailTarget(cfg) {
    const m = cfg;
    if (m.mode === 'account') { const p = MAIL_PROV[m.prov]; return { host: m.prov === 'other' ? m.host : p.host, port: m.prov === 'other' ? (m.port || 587) : p.port, from: m.from || m.user }; }
    if (m.mode === 'relay-existing') return { host: m.host, port: m.port || 25, from: m.from };
    return null;
  }
  function mailWhy(cfg, needTo) {
    const m = cfg, t = mailTarget(m);
    if (!m.mode) return 'Choose how OpenRoost should send email.';
    if (m.mode === 'off') return '';
    if (m.mode === 'relay-start' && !m._relayOk) return 'Start OpenRoost\'s mail relay first.';
    const pass = m.pass || stored(m, 'mail.pass');
    if (m.mode === 'account' && (!m.user || !pass)) return 'Enter the email address and app password.';
    if (m.mode === 'account' && m.prov === 'other' && !m.host) return 'Enter the SMTP server.';
    if (m.mode === 'relay-existing' && (!m.host || (m.auth && (!m.user || !pass)))) return 'Enter your relay\'s address' + (m.auth ? ' and sign-in.' : '.');
    if (t && !/.+@.+\..+/.test(t.from || '')) return 'Enter a From address.';
    if (needTo && !/.+@.+\..+/.test(m.to)) return 'Enter who should get alerts.';
    return '';
  }
  // opts.test(cfg) -> {result}; opts.recipients: ask for the alert recipient here (setup)
  function renderMailSetup(el, cfg, changed = () => {}, opts = {}) {
    const draw = () => {
      const m = cfg, smtp = (defPort, defSec) => `${cfgField('host', 'SMTP server', m.host, 'text', 'smtp.example.com')}
        <div class="su-f"><span>Port</span><div class="in-unit"><input class="in in-num" data-c="port" data-nosave type="number" min="1" max="65535" value="${esc(m.port || defPort)}"></div></div>
        <div class="su-f"><span>Encryption</span>${cfgSeg('sec', m.sec || defSec, SEC_OPTS)}</div>`;
      let h = '';
      if (m.mode === 'account') {
        const p = MAIL_PROV[m.prov];
        h = `<div class="su-f"><span>Provider</span>${cfgSeg('prov', m.prov, Object.entries(MAIL_PROV).map(([k, v]) => [k, v.label]))}</div>
          ${m.prov === 'other' ? smtp(587, 'starttls') : `<div class="su-chk ok su-chk-tight"><span class="st">${icon('check')}</span><div><b>${p.host}</b><small>Port ${p.port}, STARTTLS. Filled in for you.</small></div></div>`}
          ${cfgField('user', 'Email address', m.user, 'email', p.user)}
          ${cfgField('pass', m.prov === 'other' ? 'Password' : 'App password', m.pass, 'password', secretPh(m, 'mail.pass', ''), p.help)}
          ${cfgField('from', 'From address', m.from, 'email', m.user || p.user, 'Leave blank to send from the address above.')}`;
      } else if (m.mode === 'relay-existing') {
        h = `${cfgField('host', 'Relay address', m.host, 'text', '192.168.1.25 or relay.home.lan')}
          <div class="su-f"><span>Port</span><div class="in-unit"><input class="in in-num" data-c="port" data-nosave type="number" min="1" max="65535" value="${esc(m.port || 25)}"></div></div>
          <div class="su-f"><span>Encryption</span>${cfgSeg('sec', m.sec || 'none', SEC_OPTS)}</div>
          <div class="su-f"><span>Needs sign-in</span><label class="sw"><input type="checkbox" data-mauth data-nosave${m.auth ? ' checked' : ''}><span class="sw-t"></span></label></div>
          ${m.auth ? cfgField('user', 'Username', m.user) + cfgField('pass', 'Password', m.pass, 'password', secretPh(m, 'mail.pass', '')) : ''}
          <div class="note">${icon('alert')} <span>Your relay must allow this server to send through it.</span></div>
          ${cfgField('from', 'From address', m.from, 'email', 'openroost@yourdomain.com', 'Use an address your relay is allowed to send as.')}`;
      } else if (m.mode === 'relay-start') {
        h = `<div data-relay><div class="scan-wait"><span class="spin"></span> Looking for OpenRoost's mail relay…</div></div>
          ${cfgField('from', 'From address', m.from, 'email', 'openroost@yourdomain.com', 'Must be on the sending domain set for the relay (<code>RELAY_SENDER_DOMAINS</code>).')}`;
      }
      if (m.mode && m.mode !== 'off' && opts.recipients) h += `<div class="eyebrow su-eyebrow">Who gets alerts</div>
          ${cfgField('to', 'Send alerts to', m.to, 'email', 'you@example.com', 'You can add more people and choose which alerts each gets in Settings → Notifications.')}`;
      if (m.mode && m.mode !== 'off' && opts.test) h += `<div class="su-row"><button type="button" class="btn btn-sm" data-mtest>${icon('mail')} Send a test email</button><span data-mmsg role="status"></span></div>`;
      el.innerHTML = h;
      const rb = el.querySelector('[data-relay]');
      if (rb) (opts.bundled ? opts.bundled() : Promise.reject(new Error('Not available here'))).then(r => {
        const x = r.relay; m._relayOk = !!x.available;
        rb.innerHTML = x.available ? `<div class="su-chk ok su-chk-tight"><span class="st">${icon('check')}</span><div><b>OpenRoost's mail relay is running</b><small>${esc(x.address)} · it delivers through the service set in <code>.env</code>.</small></div></div>`
          : `<div class="note note-blocked">${icon('alert')} <span><b>OpenRoost's mail relay isn't running.</b> ${esc(x.error || '')}</span></div>${startHelp('mailrelay', '<code>RELAY_PASSWORD</code> (e.g. your Resend API key), <code>RELAY_SENDER_DOMAINS</code> and, if not Resend, <code>RELAY_UPSTREAM</code>')}<div><button type="button" class="btn btn-sm" data-again>Check again</button></div>`;
        rb.querySelector('[data-again]')?.addEventListener('click', draw); changed();
      }).catch(err => { rb.innerHTML = `<div class="f-help err-t">${esc(err.message)}</div>`; });
      bindCfg(el, cfg, draw, k => { const mm = el.querySelector('[data-mmsg]'); if (mm) mm.innerHTML = ''; if (k === 'prov') Object.assign(m, { host: '', port: '', sec: '' }); changed(); });
      el.querySelector('[data-mauth]')?.addEventListener('change', e => { m.auth = e.target.checked; draw(); changed(); });
      el.querySelector('[data-mtest]')?.addEventListener('click', async e => {
        const btn = e.currentTarget, msg = el.querySelector('[data-mmsg]'), why = mailWhy(m, opts.recipients);
        if (why) { msg.innerHTML = `<b class="err-t">${esc(why)}</b>`; return; }
        btn.disabled = true; msg.innerHTML = '<span class="spin"></span> Sending…';
        try { const r = await opts.test(m); msg.innerHTML = `<b class="ok-t">${icon('check')} ${esc(r.result || 'Sent')}</b> <span class="f-help">Check your inbox (and spam).</span>`; }
        catch (err) { msg.innerHTML = `<b class="err-t">${esc(err.message)}</b>`; }
        finally { btn.disabled = false; }
      });
    };
    draw();
  }
  // Pi-hole only takes misc.dnsmasq_lines from its config file / CLI, so for your own Pi-hole OpenRoost shows the steps
  function manualDnsHTML(r) {
    const copy = (txt) => `<div class="copy"><code>${esc(txt)}</code><button type="button" class="btn btn-icon" data-copy="${esc(txt)}" title="Copy" data-keep>${icon('link')}</button></div>`;
    return `<div class="note note-blocked dns-manual">${icon('alert')} <div><b>Add these two lines to your Pi-hole</b>
      <p class="f-help" style="margin:4px 0 8px">Pi-hole only accepts <code>misc.dnsmasq_lines</code> from its own settings, not from other apps, so this is the one step OpenRoost can't do for you.${r.keep && r.keep.length ? ` Your ${r.keep.length} existing line${r.keep.length > 1 ? 's are' : ' is'} kept in the commands below.` : ''}</p>
      <div class="sso-box">${r.lines.map(copy).join('')}
        <details><summary>Pi-hole in Docker: one command</summary>${copy(r.docker)}</details>
        <details><summary>Pi-hole installed directly</summary>${copy(r.native)}</details>
        <details><summary>Pi-hole web interface</summary><ol class="steps"><li>Settings → All settings → <b>Misc</b> (expert mode).</li><li>Add each line above to <code>misc.dnsmasq_lines</code>, one per line, and save.</li><li>If Pi-hole doesn't save it, use one of the commands above.</li></ol></details></div>
      <p class="f-help" style="margin:8px 0 0">Then press <b>Run checks again</b>.</p></div></div>`;
  }
  function bindCopy(el) {
    el.querySelectorAll('[data-copy]').forEach(b => b.addEventListener('click', () => { try { navigator.clipboard.writeText(b.dataset.copy); toast('Copied'); } catch (e) { /* ignore */ } }));
  }
  const piholeSummary = cfg => cfg.mode === 'existing' ? `Your Pi-hole at ${esc(phHostOf(cfg) || '?')}${cfg.ok ? '' : ' (not connected)'}` : cfg.mode === 'bundled' ? `OpenRoost's own Pi-hole${cfg.ok ? '' : ' (not running)'}` : 'Not set up';
  const mailSummary = cfg => ({ 'relay-existing': `Your relay at ${esc(cfg.host)}`, 'relay-start': 'OpenRoost\'s own mail relay', account: `${MAIL_PROV[cfg.prov]?.label} · ${esc(cfg.user)}`, off: 'Email off' }[cfg.mode] || 'Not set up');

  // Settings panel: what's in use now, pick another option, applied only when confirmed
  function serviceSettings(el, kind) {
    const isPh = kind === 'pihole', key = isPh ? 'ph' : 'mail', OPTS = isPh ? PH_OPTS : MAIL_OPTS;
    let draft = clone(S.settings[key] || (isPh ? newPihole() : newMail()));
    const draw = () => {
      const cur = S.settings[key] || {}, same = JSON.stringify(stripPrivate(draft)) === JSON.stringify(cur) && !draft._fresh;
      el.innerHTML = `<div class="svc-cur"><span class="dot dot-${isPh ? (piholeReady(cur) ? 'ok' : 'fail') : cur.mode === 'off' || !cur.mode ? 'idle' : 'ok'}"></span><div><small>In use now</small><b>${isPh ? piholeSummary(cur) : mailSummary(cur)}</b></div></div>
        ${choiceCards(OPTS, draft.mode, key)}<div class="su-card svc-body"></div>
        <div class="svc-apply" ${same ? 'hidden' : ''}><span class="f-help svc-why"></span><button type="button" class="btn" data-svc-cancel>Cancel</button><button type="button" class="btn btn-primary" data-svc-apply>${isPh ? 'Use this Pi-hole' : 'Save email setup'}</button></div>`;
      const body = el.querySelector('.svc-body'), sync = () => {
        const s = JSON.stringify(stripPrivate(draft)) === JSON.stringify(S.settings[key] || {}) && !draft._fresh, a = el.querySelector('.svc-apply'); a.hidden = s;
        const why = isPh ? piholeWhy(draft) : mailWhy(draft, false); el.querySelector('.svc-why').textContent = why; el.querySelector('[data-svc-apply]').disabled = !!why;
      };
      const bundled = () => api('GET', '/services/bundled');
      if (isPh) renderPiholeSetup(body, draft, sync, { test: (url, password) => api('POST', '/services/pihole/test', { url, password }), bundled });
      else renderMailSetup(body, draft, sync, { test: () => api('POST', '/notify/test/email', {}), bundled });
      el.querySelectorAll('[data-choice]').forEach(b => b.addEventListener('click', () => {
        if (draft.mode === b.dataset.v) return;
        const prev = S.settings[key] || {};
        draft = b.dataset.v === prev.mode ? clone(prev) : Object.assign(isPh ? newPihole() : newMail(), { mode: b.dataset.v, to: draft.to, _fresh: true });
        draw();
      }));
      el.querySelector('[data-svc-cancel]').addEventListener('click', () => { draft = clone(S.settings[key] || {}); draw(); });
      el.querySelector('[data-svc-apply]').addEventListener('click', async e => {
        const b = e.currentTarget; b.disabled = true; b.innerHTML = '<span class="spin"></span> Applying…';
        try {
          if (isPh) {
            const r = await api('POST', '/services/pihole/use', { ph: stripPrivate(draft) });
            SV_STATE.secretsSet = r.secretsSet;
            toast(`Now using ${piholeSummary(draft)}.${r.manual ? ' Add the two DNS lines shown under Redirect health → Fix.' : r.added?.length ? ' Added the Roost DNS lines.' : ''}${r.oldPiholeError ? ' Couldn\'t clean the old Pi-hole: ' + esc(r.oldPiholeError) : ''}`, 'ok', 6000);
          } else {
            if (draft._fresh) ['pass', 'key'].forEach(k => { if (!draft[k]) pendingClear.push('mail.' + k); });
            S.settings.mail = stripPrivate(draft); await persist(); toast('Email setup saved');
          }
          await loadSettings(); draft = clone(S.settings[key]); draw(); emit();
          if (isPh) document.querySelectorAll('.custom[data-custom=redirect]').forEach(c => CUSTOM.redirect(c));
        } catch (err) { toast(esc(err.message), 'err', 6000); b.disabled = false; b.textContent = isPh ? 'Use this Pi-hole' : 'Save email setup'; }
      });
      sync();
    };
    draw();
  }

  // ---------- settings ----------
  const TZ = ['America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles', 'America/Phoenix', 'America/Anchorage', 'Pacific/Honolulu', 'Europe/London', 'Europe/Berlin', 'Australia/Sydney', 'UTC'];
  const SECTIONS = [
    { id: 'security', title: 'Security & PINs', icon: 'lock', status: 'planned', feature: 'hub.pins',
      note: 'Keypad PINs, delays, chime and per-sensor alert modes went app → Roost cloud → hub on MQTT <code>/config</code>. That format <b>isn\'t cracked yet</b> (see PROTOCOL.md), so these can\'t be changed from OpenRoost. Your current keypad PINs keep working.',
      groups: [
        { title: 'PIN codes', fields: [{ type: 'custom', render: 'pins' }] },
        { title: 'Delays & chime', planned: 'hub.delays', fields: [
          { k: 'entryDelay', label: 'Entry delay', type: 'range', min: 0, max: 120, step: 5, unit: 's', def: 45, help: 'Measured on this hub: about 45 s. Used here to show the entry countdown.' },
          { k: 'exitDelay', label: 'Exit delay', type: 'range', min: 0, max: 120, step: 5, unit: 's', def: 60, help: 'Measured: 60 s. Used here to show the exit countdown.' },
          { k: 'doorChime', label: 'Door chime', type: 'toggle', def: true } ] },
        { title: 'Per-sensor alert mode', fields: [{ type: 'custom', render: 'alertmodes' }] },
      ] },
    { id: 'notifications', title: 'Notifications', icon: 'bell', status: 'ok',
      note: 'Sent by the OpenRoost server from hub events. This replaces Roost\'s monitoring cloud.',
      groups: [
        { title: 'Email', fields: [
          { type: 'custom', render: 'mailSvc' },
          { k: 'smtpTo', label: 'Recipients', type: 'textarea', ph: 'one address per line', help: 'Everyone here gets alerts routed to Email below.', def: '' },
          { k: 'smtpSubject', label: 'Subject template', type: 'text', def: '[{site}] {alert} — {time}', help: 'Placeholders: <code>{site}</code> <code>{alert}</code> <code>{sensor}</code> <code>{time}</code>' } ] },
        { title: 'Push & webhooks', fields: [
          { k: 'ntfyUrl', label: 'ntfy topic URL', type: 'url', ph: 'https://ntfy.sh/your-secret-topic', def: '', help: 'Free push to Android/iOS via the ntfy app. Self-hosted works too.' },
          { k: 'ntfyPrio', label: 'Alert priority', type: 'select', opts: [['5', 'Max (bypass Do Not Disturb)'], ['4', 'High'], ['3', 'Default']], def: '4', help: 'Alarms always use max.' },
          { k: 'hookUrl', label: 'Webhook URL', type: 'url', ph: 'https://homeassistant.local/api/webhook/…', def: '', help: 'POSTs each event as JSON (Home Assistant, Node-RED, …).' },
          { k: 'hookSecret', label: 'Webhook secret', type: 'password', def: '', help: 'Signs each request: <code>X-OpenRoost-Signature: sha256=…</code> (HMAC-SHA256 of the body).' } ],
          actions: [{ label: 'Send test push', act: 'ntfyTest' }, { label: 'Send test webhook', act: 'hookTest' }] },
        { title: 'Matrix / Element', fields: [
          { k: 'mxOn', label: 'Send Matrix alerts', type: 'toggle', def: false, help: 'Alerts land in an Element room on every family phone.' },
          { k: 'mxHs', label: 'Homeserver URL', type: 'url', ph: 'https://matrix.example.org', def: '' },
          { k: 'mxUser', label: 'Bot account', type: 'text', ph: '@openroost:example.org', def: '', help: 'A dedicated account for OpenRoost. Invite it to the alert room.' },
          { type: 'custom', render: 'mxlogin' },
          { k: 'mxRoom', label: 'Household alert room', type: 'text', ph: '#home-alerts:example.org', def: '', help: 'Room ID (<code>!abc:server</code>) or alias (<code>#room:server</code>). Encrypted rooms work: OpenRoost notices and encrypts its messages.' },
          { k: 'mxMention', label: '@room on alarms', type: 'toggle', def: true },
          { k: 'mxE2ee', label: 'Encrypt direct messages', type: 'toggle', def: true, help: 'New DMs to emergency contacts are created end-to-end encrypted. Rooms you choose are encrypted or not by their own setting.' },
          { type: 'custom', render: 'mxe2ee' } ],
          actions: [{ label: 'Send test message', act: 'matrixTest' }] },
        { title: 'Family & emergency contacts', fields: [{ type: 'custom', render: 'contacts' }] },
        { title: 'Emergency countdown', fields: [{ type: 'custom', render: 'escalation' }] },
        { title: 'What goes where', fields: [{ type: 'custom', render: 'matrix' }] },
        { title: 'Behaviour', fields: [
          { k: 'duressSilent', label: 'Silent duress', type: 'toggle', def: true, help: 'Hostage-PIN disarms alert your contacts but never show on screens inside the home.' },
          { k: 'repeatMin', label: 'Repeat alarm notifications', type: 'number', min: 0, max: 60, unit: 'min', def: 5, help: 'Re-send until someone acknowledges. 0 = once.' },
          { k: 'lowBat', label: 'Low-battery warning', type: 'range', min: 5, max: 50, step: 5, unit: '%', def: 20 },
          { k: 'offlineMin', label: 'Hub offline alert after', type: 'number', min: 1, max: 120, unit: 'min', def: 10 },
          { k: 'sensorMissingH', label: 'Mark a sensor missing after', type: 'number', min: 2, max: 168, unit: 'h', def: 24, help: 'Sensors check in on their own. One that stays quiet this long is shown as Missing.' },
          { k: 'quiet', label: 'Quiet hours for non-urgent events', type: 'text', def: '22:00–07:00', help: 'Alarms, fire, panic, leak and duress ignore quiet hours. Uses the time zone under Appearance.' } ] },
      ] },
    { id: 'climate', title: 'Climate alerts', icon: 'thermo', status: 'ok',
      note: 'The hub and leak sensors report temperature and humidity. OpenRoost checks the limits itself.',
      groups: [
        { title: 'Temperature', fields: [
          { k: 'tempAlert', label: 'Temperature alerts', type: 'toggle', def: true },
          { k: 'tl', label: 'Alert below', type: 'number', unit: '°', def: 40, help: 'In your temperature unit (Appearance).' },
          { k: 'th', label: 'Alert above', type: 'number', unit: '°', def: 95 } ] },
        { title: 'Humidity', fields: [
          { k: 'humAlert', label: 'Humidity alerts', type: 'toggle', def: false },
          { k: 'hl', label: 'Alert below', type: 'number', unit: '%', def: 20 },
          { k: 'hh', label: 'Alert above', type: 'number', unit: '%', def: 70 } ] },
      ] },
    { id: 'account', title: 'Account', icon: 'user', status: 'ok', groups: [
        { title: 'Profile', fields: [{ type: 'custom', render: 'profile' }] },
        { title: 'Password', fields: [
          { k: 'pwCur', label: 'Current password', type: 'password', nosave: true, def: '' },
          { k: 'pwNew', label: 'New password', type: 'password', nosave: true, def: '', help: 'At least 12 characters.' },
          { k: 'pwNew2', label: 'Confirm new password', type: 'password', nosave: true, def: '' } ], actions: [{ label: 'Change password', act: 'changePass', keep: true }] },
        { title: 'Two-factor sign-in', fields: [{ type: 'custom', render: 'totp' }] },
        { title: 'Sign-in', fields: [
          { k: 'sessionLen', label: 'Stay signed in for', type: 'select', opts: [['12h', '12 hours'], ['1d', '1 day'], ['7d', '7 days'], ['30d', '30 days']], def: '12h', help: 'Without “Keep me signed in”. Ticking it at sign-in keeps you in for 30 days.' },
          { k: 'proxyAuth', label: 'Trust a reverse-proxy sign-in header', type: 'toggle', def: false, help: 'For an Authentik proxy outpost or similar. Only requests from the addresses below are trusted.' },
          { k: 'proxyIps', label: 'Trusted proxy addresses', type: 'text', ph: '192.168.1.5', def: '', help: 'Comma-separated IPs of the proxy.' },
          { k: 'proxyHeader', label: 'Username header', type: 'text', def: 'Remote-User' } ] },
        { title: 'Single sign-on — Authentik', fields: [
          { k: 'ssoOn', label: 'Sign in with Authentik', type: 'toggle', def: false, help: 'OpenID Connect. Adds a sign-in button to the login page.' },
          { k: 'ssoIssuer', label: 'Issuer URL', type: 'url', ph: 'https://auth.example.com/application/o/openroost/', def: '', help: 'Authentik → Providers → your provider → “OpenID Configuration Issuer”.' },
          { k: 'ssoClientId', label: 'Client ID', type: 'text', def: '' },
          { k: 'ssoSecret', label: 'Client secret', type: 'password', def: '' },
          { type: 'custom', render: 'ssoinfo' },
          { k: 'ssoScopes', label: 'Scopes', type: 'text', def: 'openid profile email', help: 'Authentik includes the <code>groups</code> claim in <code>profile</code>.' },
          { k: 'ssoAdminGroup', label: 'Owner group', type: 'text', def: 'openroost-admins' },
          { k: 'ssoMemberGroup', label: 'Member group', type: 'text', def: 'openroost-members', help: 'Anyone in neither group is a viewer.' },
          { k: 'ssoAutoCreate', label: 'Create accounts on first sign-in', type: 'toggle', def: true },
          { k: 'ssoLocal', label: 'Also allow password sign-in', type: 'toggle', def: true, help: 'Keep this on until single sign-on is tested. It\'s your way in if Authentik is down.' },
          { k: 'ssoButton', label: 'Button label', type: 'text', def: 'Sign in with Authentik' } ],
          actions: [{ label: 'Test connection', act: 'ssoTest' }] },
        { title: 'Household members', fields: [{ type: 'custom', render: 'users' }] },
        { title: 'Your browsers & app devices', fields: [{ type: 'custom', render: 'sessions' }] },
      ] },
    { id: 'hub', title: 'Hub & network', icon: 'server', status: 'ok', groups: [
        { title: 'Hub', fields: [
          { k: 'hubName', label: 'Hub name', type: 'text', def: 'SmartBase' },
          { k: 'hubLoc', label: 'Location', type: 'text', def: '' } ] },
        { title: 'Details', fields: [{ type: 'custom', render: 'hubinfo' }] },
        { title: 'Move hub to a new Wi-Fi network', fields: [{ type: 'custom', render: 'wifi' }] },
        { title: 'Pi-hole', fields: [
          { type: 'custom', render: 'piholeSvc' },
          { k: 'serverIp', label: 'This server\'s LAN IP', type: 'text', def: '', ph: 'detected automatically', help: 'What the Roost cloud names must resolve to. Leave blank to detect it.' },
          { k: 'hubIp', label: 'Hub IP', type: 'text', def: '', ph: 'learned when the hub connects', help: 'Used for the port 443 redirect. Give the hub a DHCP reservation.' } ] },
        { title: 'Redirect health', fields: [{ type: 'custom', render: 'redirect' },
          { k: 'manageNat', label: 'Keep the port redirect in place', type: 'toggle', def: true, help: 'Re-adds the hub\'s port 443 → listener rule at start-up and whenever the hub\'s address changes. Needs the NET_ADMIN permission (the Docker stack has it).' }] },
      ] },
    { id: 'appearance', title: 'Appearance', icon: 'palette', status: 'ok', groups: [
        { title: 'Look', fields: [
          { k: 'siteName', label: 'Home name', type: 'text', def: 'Home', help: 'Used in notification subjects.' },
          { k: 'theme', label: 'Theme', type: 'segmented', opts: [['system', 'System'], ['light', 'Light'], ['dark', 'Dark']], def: 'system' },
          { k: 'accent', label: 'Accent colour', type: 'swatches', opts: ['#2f9e6e', '#c8553d', '#3b6fd8', '#b8860b', '#8e5bd6', '#d6457a'], def: '' },
          { k: 'density', label: 'Density', type: 'segmented', opts: [['comfy', 'Comfortable'], ['compact', 'Compact']], def: 'comfy' } ] },
        { title: 'Units & time', fields: [
          { k: 'tempUnit', label: 'Temperature', type: 'segmented', opts: [['F', '°F'], ['C', '°C']], def: 'F' },
          { k: 'timeFmt', label: 'Clock', type: 'segmented', opts: [['12', '12-hour'], ['24', '24-hour']], def: '12' },
          { k: 'tz', label: 'Time zone', type: 'select', opts: TZ.map(z => [z, z.replace('_', ' ')]), def: 'America/Chicago' } ] },
        { title: 'Display', fields: [
          { k: 'showCodes', label: 'Show raw protocol codes', type: 'toggle', def: false, help: 'Adds hub codes (<code>as</code>, <code>dt</code>…) next to labels.' },
          { k: 'alarmSound', label: 'Play a sound on alarms in this browser', type: 'toggle', def: true },
          { k: 'kiosk', label: 'Wall-tablet mode', type: 'toggle', def: false, planned: 'ui.kiosk' } ] },
      ] },
    { id: 'system', title: 'System', icon: 'chip', status: 'ok', groups: [
        { title: 'Data', fields: [
          { k: 'retention', label: 'Keep event history for', type: 'number', min: 7, max: 3650, unit: 'days', def: 365 },
          { k: 'rawLog', label: 'Keep raw hub messages', type: 'toggle', def: true, help: 'Stored with each event; owners can open them in Activity. Redact before sharing (SIM ICCID, SSID, MAC).' } ],
          actions: [{ label: 'Download event history', act: 'downloadLog', keep: true }] },
        { title: 'Updates', fields: [{ type: 'custom', render: 'updates' },
          { k: 'updates', label: 'Check for updates', type: 'toggle', def: true, help: 'Twice a day, asks the project\'s git server for the newest release tag. Nothing about your home is sent.' }] },
        { title: 'Web address', fields: [
          { k: 'publicUrl', label: 'Address of this dashboard', type: 'url', ph: 'https://192.168.1.10:8443', def: '', help: 'Used for links in emails (alerts and password resets). Set automatically during setup; change it if you reach OpenRoost by another name.' } ] },
        { title: 'Protocol log', fields: [{ type: 'custom', render: 'wirelink' },
          { k: 'wireFile', label: 'Also save it to a file', type: 'toggle', def: false, help: 'Appends every entry to <code>data/wire.jsonl</code> (rotates at 20 MB): follow it with <code>sudo tail -f data/wire.jsonl</code>. Contains your hub\'s ID, SIM number and Wi-Fi name: redact before sharing.' }] },
        { title: 'Backup', fields: [{ type: 'custom', render: 'backup' }] },
        { title: 'Audit log', fields: [{ type: 'custom', render: 'audit' }] },
        { title: 'About', fields: [{ type: 'custom', render: 'about' }] },
      ] },
  ];
  const STATUS = { ok: 'Works now', planned: 'Planned, unsupported' };
  const badge = st => `<span class="badge badge-${st === 'planned' ? 'blocked' : st}">${STATUS[st] || st}</span>`;

  function defaultSettings() {
    const d = {};
    SECTIONS.forEach(sec => sec.groups.forEach(g => g.fields.forEach(f => { if (f.k && !f.nosave && f.type !== 'password') d[f.k] = f.def; })));
    d.routing = { intrusion: [1, 1, 1, 1], fire: [1, 1, 1, 1], panic: [1, 1, 1, 1], duress: [1, 0, 1, 0], leak: [1, 1, 1, 1], climate: [1, 0, 0, 1], lowbat: [1, 0, 0, 0], missing: [1, 0, 0, 0], offline: [1, 1, 1, 0], armchange: [0, 1, 0, 1] };
    d.esc = { intrusion: { on: true, secs: 60 }, fire: { on: true, secs: 120 }, duress: { on: true, secs: 60 }, room: true, responders: [] };
    return d;
  }
  Object.assign(S.settings, defaultSettings(), { ph: newPihole(), mail: Object.assign(newMail(), { mode: 'off' }) });

  const TOP_SECRETS = ['hookSecret', 'mxToken', 'ssoSecret'], NESTED_SECRETS = { ph: ['pass'], mail: ['pass', 'key'] };
  const settingKeys = () => [...new Set([...SECTIONS.flatMap(x => x.groups.flatMap(g => g.fields)).filter(f => f.k && !f.nosave).map(f => f.k), 'siteName', 'tempUnit', 'ph', 'mail', 'routing', 'esc'])];
  const stripPrivate = o => JSON.parse(JSON.stringify(o, (k, v) => (k.startsWith('_') ? undefined : v)));
  let saving = Promise.resolve(), pendingClear = [];
  function persist() {
    saving = saving.catch(() => {}).then(async () => {
      if (!SV_STATE.user) return;
      if (!isOwner()) { const e = new Error('Only owners can change settings'); toast(e.message, 'err'); throw e; }
      const out = {};
      settingKeys().forEach(k => { if (S.settings[k] !== undefined) out[k] = S.settings[k]; });
      Object.assign(out, { contacts: S.contacts, rooms: S.rooms });
      const clear = pendingClear; pendingClear = [];
      try {
        const r = await api('PUT', '/settings', { settings: stripPrivate(out), clear });
        SV_STATE.secretsSet = r.secretsSet;
        TOP_SECRETS.forEach(k => { S.settings[k] = ''; });
        Object.entries(NESTED_SECRETS).forEach(([o, ks]) => ks.forEach(k => { if (S.settings[o]) S.settings[o][k] = ''; }));
      } catch (e) { pendingClear = clear.concat(pendingClear); toast(esc(e.message), 'err', 6000); throw e; }
    });
    return saving;
  }
  async function loadSettings() {
    const r = await api('GET', '/settings');
    SV_STATE.secretsSet = r.secretsSet; SV_STATE.role = r.role;
    Object.entries(r.settings).forEach(([k, v]) => {
      if (k === 'contacts') S.contacts = v; else if (k === 'rooms') S.rooms = v; else if (k === 'sensorMeta') return;
      else if (v && typeof v === 'object' && !Array.isArray(v) && S.settings[k] && typeof S.settings[k] === 'object' && k !== 'routing') S.settings[k] = Object.assign({}, S.settings[k], v);
      else S.settings[k] = v;
    });
    applyLook(); emit();
  }
  function applyLook() {
    const r = document.documentElement, st = S.settings;
    if (st.theme && st.theme !== 'system') r.dataset.theme = st.theme; else delete r.dataset.theme;
    if (st.accent) r.style.setProperty('--accent', st.accent); else r.style.removeProperty('--accent');
    r.dataset.density = st.density || 'comfy';
    r.dataset.codes = st.showCodes ? '1' : '0';
  }

  // ---------- generic field renderer ----------
  function fieldHTML(f, v) {
    const id = 'f_' + f.k, ns = f.nosave ? ' data-nosave' : '';
    let c = '';
    switch (f.type) {
      case 'password':
        c = `<input class="in" id="${id}" type="password" data-k="${f.k}"${ns} value="" placeholder="${!f.nosave && hasSecret(f.k) ? 'Saved · type to replace' : esc(f.ph || '')}" autocomplete="${f.nosave ? 'current-password' : 'new-password'}">`; break;
      case 'text': case 'email': case 'url':
        c = `<input class="in" id="${id}" type="${f.type}" data-k="${f.k}"${ns} value="${esc(v)}" placeholder="${esc(f.ph || '')}" autocomplete="off">`; break;
      case 'number':
        c = `<span class="in-unit"><input class="in in-num" id="${id}" type="number" data-k="${f.k}" value="${esc(v)}" ${f.min != null ? `min="${f.min}"` : ''} ${f.max != null ? `max="${f.max}"` : ''}>${f.unit ? `<span class="unit">${f.unit}</span>` : ''}</span>`; break;
      case 'textarea':
        c = `<textarea class="in" id="${id}" rows="3" data-k="${f.k}" placeholder="${esc(f.ph || '')}">${esc(v)}</textarea>`; break;
      case 'select':
        c = `<select class="in" id="${id}" data-k="${f.k}">${f.opts.map(([val, l]) => `<option value="${val}"${val == v ? ' selected' : ''}>${esc(l)}</option>`).join('')}</select>`; break;
      case 'toggle':
        c = `<label class="sw"><input type="checkbox" id="${id}" data-k="${f.k}"${v ? ' checked' : ''}><span class="sw-t" aria-hidden="true"></span><span class="sr">${esc(f.label)}</span></label>`; break;
      case 'range':
        c = `<span class="rng"><input type="range" id="${id}" data-k="${f.k}" min="${f.min}" max="${f.max}" step="${f.step || 1}" value="${v}"><output>${v} ${f.unit}</output></span>`; break;
      case 'segmented':
        c = `<span class="seg" role="radiogroup">${f.opts.map(([val, l]) => `<label><input type="radio" name="${id}" data-k="${f.k}" value="${val}"${val == v ? ' checked' : ''}><span>${esc(l)}</span></label>`).join('')}</span>`; break;
      case 'swatches':
        c = `<span class="swatches"><input type="hidden" data-k="${f.k}" value="${esc(v)}"><button type="button" class="swatch swatch-none${!v ? ' on' : ''}" data-v="" title="Design default">↺</button>${f.opts.map(col => `<button type="button" class="swatch${col === v ? ' on' : ''}" data-v="${col}" style="--sw:${col}" title="${col}"></button>`).join('')}</span>`; break;
    }
    return `<div class="f f-${f.type}"><div class="f-text"><label class="f-label" for="${id}">${esc(f.label)}</label>${f.help ? `<div class="f-help">${f.help}</div>` : ''}</div><div class="f-ctl">${c}</div></div>`;
  }

  function renderSettings(el, secId) {
    const sec = SECTIONS.find(s => s.id === secId);
    const secPlanned = sec.feature && isPlanned(sec.feature);
    el.innerHTML = `<header class="sec-head"><h2 class="sec-title">${sec.title}</h2>${badge(secPlanned ? 'planned' : sec.status)}</header>
      ${sec.note ? `<div class="note${secPlanned ? ' note-blocked' : ''}">${sec.note}</div>` : ''}
      ${sec.groups.map(g => {
        const gp = g.planned && isPlanned(g.planned);
        return `<section class="group"><h3 class="group-title">${g.title}</h3><div class="group-body"${gp ? plannedAttrs(g.planned) : ''}>${g.fields.map(f => f.type === 'custom' ? `<div class="custom" data-custom="${f.render}"></div>`
          : f.planned && isPlanned(f.planned) ? `<div class="f-planned"${plannedAttrs(f.planned)}>${fieldHTML(f, S.settings[f.k])}</div>` : fieldHTML(f, S.settings[f.k])).join('')}</div>
        ${g.actions ? `<div class="group-actions">${g.actions.map(a => `<button type="button" class="btn${a.kind === 'danger' ? ' btn-danger' : ''}" data-act="${a.act}"${a.keep ? ' data-keep' : ''}>${a.label}</button>`).join('')}</div>` : ''}</section>`;
      }).join('')}
      ${secPlanned ? '' : `<div class="save-bar"><span class="save-hint">Saved on the OpenRoost server</span>
        <button type="button" class="btn" data-revert>Revert</button><button type="button" class="btn btn-primary" data-save>Save changes</button></div>`}`;
    el.querySelectorAll('[data-planned] input, [data-planned] select, [data-planned] textarea, [data-planned] button').forEach(i => { i.disabled = true; i.tabIndex = -1; });
    el.querySelectorAll('[data-custom]').forEach(c => CUSTOM[c.dataset.custom](c));
    el.querySelectorAll('.rng input').forEach(r => r.addEventListener('input', () => { r.nextElementSibling.textContent = r.value + ' ' + (sec.groups.flatMap(g => g.fields).find(f => f.k === r.dataset.k)?.unit || ''); }));
    el.querySelectorAll('.swatches').forEach(w => w.addEventListener('click', e => { const b = e.target.closest('.swatch'); if (!b) return; w.querySelector('input').value = b.dataset.v; w.querySelectorAll('.swatch').forEach(x => x.classList.toggle('on', x === b)); }));
    el.querySelectorAll('[data-act]').forEach(b => b.addEventListener('click', () => ACTIONS[b.dataset.act](b, el)));
    el.querySelector('[data-revert]')?.addEventListener('click', () => { renderSettings(el, secId); toast('Reverted', 'info'); });
    el.querySelector('[data-save]')?.addEventListener('click', () => {
      el.querySelectorAll('[data-k]:not([data-nosave])').forEach(i => {
        if (i.closest('[data-planned]')) return;
        if (i.type === 'radio') { if (i.checked) S.settings[i.dataset.k] = i.value; }
        else if (i.type === 'checkbox') S.settings[i.dataset.k] = i.checked;
        else if (i.type === 'number' || i.type === 'range') S.settings[i.dataset.k] = Number(i.value);
        else S.settings[i.dataset.k] = i.value;
      });
      el.querySelectorAll('[data-mx]').forEach(i => { const [r, c] = i.dataset.mx.split(':'); (S.settings.routing[r] ||= [0, 0, 0, 0])[+c] = i.checked ? 1 : 0; });
      const saveBtn = el.querySelector('[data-save]'); saveBtn.disabled = true;
      persist().then(() => { applyLook(); emit(); renderSettings(el, secId); toast('Settings saved'); }, () => { saveBtn.disabled = false; });
    });
    if (!isOwner()) {
      el.querySelector('.save-bar')?.remove(); el.querySelectorAll('input,select,textarea,.btn:not([data-keep])').forEach(i => { if (!i.closest('[data-custom=profile],[data-custom=totp],[data-custom=sessions]')) i.disabled = true; });
      el.querySelector('.sec-head').insertAdjacentHTML('afterend', `<div class="note">${icon('lock')} <span>Only owners can change these settings. You're signed in as a ${esc(SV_STATE.role)}.</span></div>`);
    }
  }

  // ---------- custom settings widgets ----------
  const CUSTOM = {
    piholeSvc: el => serviceSettings(el, 'pihole'),
    mailSvc: el => serviceSettings(el, 'mail'),
    pins(el) {
      el.innerHTML = `<div class="pins"${plannedAttrs('hub.pins')}>
        <div class="pin-row"><div class="pin-who"><div class="pin-name">Owner PIN <code class="code">da:"ow"</code></div><div class="f-help">Arms and disarms at the keypad.</div></div><div class="pin-val"><span class="pin-digits">••••</span><button type="button" class="btn">Change</button></div></div>
        <div class="pin-row"><div class="pin-who"><div class="pin-name">Hostage (duress) PIN <code class="code">da:"ho"</code></div><div class="f-help">Disarms normally but silently alerts your contacts.</div></div><div class="pin-val"><span class="pin-digits">••••</span><button type="button" class="btn">Change</button></div></div>
        <div class="pin-guests"><div class="pin-name">Guest PINs <code class="code">da:"gu"</code></div><button type="button" class="btn">${icon('plus')} Add guest</button></div></div>
        <div class="f-help" style="margin-top:8px">OpenRoost still sees which PIN disarmed the system (owner, guest or hostage) and alerts on hostage.</div>`;
    },
    alertmodes(el) {
      const cols = [[1, 'Always'], [2, 'Home'], [4, 'Away']];
      mount(el, () => {
        el.innerHTML = `<div class="f-help" style="margin-bottom:.5rem">Which arm states make each sensor trigger, as reported by the hub (<code>dj.as</code>: 1 = always, 2 = Home, 4 = Away).</div>
          <div class="mx-wrap"${plannedAttrs('sensors.alertMode')}><table class="mx"><thead><tr><th>Sensor</th>${cols.map(c => `<th>${c[1]}</th>`).join('')}</tr></thead><tbody>
          ${S.sensors.map(s => `<tr><td>${icon(TYPE_ICON[s.type] || 'chip')} ${esc(s.name)}</td>${cols.map(([b]) => `<td><input type="checkbox" disabled${s.as & b ? ' checked' : ''} aria-label="${esc(s.name)} ${b}"></td>`).join('')}</tr>`).join('') || '<tr><td colspan="4" class="f-help">No sensors yet.</td></tr>'}</tbody></table></div>`;
      });
    },
    matrix(el) {
      const rows = [['intrusion', 'Intrusion alarm'], ['fire', 'Fire'], ['panic', 'Panic'], ['duress', 'Duress (hostage PIN)'], ['leak', 'Water leak'], ['climate', 'Temperature / humidity'], ['lowbat', 'Low battery'], ['missing', 'Sensor missing'], ['offline', 'Hub offline'], ['armchange', 'Armed / disarmed']];
      const R = S.settings.routing || {};
      const cols = ['Email', 'Push', 'Matrix', 'Webhook'];
      el.innerHTML = `<div class="f-help" style="margin-bottom:.5rem">Household channels. Emergency contacts above have their own tiers.</div><div class="mx-scroll"><table class="mx"><thead><tr><th>Event</th>${cols.map(c => `<th>${c}</th>`).join('')}</tr></thead><tbody>
        ${rows.map(([k, l]) => `<tr><td>${l}</td>${cols.map((c, i) => `<td><input type="checkbox" data-mx="${k}:${i}"${(R[k] || [])[i] ? ' checked' : ''} aria-label="${l} ${c}"></td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
    },
    mxlogin(el) {
      el.innerHTML = `<div class="f"><div class="f-text"><span class="f-label">Bot sign-in</span><div class="f-help">${hasSecret('mxToken') ? 'Signed in: an access token is stored (encrypted).' : 'Not signed in yet.'} OpenRoost keeps only the access token, never the password.</div></div>
        <div class="f-ctl"><form class="su-row" data-mxl><input class="in" type="password" name="p" placeholder="Bot account password" autocomplete="off" data-nosave required style="flex:1;min-width:140px"><button class="btn btn-sm">${hasSecret('mxToken') ? 'Sign in again' : 'Sign bot in'}</button></form></div></div>`;
      el.querySelector('[data-mxl]').addEventListener('submit', async e => {
        e.preventDefault(); const f = e.target;
        try {
          if (!S.settings.mxHs || !S.settings.mxUser) throw new Error('Save the homeserver and bot account first');
          const r = await api('POST', '/notify/matrix/login', { password: f.elements.p.value }); SV_STATE.secretsSet = r.secretsSet; f.reset(); CUSTOM.mxlogin(el);
          toast(r.note ? 'Bot signed in. ' + esc(r.note) : 'Bot signed in, encryption keys set up', r.note ? 'warn' : 'ok', r.note ? 9000 : 3000);
          document.querySelectorAll('[data-mxe2ee]').forEach(x => CUSTOM.mxe2ee(x));
        } catch (err) { toast(esc(err.message), 'err', 6000); }
      });
    },
    mxe2ee(el) {
      el.dataset.mxe2ee = '1';
      el.innerHTML = '<div class="f-help">Checking encryption…</div>';
      api('GET', '/notify/matrix/e2ee').then(e => {
        el.innerHTML = `<div class="f"><div class="f-text"><span class="f-label">End-to-end encryption</span><div class="f-help">${
          !e.available ? 'Not available on this server: install <code>vodozemac</code> (it\'s in the Docker image). Unencrypted rooms still work.'
          : !e.ready ? 'Sign the bot in (above) to set up its encryption keys.'
          : `Ready. Bot device <code>${esc(e.device)}</code>${e.crossSigned ? ', verified by the bot\'s own account (cross-signed)' : ', <b>not cross-signed</b>: sign in again to fix'}. Device fingerprint (to compare in Element): <code class="sd-mono" style="word-break:break-all">${esc(e.fingerprint.match(/.{1,4}/g).join(' '))}</code>`}</div></div></div>`;
      }).catch(err => { el.innerHTML = `<div class="f-help">${esc(err.message)}</div>`; });
    },
    profile(el) {
      const u = SV_STATE.user;
      el.innerHTML = `<form class="su-card" data-prof><div class="su-f"><span>Username</span><span><b>${esc(u.username)}</b> <span class="f-help">· ${esc(u.role)} · used to sign in, can't be changed</span></span></div>
        <label class="su-f"><span>Display name</span><input class="in" name="d" value="${esc(u.display)}" maxlength="80" required data-nosave></label>
        <label class="su-f"><span>Email</span><input class="in" name="e" type="email" value="${esc(u.email || '')}" placeholder="you@example.com" data-nosave></label>
        <div class="su-row"><button class="btn btn-sm" data-keep>Save profile</button></div></form>`;
      el.querySelector('[data-prof]').addEventListener('submit', async e => {
        e.preventDefault(); const f = e.target;
        try { SV_STATE.user = (await api('PATCH', '/me', { display: f.elements.d.value, email: f.elements.e.value })).user; toast('Profile saved'); }
        catch (err) { toast(esc(err.message), 'err'); }
      });
    },
    totp(el) {
      const u = SV_STATE.user;
      if (u.sso) { el.innerHTML = '<div class="f-help">You sign in through Authentik, which handles two-factor for you.</div>'; return; }
      if (u.totp) {
        el.innerHTML = `<div class="su-chk ok su-chk-tight"><span class="st">${icon('check')}</span><div><b>On</b><small>Sign-in asks for a code from your authenticator app.</small></div></div>
          <form class="su-row" data-off><input class="in" type="password" name="p" placeholder="Your password" required autocomplete="current-password" data-nosave style="flex:1;min-width:140px"><button class="btn btn-sm btn-danger" data-keep>Turn off</button></form>`;
        el.querySelector('[data-off]').addEventListener('submit', async e => {
          e.preventDefault();
          try { await api('POST', '/me/totp/disable', { password: e.target.elements.p.value }); SV_STATE.user = (await api('GET', '/me')).user; CUSTOM.totp(el); toast('Two-factor sign-in turned off'); }
          catch (err) { toast(esc(err.message), 'err'); }
        });
        return;
      }
      el.innerHTML = `<div class="f-help">Adds a 6-digit code from an authenticator app (Aegis, 2FAS, Google Authenticator, 1Password…) to sign-in.</div><div class="su-row" style="margin-top:8px"><button type="button" class="btn btn-sm" data-keep data-start>Set up two-factor sign-in</button></div>`;
      el.querySelector('[data-start]').addEventListener('click', async () => {
        try {
          const r = await api('POST', '/me/totp/setup');
          el.innerHTML = `<ol class="steps"><li>In your authenticator app, add an account with this key, or open the link on your phone:</li></ol>
            <div class="sso-box"><div class="copy"><code>${esc(r.secret.replace(/(.{4})/g, '$1 ').trim())}</code></div><a href="${esc(r.uri)}" class="f-help">Open in authenticator app</a></div>
            <form class="su-row" data-en style="margin-top:10px"><input class="in" name="c" inputmode="numeric" maxlength="6" placeholder="6-digit code" required autocomplete="one-time-code" data-nosave style="width:140px"><button class="btn btn-sm btn-primary" data-keep>Turn on</button></form>
            <div class="f-help">Turning it on signs out your other browsers and devices.</div>`;
          el.querySelector('[data-en]').addEventListener('submit', async e => {
            e.preventDefault();
            try { await api('POST', '/me/totp/enable', { code: e.target.elements.c.value }); SV_STATE.user = (await api('GET', '/me')).user; CUSTOM.totp(el); toast('Two-factor sign-in is on'); }
            catch (err) { toast(esc(err.message), 'err'); }
          });
        } catch (err) { toast(esc(err.message), 'err'); }
      });
    },
    async sessions(el) {
      el.innerHTML = '<div class="scan-wait"><span class="spin"></span> Loading…</div>';
      const draw = async () => {
        const list = (await api('GET', '/me/sessions')).sessions;
        el.innerHTML = list.map(x => `<div class="list-row"><div><div>${x.kind === 'device' ? icon('chip') + ' ' + esc(x.name || 'App device') : esc(x.ua.replace(/\s*\(.*?\)\s*/g, ' ').slice(0, 60) || 'Unknown browser')} ${x.current ? '<span class="badge badge-ok">This device</span>' : ''}</div>
            <div class="f-help">${esc(x.ip)} · signed in ${ago(x.created * 1000)} · last used ${ago(x.last_seen * 1000)}</div></div>
            ${x.current ? '' : `<button type="button" class="btn" data-keep data-rv="${esc(x.id)}">Sign out</button>`}</div>`).join('') || '<div class="f-help">No sessions.</div>';
        el.querySelectorAll('[data-rv]').forEach(b => b.addEventListener('click', async () => { try { await api('DELETE', '/me/sessions/' + b.dataset.rv); toast('Signed out that device'); draw(); } catch (e) { toast(esc(e.message), 'err'); } }));
      };
      draw().catch(e => { el.innerHTML = `<div class="f-help">${esc(e.message)}</div>`; });
    },
    async users(el) {
      if (!isOwner()) { el.innerHTML = '<div class="f-help">Only owners can manage household members.</div>'; return; }
      const draw = async () => {
        const list = (await api('GET', '/users')).users, me = SV_STATE.user.id;
        el.innerHTML = list.map(u => `<div class="list-row" data-uid="${u.id}"><div><div>${esc(u.display)}${u.id === me ? ' <span class="badge badge-ok">You</span>' : ''}${u.totp ? ' <span class="badge badge-ok">2FA</span>' : ''}${u.sso ? ' <span class="badge badge-cosmetic">SSO</span>' : ''}</div><div class="f-help">@${esc(u.username)}</div></div>
            <div class="su-row"><select class="in in-sm" data-role data-keep aria-label="Role for ${esc(u.username)}"${u.id === me ? ' disabled' : ''}>${['owner', 'member', 'viewer'].map(r => `<option value="${r}"${r === u.role ? ' selected' : ''}>${r[0].toUpperCase() + r.slice(1)}</option>`).join('')}</select>
            ${u.id === me ? '' : `<button type="button" class="btn btn-sm" data-keep data-reset>Reset password</button>${u.totp ? '<button type="button" class="btn btn-sm" data-keep data-totp>Reset 2FA</button>' : ''}<button type="button" class="btn btn-sm btn-danger" data-keep data-del>Remove</button>`}</div></div>`).join('')
          + `<div class="f-help" style="margin:.5rem 0">Owners change settings and members. Members can acknowledge alarms (and arm and disarm, once that's supported). Viewers only see status and history. Separate from keypad PINs.</div>
          <form class="su-card" data-add><div class="eyebrow su-eyebrow">Add a household member</div>
            <label class="su-f"><span>Username</span><input class="in" name="u" required pattern="[A-Za-z0-9._-]{3,32}" autocomplete="off" data-nosave></label>
            <label class="su-f"><span>Name</span><input class="in" name="d" maxlength="80" data-nosave></label>
            <label class="su-f"><span>Role</span><select class="in" name="r" data-nosave><option value="member">Member</option><option value="viewer">Viewer</option><option value="owner">Owner</option></select></label>
            <label class="su-f"><span>Temporary password</span><input class="in" name="p" type="password" minlength="12" required autocomplete="new-password" data-nosave></label>
            <span class="f-help su-help">At least 12 characters. Give it to them in person; they can change it under Account.</span>
            <div class="su-row"><button class="btn btn-primary btn-sm" data-keep>${icon('plus')} Add member</button></div></form>
          <form class="su-card" data-inv><div class="eyebrow su-eyebrow">Or invite them with a link</div>
            <div class="f-help su-help">They choose their own username and password. The link works once.</div>
            <label class="su-f"><span>Role</span><select class="in" name="r" data-nosave><option value="member">Member</option><option value="viewer">Viewer</option><option value="owner">Owner</option></select></label>
            <label class="su-f"><span>Expires after</span><select class="in" name="h" data-nosave><option value="24">1 day</option><option value="72" selected>3 days</option><option value="168">7 days</option></select></label>
            <label class="su-f"><span>Email it to</span><input class="in" name="e" type="email" placeholder="Optional: they@example.com" data-nosave></label>
            <label class="su-f"><span>Note</span><input class="in" name="n" maxlength="80" placeholder="Optional, e.g. Grandma" data-nosave></label>
            <div class="su-row"><button class="btn btn-sm btn-primary" data-keep>${icon('link')} Create invite link</button></div><div data-invout></div></form>
          <div data-invlist></div>`;
        const row = b => +b.closest('[data-uid]').dataset.uid;
        el.querySelectorAll('[data-role]').forEach(sel => sel.addEventListener('change', async () => {
          try { await api('PATCH', '/users/' + row(sel), { role: sel.value }); toast('Role changed. They\'ll be signed out to pick it up.'); } catch (e) { toast(esc(e.message), 'err'); draw(); }
        }));
        el.querySelectorAll('[data-del]').forEach(b => b.addEventListener('click', async () => {
          if (b.dataset.armed !== '1') { b.dataset.armed = '1'; b.textContent = 'Click again to remove'; setTimeout(() => { b.dataset.armed = ''; b.textContent = 'Remove'; }, 4000); return; }
          try { await api('DELETE', '/users/' + row(b)); toast('Member removed'); draw(); } catch (e) { toast(esc(e.message), 'err'); }
        }));
        el.querySelectorAll('[data-totp]').forEach(b => b.addEventListener('click', async () => { try { await api('POST', `/users/${row(b)}/totp/reset`); toast('Two-factor turned off for them'); draw(); } catch (e) { toast(esc(e.message), 'err'); } }));
        el.querySelectorAll('[data-reset]').forEach(b => b.addEventListener('click', () => {
          const r = b.closest('.list-row'); if (r.nextElementSibling?.matches('[data-resetform]')) return;
          r.insertAdjacentHTML('afterend', `<form class="su-row" data-resetform style="padding:8px 0"><input class="in" type="password" name="p" minlength="12" required placeholder="New temporary password (12+)" autocomplete="new-password" data-nosave style="flex:1"><button class="btn btn-sm btn-primary" data-keep>Set password</button></form>`);
          const f = r.nextElementSibling; f.elements.p.focus();
          f.addEventListener('submit', async e => { e.preventDefault(); try { await api('POST', `/users/${row(b)}/password`, { password: f.elements.p.value }); toast('Password reset; they were signed out'); f.remove(); } catch (err) { toast(esc(err.message), 'err'); } });
        }));
        const invList = async () => {
          const box = el.querySelector('[data-invlist]'), inv = (await api('GET', '/users/invites')).invites;
          box.innerHTML = inv.length ? `<div class="eyebrow su-eyebrow" style="margin-top:12px">Pending invites</div>` + inv.map(i => `<div class="list-row"><div><div>${esc(i.note || i.email || 'Invite')} <span class="badge">${esc(i.role)}</span></div>
            <div class="f-help">by @${esc(i.by)} · expires ${new Date(i.exp * 1000).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })}${i.email ? ' · sent to ' + esc(i.email) : ''}</div></div>
            <button type="button" class="btn btn-sm btn-danger" data-keep data-revoke="${esc(i.id)}">Revoke</button></div>`).join('') : '';
          box.querySelectorAll('[data-revoke]').forEach(b => b.addEventListener('click', async () => { try { await api('DELETE', '/users/invites/' + b.dataset.revoke); toast('Invite revoked'); invList(); } catch (err) { toast(esc(err.message), 'err'); } }));
        };
        invList().catch(() => {});
        el.querySelector('[data-inv]').addEventListener('submit', async e => {
          e.preventDefault(); const f = e.target, out = f.querySelector('[data-invout]');
          const showLink = (link, msg) => { out.innerHTML = `<div class="note" style="margin-top:8px">${icon('link')} <span>${msg}<br><code class="sd-mono" style="word-break:break-all">${esc(link)}</code><br><button type="button" class="btn btn-sm" data-keep data-copy="${esc(link)}" style="margin-top:6px">Copy link</button></span></div>`; bindCopy(out); };
          try {
            const r = await api('POST', '/users/invites', { role: f.elements.r.value, hours: +f.elements.h.value, email: f.elements.e.value.trim(), note: f.elements.n.value.trim() });
            showLink(r.link, r.emailed ? `Emailed to ${esc(f.elements.e.value.trim())}. You can also share it yourself; it's shown only now:` : 'Share this link with them. It\'s shown only now:');
            f.elements.e.value = ''; f.elements.n.value = ''; invList();
          } catch (err) { if (err.data?.link) { showLink(err.data.link, esc(err.message)); invList(); } else toast(esc(err.message), 'err', 6000); }
        });
        el.querySelector('[data-add]').addEventListener('submit', async e => {
          e.preventDefault(); const f = e.target;
          try { await api('POST', '/users', { username: f.elements.u.value, display: f.elements.d.value, role: f.elements.r.value, password: f.elements.p.value }); toast('Member added'); draw(); }
          catch (err) { toast(esc(err.message), 'err', 6000); }
        });
      };
      draw().catch(e => { el.innerHTML = `<div class="f-help">${esc(e.message)}</div>`; });
    },
    hubinfo(el) {
      mount(el, () => {
        const h = S.hub;
        if (!h.id) { el.innerHTML = '<div class="f-help">No hub has connected yet.</div>'; return; }
        const rows = [['Status', h.online ? `Online · connected ${uptime()}` : `Offline · last seen ${ago(h.lastSeen)}`, ''], ['Device id', 'z••••••••' + h.id.slice(-4), 'id'], ['Address', h.ip || '—', ''],
          ['Claimed', h.claimed ? (h.claimed === h.id ? 'Yes — other devices are refused' : 'A different hub is claimed') : 'Not yet', ''], ['Power', h.pw == null ? '—' : h.pw ? 'Mains' : 'Battery (events wait until it reconnects)', 'pw'],
          ['Backup battery', h.bat != null ? h.bat + ' mV' : '—', 'bat'], ['Wi-Fi', h.ss != null ? `${h.ss} · ch ${h.wc} · ${h.rs} dBm` : '—', 'ss/wc/rs'], ['Cellular', h.cs == null ? '—' : h.cs === 99 ? 'No signal / no plan' : h.cs, 'cs'],
          ['Climate', h.temp != null ? `${temp(h.temp)} · ${h.hum}%` : '—', 'cl'], ['Hub firmware', h.bfw || '—', 'bfw'], ['Wi-Fi module', h.wfw || '—', 'wfw'], ['Sub-GHz radio', h.sfw || '—', 'sfw'],
          ['LTE modem', h.cfw || '—', 'cfw'], ['Hardware', h.hw || '—', 'hw'], ['Cert bundle', h.cv || '—', 'cv']];
        el.innerHTML = `<dl class="kv">${rows.map(([k, v, c]) => `<div><dt>${k}${c ? ` <code class="code">${c}</code>` : ''}</dt><dd>${esc(v)}</dd></div>`).join('')}</dl>
          ${isOwner() && h.id && h.claimed !== h.id ? `<div class="group-actions"><button type="button" class="btn btn-sm" data-claim>Trust this hub</button></div>` : ''}`;
        el.querySelector('[data-claim]')?.addEventListener('click', async () => { try { S.hub = toHub(await api('POST', '/hub/claim')); emit(); toast('Hub trusted. Other devices claiming to be a hub are refused.'); } catch (e) { toast(esc(e.message), 'err'); } });
      });
    },
    wifi(el) {
      el.innerHTML = `<div${plannedAttrs('hub.wifi')}><div class="f-help">Uses the hub's own setup network (<code>scan</code> and <code>provision</code> are decoded; provisioning is untested and needs a device that can join the hub's network).</div>
        <div class="group-actions"><button type="button" class="btn btn-primary">${icon('wifi')} Scan for networks</button></div></div>`;
    },
    contacts(el) {
      const tiers = [['distress', 'Distress', 'Panic button, hostage PIN, fire'], ['alarms', 'Alarms', 'Intrusion, water leak'], ['info', 'Everything', 'Arming, low battery, hub offline…']];
      const draw = () => {
        el.innerHTML = `<div class="f-help" style="margin-bottom:.6rem">People outside the household channels who should hear about trouble. <b>Distress</b> messages go by email <i>and</i> Matrix DM and ignore quiet hours. Saved with <b>Save changes</b>.</div>
          <div class="mx-scroll"><table class="mx contacts"><thead><tr><th>Contact</th>${tiers.map(([, l, t]) => `<th title="${t}">${l}</th>`).join('')}<th></th></tr></thead><tbody>
          ${S.contacts.map(c => `<tr><td><div class="c-name">${esc(c.name)}</div><div class="f-help">${[c.email && icon('mail') + ' ' + esc(c.email), c.mx && '<span class="mx-id">[m]</span> ' + esc(c.mx)].filter(Boolean).join(' &nbsp; ')}</div></td>
            ${tiers.map(([k, l]) => `<td><input type="checkbox" data-ct="${c.id}:${k}"${c.tiers?.[k] ? ' checked' : ''} aria-label="${esc(c.name)} ${l}"></td>`).join('')}
            <td><button type="button" class="btn btn-icon" data-cdel="${c.id}" title="Remove ${esc(c.name)}">${icon('trash')}</button></td></tr>`).join('') || `<tr><td colspan="5" class="f-help">No contacts yet.</td></tr>`}</tbody></table></div>
          <form class="contact-add"><input class="in" name="n" placeholder="Name" required maxlength="80" data-nosave><input class="in" name="e" type="email" placeholder="Email" data-nosave><input class="in" name="m" placeholder="@user:matrix.org" data-nosave><button class="btn">${icon('plus')} Add</button></form>
          <div class="group-actions"><button type="button" class="btn" data-ctest>Email a test to every contact</button></div>`;
        el.querySelectorAll('[data-ct]').forEach(i => i.addEventListener('change', () => { const [id, k] = i.dataset.ct.split(':'); const c = S.contacts.find(x => x.id == id); (c.tiers ||= {})[k] = i.checked ? 1 : 0; }));
        el.querySelectorAll('[data-cdel]').forEach(b => b.addEventListener('click', () => { S.contacts = S.contacts.filter(c => c.id != b.dataset.cdel); draw(); toast('Contact removed — Save changes to keep it', 'info'); }));
        el.querySelector('.contact-add').addEventListener('submit', e => {
          e.preventDefault(); const f = e.target, mx = f.elements.m.value.trim(), em = f.elements.e.value.trim();
          if (!em && !mx) return toast('Add an email or a Matrix ID', 'err');
          if (mx && !/^@[^:\s]+:[^\s]+$/.test(mx)) return toast('Matrix IDs look like <code>@name:server.org</code>', 'err');
          S.contacts.push({ id: now(), name: f.elements.n.value.trim(), email: em, mx, tiers: { distress: 1, alarms: 1, info: 0 } }); draw(); toast('Contact added — Save changes to keep it');
        });
        el.querySelector('[data-ctest]').addEventListener('click', e => busy(e.currentTarget, async () => {
          const list = S.contacts.filter(c => c.email); if (!list.length) return toast('No contacts with an email address', 'err');
          let ok = 0; for (const c of list) { try { await api('POST', '/notify/test/email', { to: c.email }); ok++; } catch (err) { toast(`${esc(c.email)}: ${esc(err.message)}`, 'err', 6000); } }
          if (ok) toast(`Test email sent to ${ok} contact${ok === 1 ? '' : 's'}`);
        }));
      };
      draw();
    },
    escalation(el) {
      const KINDS = [['intrusion', 'Break-in', 'Alarm sounding while armed'], ['fire', 'Fire alarm', 'The smoke listener hears an alarm'], ['duress', 'Distress PIN used', 'Disarmed with the hostage PIN']];
      const draw = () => {
        const e = S.settings.esc || (S.settings.esc = { room: true, responders: [] });
        e.responders ||= [];
        el.innerHTML = `<div class="f-help" style="margin-bottom:.6rem">When one of these alarms goes off, the people below are warned first and get a few seconds to cancel before the
            <b>emergency contacts</b> (above) are told. They cancel by replying <b>N</b> on Matrix, with the link in their email, or with <b>Cancel</b> in the app. If nobody cancels in time, the contacts get the alert as usual.
            A countdown only runs if someone below can cancel it and a contact would be told. Saved with <b>Save changes</b>.</div>
          ${KINDS.map(([k, l, d]) => { const c = e[k] ||= { on: true, secs: k === 'fire' ? 120 : 60 }; return `<div class="f"><div class="f-text"><span class="f-label">${l}</span><div class="f-help">${d}</div></div>
            <div class="f-ctl su-row"><span class="in-unit"><input class="in in-num" type="number" min="10" max="600" value="${c.secs}" data-escsecs="${k}" data-nosave aria-label="${l}: seconds to cancel"${c.on ? '' : ' disabled'}><span class="unit">s</span></span>
            <label class="sw"><input type="checkbox" data-escon="${k}"${c.on ? ' checked' : ''} data-nosave><span class="sw-t" aria-hidden="true"></span><span class="sr">${l} countdown</span></label></div></div>`; }).join('')}
          <div class="f"><div class="f-text"><span class="f-label">Also post it in the household room</span><div class="f-help">The Matrix alert room. Only the people below can cancel there.</div></div>
            <div class="f-ctl"><label class="sw"><input type="checkbox" data-escroom${e.room !== false ? ' checked' : ''} data-nosave><span class="sw-t" aria-hidden="true"></span><span class="sr">Post in the household room</span></label></div></div>
          <div class="eyebrow su-eyebrow" style="margin-top:10px">Who is warned and can cancel</div>
          ${e.responders.map(r => `<div class="list-row"><div><div>${esc(r.name || r.email || r.mx)}</div><div class="f-help">${[r.email && icon('mail') + ' ' + esc(r.email), r.mx && '<span class="mx-id">[m]</span> ' + esc(r.mx)].filter(Boolean).join(' · ')}</div></div>
            <button type="button" class="btn btn-icon" data-escdel="${r.id}" title="Remove ${esc(r.name || '')}">${icon('trash')}</button></div>`).join('') || '<div class="f-help">Nobody yet: the countdown is off until you add someone.</div>'}
          <form class="contact-add" data-escadd><input class="in" name="n" placeholder="Name" required maxlength="80" data-nosave><input class="in" name="e" type="email" placeholder="Email (gets a cancel link)" data-nosave><input class="in" name="m" placeholder="@name:server (replies N)" data-nosave><button class="btn">${icon('plus')} Add</button></form>
          <div class="f-help" style="margin-top:6px">${icon('alert')} A distress PIN means someone may be forced to act. Anyone on this list can cancel, so keep it to people who wouldn't be with you, or turn the distress countdown off.</div>`;
        el.querySelectorAll('[data-escsecs]').forEach(i => i.addEventListener('change', () => { const v = Math.max(10, Math.min(600, Math.round(+i.value || 60))); i.value = v; e[i.dataset.escsecs].secs = v; }));
        el.querySelectorAll('[data-escon]').forEach(i => i.addEventListener('change', () => { e[i.dataset.escon].on = i.checked; draw(); }));
        el.querySelector('[data-escroom]').addEventListener('change', ev => { e.room = ev.target.checked; });
        el.querySelectorAll('[data-escdel]').forEach(b => b.addEventListener('click', () => { e.responders = e.responders.filter(r => r.id != b.dataset.escdel); draw(); toast('Removed — Save changes to keep it', 'info'); }));
        el.querySelector('[data-escadd]').addEventListener('submit', ev => {
          ev.preventDefault(); const f = ev.target, mx = f.elements.m.value.trim(), em = f.elements.e.value.trim();
          if (!em && !mx) return toast('Add an email or a Matrix ID', 'err');
          if (mx && !/^@[^:\s]+:[^\s]+$/.test(mx)) return toast('Matrix IDs look like <code>@name:server.org</code>', 'err');
          e.responders.push({ id: now(), name: f.elements.n.value.trim(), email: em, mx }); draw(); toast('Added — Save changes to keep it');
        });
      };
      draw();
    },
    ssoinfo(el) {
      const cb = location.origin + '/api/v1/auth/oidc/callback';
      el.innerHTML = `<div class="sso-box"><div class="f-label">Redirect URI</div><div class="copy"><code>${esc(cb)}</code><button type="button" class="btn btn-icon" data-copy title="Copy" data-keep>${icon('link')}</button></div>
        <details><summary>Authentik setup (2 minutes)</summary><ol class="steps">
          <li><b>Applications → Providers → Create → OAuth2/OpenID Provider.</b> Client type <i>Confidential</i>, paste the redirect URI above, pick a signing key.</li>
          <li><b>Applications → Create</b>: name “OpenRoost”, link the provider.</li>
          <li>Copy the <b>Client ID</b>, <b>Client secret</b> and issuer URL into the fields here.</li>
          <li>Create groups <code>openroost-admins</code> / <code>openroost-members</code> and add your family.</li>
          <li>Press <b>Test connection</b>, save, then try it from a private window before turning off password sign-in.</li></ol></details></div>`;
      el.querySelector('[data-copy]').addEventListener('click', () => { try { navigator.clipboard.writeText(cb); } catch (e) { /* ignore */ } toast('Redirect URI copied'); });
    },
    redirect(el) {
      const draw = (checks, busyNow) => {
        const bad = checks ? checks.filter(c => c.status === 'fail').length : 0;
        el.innerHTML = `<div class="chk-head">${busyNow ? '<span class="spin"></span><b>Checking…</b>' : bad ? `<span class="dot dot-fail"></span><b>${bad} problem${bad > 1 ? 's' : ''}</b>` : '<span class="dot dot-ok"></span><b>Hub traffic reaches this server</b>'}
          <button type="button" class="btn" data-run data-keep ${busyNow ? 'disabled' : ''}>Run checks</button></div>
          <div class="chks">${(checks || []).map(c => `<div class="chk"${c.status === 'planned' ? plannedAttrs('pihole.bundled') : ''}><span class="dot dot-${{ ok: 'ok', fail: 'fail', unknown: 'warn', wait: 'idle', planned: 'idle' }[c.status] || 'idle'}"></span>
            <div><div class="chk-l">${esc(c.title)}</div><div class="f-help">${esc(c.detail)}</div></div>${c.fix && isOwner() ? `<button type="button" class="btn" data-fix="${c.fix}" data-keep>Fix</button>` : '<span></span>'}</div>`).join('')}</div>`;
        el.querySelector('[data-run]').addEventListener('click', run);
        el.querySelectorAll('[data-fix]').forEach(b => b.addEventListener('click', () => busy(b, async () => {
          try {
            const r = await api('POST', '/services/fix/' + b.dataset.fix);
            if (r.manual) { el.querySelector('.dns-manual')?.remove(); el.insertAdjacentHTML('beforeend', manualDnsHTML(r)); bindCopy(el); return; }
            toast('Fixed'); run();
          } catch (e) { toast(esc(e.message), 'err', 6000); run(); }
        })));
      };
      async function run() {
        if (!isOwner()) { el.innerHTML = '<div class="f-help">Only owners can run the checks.</div>'; return; }
        draw(null, true);
        try { draw((await api('GET', '/services/checks')).checks, false); } catch (e) { el.innerHTML = `<div class="f-help">${esc(e.message)}</div>`; }
      }
      run();
    },
    backup(el) {
      if (!isOwner()) { el.innerHTML = '<div class="f-help">Only owners can download backups.</div>'; return; }
      el.innerHTML = `<div class="f-help">Downloads the database and the master key, encrypted with a passphrase you choose. Keep the passphrase somewhere safe: without it the backup can't be opened.
        Restore with the server stopped: <code>python3 -m openroost restore backup.orb --data &lt;data folder&gt;</code>.</div>
        <form class="su-card" data-bk style="margin-top:10px"><label class="su-f"><span>Your password</span><input class="in" type="password" name="p" required autocomplete="current-password" data-nosave></label>
          <label class="su-f"><span>Backup passphrase</span><input class="in" type="password" name="x" minlength="12" required autocomplete="new-password" data-nosave></label>
          <div class="su-row"><button class="btn btn-sm btn-primary" data-keep>Download encrypted backup</button></div></form>`;
      el.querySelector('[data-bk]').addEventListener('submit', async e => {
        e.preventDefault(); const f = e.target, b = f.querySelector('button');
        await busy(b, async () => {
          const r = await fetch('/api/v1/backup', { method: 'POST', credentials: 'same-origin', headers: { 'X-OpenRoost': '1', 'Content-Type': 'application/json' }, body: JSON.stringify({ password: f.elements.p.value, passphrase: f.elements.x.value }) });
          if (!r.ok) { let m = 'Backup failed'; try { m = (await r.json()).error; } catch (x) { /* ignore */ } return toast(esc(m), 'err'); }
          const name = (r.headers.get('Content-Disposition') || '').match(/filename="([^"]+)"/)?.[1] || 'openroost.orb';
          download(name, await r.blob()); f.reset(); toast('Backup downloaded');
        });
      });
    },
    wirelink(el) {
      el.innerHTML = `<div class="f-help">Everything the listener receives from and sends to the hub, live: TLS handshakes, the time request, MQTT connect (with the JWT's claims), subscriptions, every message and its payload. For working out more of the protocol. Owners only.</div>
        <div class="group-actions"><a class="btn" href="#wire" data-keep>${icon('terminal')} Open the live protocol log</a></div>`;
    },
    async audit(el) {
      if (!isOwner()) { el.innerHTML = '<div class="f-help">Only owners can read the audit log.</div>'; return; }
      try {
        const list = (await api('GET', '/audit?limit=100')).audit;
        el.innerHTML = `<div class="audit">${list.map(a => `<div class="list-row"><div><div><b>${esc(a.action)}</b> <span class="f-help">${esc(a.detail)}</span></div><div class="f-help">${esc(a.user)} · ${esc(a.ip)} · ${new Date(a.t * 1000).toLocaleString()}</div></div></div>`).join('') || '<div class="f-help">Nothing yet.</div>'}</div>`;
      } catch (e) { el.innerHTML = `<div class="f-help">${esc(e.message)}</div>`; }
    },
    updates(el) {
      const draw = u => {
        const how = u.docker ? `<code>./update.sh</code> in the OpenRoost folder on the server (pulls the new release and rebuilds the container). Your data and settings are kept.`
          : 'Pull the new release with <code>git pull</code> and restart OpenRoost.';
        el.innerHTML = `<dl class="kv"><div><dt>This server</dt><dd>${esc(u.version)}${u.commit ? ` <span class="sd-raw">(${esc(u.commit)})</span>` : ''}${u.docker ? ' · Docker' : ''}</dd></div>
          <div><dt>Newest release</dt><dd>${u.latest ? esc(u.latest) : '—'}</dd></div><div><dt>Last checked</dt><dd>${u.checked ? ago(u.checked * 1000) : 'never'}</dd></div></dl>
          ${u.updateAvailable ? `<div class="note note-blocked">${icon('alert')} <span><b>Update available: ${esc(u.latest)}.</b> ${u.releaseUrl ? `<a href="${esc(u.releaseUrl)}" target="_blank" rel="noopener noreferrer">What's new</a>. ` : ''}To update, run ${how}</span></div>`
            : u.latest ? `<div class="f-help">${icon('check')} You're on the newest release.</div>` : ''}
          ${u.error ? `<div class="f-help err-t">${esc(u.error)}</div>` : ''}
          ${isOwner() ? '<div class="group-actions"><button type="button" class="btn" data-chk data-keep>Check now</button></div>' : ''}`;
        el.querySelector('[data-chk]')?.addEventListener('click', e => busy(e.currentTarget, async () => {
          try { S.update = await api('POST', '/version/check'); draw(S.update); emit(); } catch (err) { toast(esc(err.message), 'err'); }
        }));
      };
      api('GET', '/version').then(u => { S.update = u; draw(u); }).catch(e => { el.innerHTML = `<div class="f-help">${esc(e.message)}</div>`; });
    },
    about(el) {
      el.innerHTML = `<dl class="kv"><div><dt>OpenRoost360</dt><dd>${esc(S.version || '—')}</dd></div><div><dt>API</dt><dd><a href="/api/v1/openapi.json">/api/v1/openapi.json</a></dd></div>
        <div><dt>HTTPS certificate</dt><dd class="sd-mono" style="font-size:11px;word-break:break-all">${esc(S.tlsFingerprint || (location.protocol === 'https:' ? 'set by your reverse proxy' : 'HTTPS is off'))}</dd></div>
        <div><dt>Protocol notes</dt><dd>PROTOCOL.md</dd></div></dl>
        <div class="f-help">The mobile app shows this fingerprint the first time it connects; check they match. Not affiliated with Roost.</div>
        ${isOwner() ? '<div data-rot></div>' : ''}`;
      const box = el.querySelector('[data-rot]'); if (!box) return;
      api('GET', '/admin/key').then(k => {
        box.innerHTML = `<dl class="kv"><div><dt>Master key</dt><dd><code>${esc(k.id)}</code>${k.rotated ? ` · rotated ${ago(+k.rotated * 1000)}` : ''}${k.fromEnv ? ' · from OPENROOST_MASTER_KEY' : ''}</dd></div>
          ${k.accountsOnOldKey ? `<div><dt>Accounts on an older key</dt><dd>${k.accountsOnOldKey}: they move to the new key at their next sign-in</dd></div>` : ''}</dl>
          <div class="f-help">Rotating makes a new master key and re-encrypts every stored secret with it. Everyone else is signed out (you stay signed in), and pending password-reset and invite links stop working. Do it if <code>master.key</code> or a backup may have leaked, then download a fresh backup.</div>
          ${k.fromEnv ? '<div class="f-help">The key comes from the environment, so OpenRoost can\'t replace it here.</div>' : `<form class="su-row" data-rotf style="margin-top:8px"><input class="in" type="password" name="p" placeholder="Your password" autocomplete="current-password" required data-nosave style="flex:1;min-width:160px"><button class="btn" data-keep>Rotate master key</button></form>`}`;
        const f = box.querySelector('[data-rotf]'); if (!f) return;
        f.addEventListener('submit', async e => {
          e.preventDefault(); const b = f.querySelector('button');
          if (b.dataset.armed !== '1') { b.dataset.armed = '1'; b.textContent = 'Click again: sign everyone out and rotate'; setTimeout(() => { b.dataset.armed = ''; b.textContent = 'Rotate master key'; }, 5000); return; }
          b.disabled = true;
          try { const r = await api('POST', '/admin/rotate-key', { password: f.elements.p.value }); toast(`Master key rotated (${esc(r.id)}). ${r.sessionsEnded - 1 > 0 ? (r.sessionsEnded - 1) + ' other sessions were signed out. ' : ''}Download a new backup now.`, 'ok', 9000); CUSTOM.about(el); }
          catch (err) { toast(esc(err.message), 'err', 6000); b.disabled = false; b.dataset.armed = ''; b.textContent = 'Rotate master key'; }
        });
      }).catch(err => { box.innerHTML = `<div class="f-help">${esc(err.message)}</div>`; });
    },
  };

  const ACTIONS = {
    async changePass(b, el) {
      const g = k => el.querySelector(`[data-k="${k}"]`);
      if (!g('pwCur').value) return toast('Enter your current password', 'err');
      if (g('pwNew').value.length < 12) return toast('New password must be 12+ characters', 'err');
      if (g('pwNew').value !== g('pwNew2').value) return toast('Passwords do not match', 'err');
      await busy(b, async () => {
        try { await api('POST', '/me/password', { current: g('pwCur').value, new: g('pwNew').value }); ['pwCur', 'pwNew', 'pwNew2'].forEach(k => { g(k).value = ''; }); toast('Password changed. Other devices were signed out.'); }
        catch (e) { toast(esc(e.message), 'err', 6000); }
      });
    },
    ntfyTest(b) { return busy(b, async () => { try { await api('POST', '/notify/test/ntfy', {}); toast('Test push sent'); } catch (e) { toast(esc(e.message), 'err', 6000); } }); },
    hookTest(b) { return busy(b, async () => { try { await api('POST', '/notify/test/webhook', {}); toast('Test webhook accepted'); } catch (e) { toast(esc(e.message), 'err', 6000); } }); },
    matrixTest(b) { return busy(b, async () => { try { await api('POST', '/notify/test/matrix', {}); toast('Test message sent'); } catch (e) { toast(esc(e.message), 'err', 6000); } }); },
    ssoTest(b, el) {
      return busy(b, async () => {
        try { const r = await api('POST', '/services/sso/test', { issuer: el.querySelector('[data-k="ssoIssuer"]').value }); toast(esc(r.result)); }
        catch (e) { toast(esc(e.message), 'err', 6000); }
      });
    },
    downloadLog(b) {
      return busy(b, async () => { const r = await api('GET', '/events?limit=500'); download('openroost-events.jsonl', r.events.map(e => JSON.stringify(e)).join('\n'), 'application/x-ndjson'); });
    },
  };

  // ---------- pairing (the hub does it; OpenRoost names what joins) ----------
  function renderPairing(el) {
    let sig = '';
    mount(el, () => {
      const p = S.pairing, found = p.found || [];
      const nsig = (p.active ? 'on' : 'off') + found.map(s => s.id).join(',');
      const cd = el.querySelector('[data-cd]');
      if (p.active && cd) { const r = Math.max(0, Math.round(p.until - now() / 1000)); cd.textContent = `${Math.floor(r / 60)}:${String(r % 60).padStart(2, '0')}`; }
      if (nsig === sig) return; sig = nsig;
      el.innerHTML = !p.active && !found.length ? `<div class="pair">
          <div class="f-help">Pairing happens on the hub; OpenRoost names whatever joins.</div>
          <ol class="steps"><li>Press the <b>grey button</b> on the back of the SmartBase. The light ring <b>blinks green</b> for 10 minutes.</li><li>Pull the sensor's red battery tab (or pull and re-insert it).</li><li>The hub chimes and the sensor shows up here.</li></ol>
          ${isOwner() ? `<button type="button" class="btn btn-primary" data-start>${icon('link')} I pressed the button — watch for sensors</button>` : ''}</div>`
        : `<div class="pair pair-on">${p.active ? `<div class="pair-live"><span class="pulse"></span> Watching for new sensors <span class="pair-cd" data-cd>10:00</span>${isOwner() ? '<button type="button" class="btn" data-stop>Stop</button>' : ''}</div>` : ''}
          ${found.map(s => `<form class="pair-new" data-id="${s.id}">
            <div class="pair-found">${icon(TYPE_ICON[s.type] || 'chip')}<div><b>${s.type === 'unknown' ? 'New device — type not recognised' : 'New ' + esc(s.typeLabel)}</b>
              <div class="${s.type === 'unknown' ? 'f-help' : 'det'}">${s.type === 'unknown' ? `The hub reported device code <code>dt ${esc(s.dt)}</code>, which isn't in OpenRoost's table yet.` : `${icon('check')} Recognised from the hub (<code>dt ${esc(s.dt)}</code>)`}</div>
              <div class="f-help">slot ${s.id} · ${esc(s.firmware || '')} · ${s.signal.rssi ?? '—'} dBm</div></div></div>
            <input class="in" name="n" placeholder="Name, e.g. ${{ door: 'Side Door', motion: 'Hallway Motion', leak: 'Under Sink' }[s.type] || 'Side Door'}" required aria-label="Sensor name" maxlength="40">
            <div class="combo"><input class="in" name="r" placeholder="Room — search or create" autocomplete="off" role="combobox" aria-expanded="false" aria-autocomplete="list" aria-label="Room"><ul class="combo-list" role="listbox" hidden></ul></div>
            <button class="btn btn-primary"${isOwner() ? '' : ' disabled'}>Save</button></form>`).join('')}
          ${p.active && !found.length ? '<div class="f-help">Pull the tab on the sensor now…</div>' : ''}</div>`;
      el.querySelector('[data-start]')?.addEventListener('click', async () => { try { S.pairing = await api('POST', '/pairing/start'); emit(); } catch (e) { toast(esc(e.message), 'err'); } });
      el.querySelector('[data-stop]')?.addEventListener('click', async () => { try { S.pairing = await api('POST', '/pairing/stop'); emit(); } catch (e) { toast(esc(e.message), 'err'); } });
      el.querySelectorAll('.pair-new').forEach(f => {
        roomCombo(f.querySelector('.combo'));
        f.addEventListener('submit', async e => {
          e.preventDefault(); if (f.querySelector('.combo-list:not([hidden])')) return;
          try { await renameSensor(+f.dataset.id, f.elements.n.value.trim(), f.elements.r.value.trim()); S.pairing = await api('GET', '/pairing'); emit(); toast('Sensor added'); }
          catch (err) { toast(esc(err.message), 'err'); }
        });
      });
    });
  }

  // room picker: search existing rooms; first option is always "+ Create new room"
  function roomCombo(wrap) {
    const input = wrap.querySelector('input'), list = wrap.querySelector('.combo-list');
    let items = [], active = 0, creating = false;
    const open = v => { list.hidden = !v; input.setAttribute('aria-expanded', String(v)); };
    const draw = () => {
      const q = input.value.trim(), ql = q.toLowerCase(), rooms = allRooms();
      const matches = rooms.filter(r => r.toLowerCase().includes(ql)), exact = rooms.find(r => r.toLowerCase() === ql);
      items = [{ create: true, label: q && !exact ? `+ Create new room “${q}”` : '+ Create New Room' }, ...matches.map(r => ({ room: r }))];
      if (active >= items.length) active = items.length - 1;
      const hl = r => { const i = r.toLowerCase().indexOf(ql); return q && i >= 0 ? esc(r.slice(0, i)) + '<mark>' + esc(r.slice(i, i + q.length)) + '</mark>' + esc(r.slice(i + q.length)) : esc(r); };
      list.innerHTML = items.map((it, i) => `<li role="option" data-i="${i}" class="${it.create ? 'create' : ''}${i === active ? ' active' : ''}" aria-selected="${i === active}">${it.create ? esc(it.label) : icon('home') + ' ' + hl(it.room)}</li>`).join('')
        + (q && !matches.length ? '<li class="none" aria-disabled="true">No rooms match</li>' : '');
    };
    const setCreating = v => { creating = v; wrap.classList.toggle('creating', v); input.placeholder = v ? 'Name the new room, then press Enter' : 'Room — search or create'; };
    const choose = i => {
      const it = items[i]; if (!it) return;
      if (it.room) { input.value = it.room; setCreating(false); open(false); return; }
      const q = input.value.trim();
      if (q) { input.value = createRoom(q); setCreating(false); open(false); toast(`Room “${esc(input.value)}” created`); }
      else { setCreating(true); open(false); input.focus(); }
    };
    input.addEventListener('focus', () => { if (!creating) { active = 0; draw(); open(true); } });
    input.addEventListener('input', () => { if (creating) return; active = input.value.trim() ? Math.min(1, items.length) : 0; draw(); if (items.length > 1 && input.value.trim()) active = 1; draw(); open(true); });
    input.addEventListener('keydown', e => {
      if (creating) { if (e.key === 'Enter') { e.preventDefault(); const q = input.value.trim(); if (q) { input.value = createRoom(q); setCreating(false); toast(`Room “${esc(input.value)}” created`); } } else if (e.key === 'Escape') { setCreating(false); input.value = ''; } return; }
      if (list.hidden && e.key === 'ArrowDown') { draw(); open(true); return; }
      if (list.hidden) return;
      if (e.key === 'ArrowDown') { e.preventDefault(); active = (active + 1) % items.length; draw(); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); active = (active - 1 + items.length) % items.length; draw(); }
      else if (e.key === 'Enter') { e.preventDefault(); choose(active); }
      else if (e.key === 'Escape') { open(false); }
    });
    input.addEventListener('blur', () => setTimeout(() => open(false), 120));
    list.addEventListener('mousedown', e => e.preventDefault());
    list.addEventListener('click', e => { const li = e.target.closest('li[data-i]'); if (li) choose(+li.dataset.i); });
  }

  // ---------- session + sign-in ----------
  const roleName = r => r ? r[0].toUpperCase() + r.slice(1) : '';
  function session() { const u = SV_STATE.user; return u ? { name: u.display || u.username, user: u.username, role: roleName(u.role), via: u.sso ? 'authentik' : 'local' } : null; }
  async function logout() { try { await api('POST', '/auth/logout', {}); } catch (e) { /* signed out anyway */ } location.hash = ''; location.href = '/'; }
  async function gate(start) {
    applyLook();
    let st;
    try { st = await api('GET', '/status'); S.tlsFingerprint = st.tlsFingerprint; }
    catch (e) { document.body.innerHTML = `<div class="login-wrap"><div class="login-card"><h2 class="login-title">Can't reach the OpenRoost server</h2><p class="f-help">${esc(e.message)}</p></div></div>`; return; }
    if (!st.setupDone) { location.replace('setup.html'); return; }
    const enter = async me => {
      SV_STATE.user = me.user; SV_STATE.sid = me.sessionId; SV_STATE.role = me.user.role;
      await loadSettings(); await loadAll(); connectStream();
      document.querySelector('.login-wrap')?.remove(); document.body.classList.remove('logged-out');
      start(session());
    };
    if (st.signedIn && !new URLSearchParams(location.search).has('cancel')) return enter(await api('GET', '/me'));   // a cancel link works signed in or not
    const wrap = document.createElement('div'); wrap.className = 'login-wrap'; document.body.appendChild(wrap); document.body.classList.add('logged-out');
    const qs = new URLSearchParams(location.search), ssoErr = qs.get('ssoError'), resetTok = qs.get('reset'), inviteTok = qs.get('invite'), cancelTok = qs.get('cancel');
    if (ssoErr || resetTok || inviteTok || cancelTok) history.replaceState(null, '', location.pathname);
    const card = inner => { wrap.innerHTML = `<div class="login-card"><div class="login-brand"><span class="login-mark">${icon('home')}</span><div><b>OpenRoost360</b><small>Sign in to your home</small></div></div>${inner}</div>`; };
    const main = (err = '') => {
      card(`<h2 class="login-title">Welcome home</h2><div class="login-err" role="alert">${esc(err)}</div>
        ${st.sso.on ? `<a class="btn btn-sso" href="/api/v1/auth/oidc/start">${icon('shield')} ${esc(st.sso.button)}</a>${st.localLogin ? '<div class="login-or"><span>or use a password</span></div>' : ''}` : ''}
        ${st.localLogin ? `<form class="login-form"><label>Username<input class="in" name="u" autocomplete="username" required maxlength="64"></label><label>Password<input class="in" type="password" name="p" autocomplete="current-password" required maxlength="256"></label>
          <label class="login-rem"><input type="checkbox" name="r"> Keep me signed in on this device (30 days)</label><button class="btn btn-primary">Sign in</button></form>
          <div class="login-hint"><a href="#" data-forgot>Forgot password?</a></div>` : ''}`);
      wrap.querySelector('[data-forgot]')?.addEventListener('click', e => { e.preventDefault(); forgot(); });
      const f = wrap.querySelector('form'); if (!f) return; f.elements.u.focus();
      f.addEventListener('submit', async e => {
        e.preventDefault(); const btn = f.querySelector('button'); btn.disabled = true;
        try {
          const r = await api('POST', '/auth/login', { username: f.elements.u.value.trim(), password: f.elements.p.value, remember: f.elements.r.checked });
          if (r.mfaRequired) return totp(r.ticket);
          await enter(await api('GET', '/me')); toast(`Welcome, ${esc(session().name)}`);
        } catch (err) { main(err.status === 401 || err.status === 429 || err.status === 403 ? err.message : 'Couldn\'t sign in: ' + err.message); }
      });
    };
    const totp = ticket => {
      card(`<h2 class="login-title">Two-step check</h2><div class="f-help">Enter the 6-digit code from your authenticator app.</div><div class="login-err" role="alert"></div>
        <form class="login-form"><input class="in login-code" name="c" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="000000" required><button class="btn btn-primary">Verify</button><button type="button" class="btn" data-back>Back</button></form>`);
      const f = wrap.querySelector('form'); f.elements.c.focus(); wrap.querySelector('[data-back]').onclick = () => main();
      f.onsubmit = async e => {
        e.preventDefault();
        try { await api('POST', '/auth/totp', { ticket, code: f.elements.c.value }); await enter(await api('GET', '/me')); }
        catch (err) { if (err.status === 401 && /timed out/.test(err.message)) return main(err.message); wrap.querySelector('.login-err').textContent = err.message; f.elements.c.select(); }
      };
    };
    const forgot = (msg = '') => {
      card(`<h2 class="login-title">Reset your password</h2><div class="f-help">Enter your username or email. If your account has an email address, we'll send a link to choose a new password.</div><div class="login-err" role="alert"></div>
        ${msg ? `<div class="note">${icon('mail')} <span>${esc(msg)}</span></div>` : `<form class="login-form"><label>Username or email<input class="in" name="l" required maxlength="254" autocomplete="username"></label><button class="btn btn-primary">Send reset link</button></form>`}
        <div class="login-hint"><a href="#" data-back>Back to sign in</a></div>`);
      wrap.querySelector('[data-back]').onclick = e => { e.preventDefault(); main(); };
      const f = wrap.querySelector('form'); if (!f) return; f.elements.l.focus();
      f.onsubmit = async e => {
        e.preventDefault(); f.querySelector('button').disabled = true;
        try { const r = await api('POST', '/auth/reset-request', { login: f.elements.l.value.trim() }); forgot(r.message); }
        catch (err) { wrap.querySelector('.login-err').textContent = err.message; f.querySelector('button').disabled = false; }
      };
    };
    const reset = token => {
      card(`<h2 class="login-title">Choose a new password</h2><div class="login-err" role="alert"></div>
        <form class="login-form"><label>New password<input class="in" type="password" name="p" minlength="12" required autocomplete="new-password" maxlength="256"></label>
          <label>Confirm<input class="in" type="password" name="p2" minlength="12" required autocomplete="new-password" maxlength="256"></label><button class="btn btn-primary">Set password</button></form>
        <div class="login-hint">At least 12 characters. Your other devices will be signed out.</div>`);
      const f = wrap.querySelector('form'); f.elements.p.focus();
      f.onsubmit = async e => {
        e.preventDefault(); const err = wrap.querySelector('.login-err');
        if (f.elements.p.value !== f.elements.p2.value) { err.textContent = 'Passwords don\'t match.'; return; }
        try { await api('POST', '/auth/reset', { token, password: f.elements.p.value }); main(''); toast('Password changed. Sign in with the new one.'); }
        catch (x) { err.textContent = x.message; }
      };
    };
    const join = async token => {
      let inv;
      try { inv = await api('POST', '/auth/invite', { token }); }
      catch (err) { return main(err.message); }
      card(`<h2 class="login-title">Join ${esc(inv.site)}</h2><div class="f-help">@${esc(inv.by)} invited you as <b>${esc(inv.role)}</b>. Choose how you'll sign in.</div><div class="login-err" role="alert"></div>
        <form class="login-form"><label>Your name<input class="in" name="d" maxlength="80" autocomplete="name"></label>
          <label>Username<input class="in" name="u" required pattern="[A-Za-z0-9._\-]{3,32}" maxlength="32" autocomplete="username" title="3–32 letters, digits, . _ or -"></label>
          <label>Email (for password resets)<input class="in" type="email" name="e" value="${esc(inv.email)}" maxlength="254" autocomplete="email"></label>
          <label>Password<input class="in" type="password" name="p" minlength="12" required autocomplete="new-password" maxlength="256"></label>
          <label>Confirm<input class="in" type="password" name="p2" minlength="12" required autocomplete="new-password" maxlength="256"></label>
          <button class="btn btn-primary">Create account</button></form>
        <div class="login-hint">At least 12 characters. <a href="#" data-back>I already have an account</a></div>`);
      wrap.querySelector('[data-back]').onclick = e => { e.preventDefault(); main(); };
      const f = wrap.querySelector('form'); f.elements.d.focus();
      f.onsubmit = async e => {
        e.preventDefault(); const err = wrap.querySelector('.login-err');
        if (f.elements.p.value !== f.elements.p2.value) { err.textContent = 'Passwords don\'t match.'; return; }
        try {
          await api('POST', '/auth/invite/accept', { token, username: f.elements.u.value.trim(), password: f.elements.p.value, display: f.elements.d.value.trim(), email: f.elements.e.value.trim() });
          await enter(await api('GET', '/me')); toast(`Welcome, ${esc(session().name)}`);
        } catch (x) { err.textContent = x.message; }
      };
    };
    const cancelPage = async token => {
      let r;
      try { r = await api('POST', '/escalations/peek', { token }); } catch (err) { return card(`<h2 class="login-title">Cancel link</h2><div class="login-err" role="alert">${esc(err.message)}</div><div class="login-hint"><a href="/">Sign in</a></div>`); }
      const x = r.escalation, skew = r.now * 1000 - Date.now();
      const draw = (msg = '') => {
        const left = Math.max(0, Math.ceil((x.deadline * 1000 - (Date.now() + skew)) / 1000));
        const done = x.state !== 'pending' || left === 0;
        card(`<div class="eyebrow" style="color:var(--crit)">Emergency · ${esc(r.site)}</div><h2 class="login-title">${esc(x.label)}</h2><p class="f-help">${esc(x.detail)}</p>
          ${x.state === 'cancelled' ? `<div class="note">${icon('check')} <span>Cancelled by ${esc(x.by || '?')} (${esc(x.via || '')}). The emergency contacts were not told.</span></div>`
          : x.state === 'sent' || left === 0 ? `<div class="note note-blocked">${icon('alert')} <span>Too late: the emergency contacts ${x.state === 'sent' ? 'were told' : 'are being told'}.</span></div>`
          : `<p style="font-weight:700;color:var(--crit)">${left} seconds left to cancel the emergency email / Matrix message.</p><button class="btn btn-primary" data-do style="width:100%">Cancel emergency messages</button>`}
          <div class="login-err" role="alert">${esc(msg)}</div><div class="login-hint">Hello ${esc(r.name)}. <a href="/">Open OpenRoost</a></div>`);
        wrap.querySelector('[data-do]')?.addEventListener('click', async ev => {
          ev.currentTarget.disabled = true;
          try { Object.assign(x, (await api('POST', '/escalations/cancel', { token })).escalation); draw(); }
          catch (err) { if (err.status === 409) x.state = 'sent'; draw(err.message); }
        });
        if (!done) setTimeout(() => { if (x.state === 'pending' && document.contains(wrap)) draw(); }, 1000);
      };
      draw();
    };
    if (cancelTok) cancelPage(cancelTok); else if (inviteTok) join(inviteTok); else if (resetTok) reset(resetTok); else main(ssoErr || '');
  }
  function userMenu(el) {
    const s = session(); if (!s) return;
    el.innerHTML = `<button type="button" class="avatar" aria-haspopup="true" aria-expanded="false" title="${esc(s.name)}">${esc(s.name[0].toUpperCase())}</button>
      <div class="um" hidden><div class="um-who"><b>${esc(s.name)}</b><small>${s.role} · ${s.via === 'authentik' ? 'signed in with Authentik' : 'local account'}</small></div>
      <a href="#settings/account">${icon('user')} Account</a><button type="button" data-logout>${icon('unlock')} Sign out</button></div>`;
    const btn = el.querySelector('.avatar'), menu = el.querySelector('.um');
    btn.addEventListener('click', e => { e.stopPropagation(); menu.hidden = !menu.hidden; btn.setAttribute('aria-expanded', String(!menu.hidden)); });
    document.addEventListener('click', e => { if (!el.contains(e.target)) { menu.hidden = true; btn.setAttribute('aria-expanded', 'false'); } });
    el.querySelector('[data-logout]').addEventListener('click', logout);
  }

  // ---------- dashboard UI helpers ----------
  function health() {
    const p = [];
    if (!S.live) p.push('Live updates paused — reconnecting');
    if (!S.hub.id) p.push('No hub has connected yet');
    else if (!S.hub.online) p.push(S.hub.pw === 0 ? `Hub on battery · last seen ${ago(S.hub.lastSeen)}` : `Hub not connected · last seen ${ago(S.hub.lastSeen)}`);
    return { ok: !p.length, problems: p };
  }
  function healthHTML() { const h = health(); return `<a class="health ${h.ok ? 'ok' : 'bad'}" href="#settings/hub"><span class="hd"></span><span class="ht"><b>${h.ok ? 'Cloud stand-in working' : 'Cloud stand-in needs attention'}</b><small>${h.ok ? `Hub connected for ${uptime()} · events arrive live` : esc(h.problems.join(' · '))}</small></span>${icon('server')}</a>`; }
  function stateInfo() {
    const alarm = S.alerts.find(a => a.active && ['intrusion', 'panic', 'fire'].includes(a.kind)), c = S.countdown, rem = remaining();
    const live = S.sensors, gone = live.filter(isMissing).length, on = live.length - gone;
    const climate = S.hub.temp != null ? ` · ${temp(S.hub.temp)} inside · ${S.hub.hum}% humidity` : '';
    if (alarm) return { key: 'alarm', cls: 's-alarm', lbl: 'Alarm', hint: 'Disarm at the keypad', title: alarm.title, sub: alarm.detail, p: 100 };
    if (c) return { key: c.kind, cls: 's-pending', lbl: `${rem}s`, hint: c.kind === 'exit' ? 'Arming Away' : 'Entry delay', title: c.kind === 'exit' ? 'Time to head out' : 'Someone came in', sub: c.kind === 'exit' ? 'The system arms when the countdown ends.' : 'Disarm at the keypad before the countdown ends.', p: Math.max(0, Math.min(100, rem / (c.total || 60) * 100)) };
    if (S.as == null) return { key: 'none', cls: 's-pending', lbl: 'Waiting', hint: '', title: 'Waiting for the hub', sub: 'The SmartBase hasn\'t reported its state yet.', p: 0 };
    if (S.as === 2) return { key: 'home', cls: 's-armed', lbl: 'Home', hint: 'Armed', title: 'Armed while you\'re home', sub: `Doors are watched; motion sensors are relaxed${climate}.`, p: 100 };
    if (S.as === 4) return { key: 'away', cls: 's-armed', lbl: 'Away', hint: 'Armed', title: 'Armed — everyone\'s out', sub: `Every sensor is watching${climate}.`, p: 100 };
    const open = live.filter(s => s.state === 'open');
    return { key: 'off', cls: '', lbl: 'Disarmed', hint: '', title: open.length ? `${open.map(s => s.name).join(', ')} ${open.length > 1 ? 'are' : 'is'} open` : 'All quiet at home',
      sub: `${on} sensor${on === 1 ? '' : 's'} connected${gone ? ` · ${gone} missing` : ''}${climate}`, p: 100 };
  }
  const ringHTML = st => `<div class="ring ${st.cls}" role="img" aria-label="${esc(st.hint ? `${st.lbl} — ${st.hint}` : st.lbl)}"><svg viewBox="0 0 100 100" aria-hidden="true"><circle class="ring-trk" cx="50" cy="50" r="45"/><circle class="ring-arc" cx="50" cy="50" r="45" pathLength="100" stroke-dasharray="${st.p.toFixed(2)} 100" transform="rotate(-90 50 50)"/></svg><span class="ring-in"><span class="lbl">${st.lbl}</span>${st.hint ? `<span class="hint">${st.hint}</span>` : ''}</span></div>`;
  function modesHTML() {
    const cur = S.as === 2 ? 'home' : S.as === 4 || S.as === 8 ? 'away' : S.as === 0 ? 'off' : null;
    return `<div class="modes" role="group" aria-label="Arm mode">${[['off', 'Off'], ['home', 'Home'], ['away', 'Away']].map(([k, l]) => `<button type="button" data-a="${k}" class="${cur === k ? 'on' : ''}"${plannedAttrs('hub.arm')}>${l}</button>`).join('')}</div>`;
  }
  const previewNote = () => `<div class="preview">${icon('alert')} <span>Arming from the app needs the hub's command format (not cracked yet). Arming at the keypad shows up here.</span></div>`;
  function bindHome(root) {
    root.addEventListener('click', async e => {
      const k = e.target.closest('[data-ack]');
      if (k) { k.disabled = true; try { await api('POST', `/alerts/${k.dataset.ack}/ack`); S.alerts = S.alerts.filter(a => a.kind !== k.dataset.ack); emit(); } catch (err) { k.disabled = false; toast(esc(err.message), 'err'); } }
    });
  }
  function devCard(s, opts = {}) {
    const p = batPct(s), low = s.low, miss = isMissing(s);
    const cls = miss ? 'missing' : s.state === 'wet' ? 'crit' : isAlertState(s) ? 'hot' : '';
    const meta = miss ? `<span>Last heard ${ago(s.last)}</span>`
      : `<span class="batt ${low ? 'low' : ''}">${icon('battery')} ${s.pct == null ? '—' : p + '%'}</span><span>${icon('wifi')} ${['—', 'weak', 'fair', 'good', 'great'][bars(s.rs)]}</span>`;
    const state = miss ? 'Missing' : sensorState(s) + (s.temp != null && s.type === 'leak' ? ` · ${temp(s.temp)}` : '');
    const act = opts.manage ? `<div class="dev-act"><button type="button" class="btn btn-sm dev-edit" data-edit="${s.id}" aria-label="${isOwner() ? 'Edit' : 'Details for'} ${esc(s.name)}">${icon(isOwner() ? 'edit' : 'eye')} ${isOwner() ? 'Edit' : 'Details'}</button>${isOwner() ? `<button type="button" class="btn btn-sm btn-icon${miss ? ' dev-rm-strong' : ' dev-rm'}" data-rm="${s.id}" title="Remove ${esc(s.name)}" aria-label="Remove ${esc(s.name)}">${icon('trash')}</button>` : ''}</div>` : '';
    return `<div class="dev ${cls}${s.named ? '' : ' unnamed'}"><div class="top"><span class="ico">${icon(TYPE_ICON[s.type] || 'chip')}</span><span class="state">${esc(state)}</span></div>
      <div class="name" title="${esc(s.name)}">${esc(s.name)}</div><div class="room">${esc(s.room || s.typeLabel)}</div>
      <div class="meta">${meta}</div>${act}</div>`;
  }
  function timeline(list, raw) {
    if (!list.length) return '<div class="empty">Nothing here yet.</div>';
    let day = '', out = '';
    list.forEach(e => {
      const d = fmtDate(e.t); if (d !== day) { day = d; out += `<li class="day">${d}</li>`; }
      out += `<li class="ev sev-${esc(e.sev)}"><span class="bub">${icon(KIND_ICON[e.kind] || 'list')}</span><div><div class="t1">${esc(e.title)}</div><div class="t2">${esc(e.detail || '')}</div></div><span class="tm">${fmtTime(e.t)}</span>
        ${raw && e.raw ? `<details><summary>What the hub sent</summary><pre>${esc(JSON.stringify(e.raw, null, 1))}</pre></details>` : ''}</li>`;
    });
    return `<ul class="tl">${out}</ul>`;
  }
  const ALERT_ICON = { leak: 'leak', fire: 'fire' };
  const escLeft = x => Math.max(0, Math.ceil((x.deadline * 1000 - (Date.now() + S.escSkew)) / 1000));
  const escHTML = () => S.esc.filter(x => x.state === 'pending' || (x.at && Date.now() + S.escSkew - x.at * 1000 < 600000)).map(x => x.state === 'pending'
    ? `<div class="alert esc-pending" role="alert">${icon('alert')}<div><h3>${esc(x.label)} · ${escLeft(x)} s</h3><p>${esc(x.detail)} Emergency contacts are told when the countdown ends.</p></div>${SV_STATE.role !== 'viewer' ? `<button type="button" class="btn" data-esccancel="${esc(x.id)}">Cancel emergency messages</button>` : ''}</div>`
    : `<div class="alert ended${x.state === 'cancelled' ? ' esc-ok' : ''}">${icon(x.state === 'cancelled' ? 'check' : 'alert')}<div><h3>${esc(x.label)}: ${x.state === 'cancelled' ? 'cancelled' : 'emergency contacts told'}</h3><p>${x.state === 'cancelled' ? `By ${esc(x.by || '?')} (${esc(x.via || '')})` : `No one cancelled within ${x.secs} seconds${x.told && x.told.length ? ' · told ' + esc(x.told.join(', ')) : ''}`} · ${ago(x.at * 1000)}</p></div></div>`).join('');
  document.addEventListener('click', async e => {
    const b = e.target.closest('[data-esccancel]'); if (!b) return;
    b.disabled = true;
    try { const r = await api('POST', `/escalations/${b.dataset.esccancel}/cancel`); const i = S.esc.findIndex(y => y.id === r.escalation.id); if (i >= 0) S.esc[i] = r.escalation; toast('Cancelled: the emergency contacts won\'t be told'); emit(); }
    catch (err) { toast(esc(err.message), 'err', 6000); b.disabled = false; }
  });
  const alertsHTML = () => escHTML() + S.alerts.map(a => `<div class="alert k-${esc(a.kind)}${a.active ? '' : ' ended'}">${icon(ALERT_ICON[a.kind] || 'alert')}<div><h3>${esc(a.title)}${a.active ? '' : ' (over)'}</h3><p>${esc(a.detail)} · ${ago(a.since)}</p></div>${SV_STATE.role !== 'viewer' ? `<button type="button" class="btn" data-ack="${esc(a.kind)}">Got it</button>` : ''}</div>`).join('');
  const ACTIVITY_SETS = { all: null, alerts: ['alarm', 'fire', 'panic', 'duress', 'leak'], arming: ['arm', 'disarm'], sensors: ['sensor'], system: ['system', 'power', 'pair', 'climate'] };
  function startRouter(pages, def, onRoute) {
    const route = () => { const [page, sub] = (location.hash.slice(1) || def).split('/'); return { page: pages[page] ? page : def, sub }; };
    const render = () => { const r = route(); onRoute && onRoute(r); const m = document.getElementById('main'), fresh = m.cloneNode(false); m.replaceWith(fresh); pages[r.page](fresh, r.sub); window.scrollTo && window.scrollTo(0, 0); };
    window.addEventListener('hashchange', render); render(); return route;
  }

  window.OpenRoost = {
    session, logout, gate, userMenu, SV_STATE, api, download, loadFeatures, isPlanned, plannedAttrs, defaultSettings, manualDnsHTML, bindCopy,
    ui: { isMissing, health, healthHTML, stateInfo, ringHTML, modesHTML, previewNote, bindHome, devCard, timeline, alertsHTML, ACTIVITY_SETS, startRouter },
    S, on, mount, emit, icon, esc, removeSensor, confirmRemoveSensor, sensorDetails, renameSensor,
    SECTIONS, renderSettings, renderPairing, toast, badge, roomCombo, createRoom, applyLook, persist,
    svc: { PH_OPTS, MAIL_OPTS, choiceCards, renderPiholeSetup, renderMailSetup, piholeReady, piholeWhy, mailWhy, mailTarget, piholeSummary, mailSummary, phHostOf, newPihole, newMail },
    TYPE_LABEL, TYPE_ICON, KIND_ICON, AS_LABEL, DA_LABEL,
    fmt: { time: fmtTime, date: fmtDate, ago, batPct, bars, temp, remaining, sensorState, isAlertState, uptime },
  };
})();
