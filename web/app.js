/* OpenRoost360 dashboard (index.html). Data: core.js (REST + live stream from the OpenRoost server). */
const M = OpenRoost, S = M.S, U = M.ui, I = M.icon, esc = M.esc, F = M.fmt;
const TABS = [['home', 'Home', 'home'], ['devices', 'Devices', 'grid'], ['activity', 'Activity', 'list'], ['settings', 'Settings', 'sliders']];
let route;

function renderHeader(r) {
  const page = (r && r.page) || (route ? route().page : 'home');
  M.setHTML(document.getElementById('tabs'), TABS.map(([id, l, ic]) => `<a href="#${id}" class="${page === id ? 'on' : ''}">${I(ic)}<span>${l}</span></a>`).join(''));
  const h = S.hub, cls = !h.online ? 'off' : h.pw === 0 || !S.live ? 'warn' : '';
  const up = S.update && S.update.updateAvailable && M.SV_STATE.role === 'owner';
  M.setHTML(document.getElementById('status'), `<span class="pill ${cls}"><span class="d"></span>${h.online ? 'Hub online' : h.id ? 'Hub offline' : 'Waiting for hub'}${h.online && h.pw === 0 ? ' · on battery' : ''}${!S.live ? ' · reconnecting' : ''}</span>`
    + (up ? ` <a class="pill warn upd" href="#settings/system"><span class="d"></span>Update ${esc(S.update.latest || 'available')}</a>` : ''));
}

const pages = {
  home(main) {
    main.innerHTML = `<div id="al"></div><div class="cols"><div class="stack">
      <section class="card hero" id="hero"></section>
      <section class="card h-rooms"><div class="eyebrow">${I('grid')} Around the house <a href="#devices">See all</a></div><div class="rooms" id="rooms"></div></section></div>
      <div class="stack"><section class="card h-stat"><div class="stat" id="stat"></div></section><div id="health"></div>
      <section class="card h-act"><div class="eyebrow">${I('list')} Recent activity <a href="#activity">History</a></div><div id="tl"></div></section></div></div>`;
    M.mount(main, () => {
      const H = (sel, html) => M.setHTML(main.querySelector(sel), html);
      H('#al', U.alertsHTML());
      const st = U.stateInfo();
      H('#hero', `${U.ringHTML(st)}<div><h2>${esc(st.title)}</h2><p>${esc(st.sub)}</p>${U.modesHTML()}${U.previewNote()}</div>`);
      H('#rooms', U.hubCard() + ([...S.sensors].sort((a, b) => U.isMissing(b) - U.isMissing(a)).map(s => U.devCard(s)).join('') || (S.hub.id ? '' : '<div class="empty">No sensors yet. They appear as the hub reports them.</div>')));
      const low = S.sensors.filter(U.isLow).length;
      const leaks = S.sensors.filter(s => s.temp != null && !U.isMissing(s));
      const where = leaks.length ? `At the hub · sensors ${leaks.map(s => F.temp(s.temp)).join(', ')}` : 'At the hub';
      H('#stat', `<div title="${esc(where)}"><b>${F.temp(S.hub.temp)}</b><span>Hub temp</span></div><div><b>${S.hub.hum != null ? Math.round(S.hub.hum) + '%' : '—'}</b><span>Hub humidity</span></div><div><b style="color:${low ? 'var(--warn)' : 'inherit'}">${low}</b><span>Low batteries</span></div>`);
      H('#health', U.healthHTML());
      H('#tl', U.timeline(S.events.slice(0, 8)));
    });
    U.bindHome(main);
  },
  devices(main) {
    main.innerHTML = `<section class="card" style="margin-bottom:var(--gap)"><div class="eyebrow">${I('link')} Add a sensor${M.SV_STATE.role === 'owner' ? ' <button type="button" class="btn btn-sm" data-addman>' + I('plus') + ' Add by hand</button>' : ''}</div><div id="pair"></div></section><div id="byroom" class="stack"></div>`;
    M.renderPairing(main.querySelector('#pair'));
    M.mount(main, () => {
      const missing = S.sensors.filter(U.isMissing), groups = {};
      S.sensors.filter(s => !U.isMissing(s)).forEach(s => (groups[s.room || 'No room yet'] ||= []).push(s));
      const card = s => U.devCard(s, { manage: true });
      M.setHTML(main.querySelector('#byroom'), (S.hub.id ? `<section class="card"><div class="eyebrow">${I('server')} Hub</div><div class="rooms">${U.hubCard({ manage: true })}</div></section>` : '')
        + (missing.length ? `<section class="card"><div class="eyebrow">${I('alert')} Missing · ${missing.length}</div>
          <div class="missing-note"><span>Not heard from in over ${S.settings.sensorMissingH || 24} h. Try a fresh battery, or remove it if it's gone for good.</span></div>
          <div class="rooms">${missing.map(card).join('')}</div></section>` : '')
        + (Object.entries(groups).map(([room, list]) => `<section class="card"><div class="eyebrow">${esc(room)}</div><div class="rooms">${list.map(card).join('')}</div></section>`).join('')
        || '<section class="card"><div class="empty">No sensors yet. Sensors already paired with the hub appear when they next report in, or add one by hand.</div></section>'));
    });
    main.addEventListener('click', e => {
      const r = e.target.closest('[data-rm]'), ed = e.target.closest('[data-edit]');
      if (r) M.confirmRemoveSensor(+r.dataset.rm); if (ed) M.sensorDetails(+ed.dataset.edit);
      if (e.target.closest('[data-hubedit]')) M.hubDetails();
      if (e.target.closest('[data-addman]')) M.addSensorDialog();
    });
  },
  activity(main) {
    let f = 'all', older = [], done = false; const sets = U.ACTIVITY_SETS;
    main.innerHTML = `<div class="chips" id="chips"></div>${M.SV_STATE.role === 'owner' ? `<div class="wire-link"><a href="#wire">${I('terminal')} Live protocol log</a></div>` : ''}<section class="card"><div id="tl"></div><div class="group-actions" id="more"></div></section>`;
    const chips = () => main.querySelector('#chips').innerHTML = Object.keys(sets).map(k => `<button class="chip ${k === f ? 'on' : ''}" data-f="${k}">${k[0].toUpperCase() + k.slice(1)}</button>`).join('');
    chips(); main.querySelector('#chips').onclick = e => { const b = e.target.closest('[data-f]'); if (b) { f = b.dataset.f; chips(); M.emit(); } };
    M.mount(main, () => {
      const all = [...S.events, ...older];
      main.querySelector('#tl').innerHTML = U.timeline(all.filter(e => !sets[f] || sets[f].includes(e.kind)), M.SV_STATE.role === 'owner');
      main.querySelector('#more').innerHTML = done ? '' : '<button type="button" class="btn" data-more>Load older</button>';
    });
    main.querySelector('#more').addEventListener('click', async e => {
      if (!e.target.closest('[data-more]')) return;
      const all = [...S.events, ...older], last = all[all.length - 1];
      const r = await M.api('GET', `/events?limit=200${last ? '&before=' + last.id : ''}`);
      older = older.concat(r.events.map(x => ({ ...x, t: x.t * 1000 }))); done = r.events.length < 200; M.emit();
    });
  },
  wire(main) {
    if (M.SV_STATE.role !== 'owner') { main.innerHTML = '<section class="card"><div class="empty">Only owners can see the protocol log.</div></section>'; return; }
    const LABELS = { all: 'All', mqtt: 'MQTT', messages: 'Messages', connections: 'Connections', http: 'HTTP' };
    const GROUPS = { all: null, mqtt: ['connect', 'connack', 'subscribe', 'publish', 'puback', 'pubrel', 'sent', 'ping', 'disconnect', 'packet'], messages: ['publish', 'sent'], connections: ['tcp', 'tls', 'tls_failed', 'connect', 'connack', 'disconnect', 'closed'], http: ['http', 'http_reply'] };
    let group = 'all', text = '', open = new Set();
    main.innerHTML = `<section class="card wire-card"><div class="eyebrow">${I('terminal')} Protocol log <span class="wire-live" id="live"></span></div>
      <div class="wire-tools"><div class="chips" id="wchips"></div>
        <input class="in in-sm" id="wq" placeholder="Search (topic, field, value…)" aria-label="Search the protocol log">
        <button type="button" class="btn btn-sm" id="wpause">Pause</button><button type="button" class="btn btn-sm" id="wclear">Clear view</button><button type="button" class="btn btn-sm" id="wdl">${I('list')} Download</button></div>
      <div class="f-help">Newest first. Click an entry to see everything. Contains your hub's ID, SIM number and Wi-Fi name: redact before sharing. Also on the server: <code>docker compose logs -f openroost</code> with <code>OPENROOST_WIRE_STDOUT=1</code>, or <code>data/wire.jsonl</code> (Settings → System).</div>
      <ol class="wire" id="wl"></ol></section>`;
    const chips = () => main.querySelector('#wchips').innerHTML = Object.keys(GROUPS).map(k => `<button class="chip ${k === group ? 'on' : ''}" data-g="${k}">${LABELS[k]}</button>`).join('');
    chips();
    main.querySelector('#wchips').onclick = e => { const b = e.target.closest('[data-g]'); if (b) { group = b.dataset.g; chips(); M.emit(); } };
    main.querySelector('#wq').oninput = e => { text = e.target.value.toLowerCase(); M.emit(); };
    main.querySelector('#wpause').onclick = e => { S.wirePaused = !S.wirePaused; e.target.textContent = S.wirePaused ? 'Resume' : 'Pause'; M.emit(); };
    main.querySelector('#wclear').onclick = () => { S.wire.length = 0; open.clear(); M.emit(); };
    main.querySelector('#wdl').onclick = () => M.download(`openroost-wire-${new Date().toISOString().slice(0, 19).replace(/:/g, '')}.jsonl`, S.wire.map(w => JSON.stringify(w)).join('\n'), 'application/x-ndjson');
    main.querySelector('#wl').onclick = e => { const li = e.target.closest('[data-seq]'); if (li && !e.target.closest('pre')) { const k = +li.dataset.seq; open.has(k) ? open.delete(k) : open.add(k); M.emit(); } };
    const short = v => { const s = v === undefined ? '(empty)' : typeof v === 'string' ? v : String(JSON.stringify(v)); return s.length > 220 ? s.slice(0, 220) + '…' : s; };
    const summary = w => ({
      tcp: `TCP connection on :${w.port}`, tls: `TLS ${w.version || ''} · ${w.cipher || ''}${w.sni ? ' · SNI ' + w.sni : ''}`, tls_failed: `TLS failed: ${w.error}`,
      http: w.request, http_reply: `→ ${w.status}${w.body ? ' ' + w.body : ''}`,
      connect: `CONNECT ${w.clientId} · keepalive ${w.keepalive}s${w.username ? ' · user ' + w.username : ''}`, connack: `CONNACK ${w.code}${w.note ? ' (' + w.note + ')' : ''}`,
      subscribe: 'SUBSCRIBE ' + (w.topics || []).map(t => `${t.topic} (q${t.qos})`).join(', '),
      publish: `${w.topic} · ${w.json !== undefined ? short(w.json) : w.text !== undefined ? short(w.text) : w.hex ? 'hex ' + short(w.hex) : '(empty)'}`,
      sent: `→ ${w.topic} · ${w.empty ? '(empty)' : short(w.json ?? w.text ?? w.hex)}${w.note ? ' — ' + w.note : ''}`,
      puback: `PUBACK ${w.pid}`, pubrel: `PUBREL ${w.pid}`, ping: 'PINGREQ → PINGRESP', disconnect: 'DISCONNECT', closed: `Connection closed: ${w.reason}`, packet: `Packet type ${w.type}${w.note ? ' (' + w.note + ')' : ''}`,
    }[w.kind] || w.kind);
    M.mount(main, () => {
      main.querySelector('#live').innerHTML = S.wirePaused ? '<span class="pill warn"><span class="d"></span>Paused</span>' : S.live ? '<span class="pill"><span class="d"></span>Live</span>' : '<span class="pill off"><span class="d"></span>Reconnecting</span>';
      if (S.wirePaused) return;
      const g = GROUPS[group], list = S.wire.filter(w => (!g || g.includes(w.kind)) && (!text || JSON.stringify(w).toLowerCase().includes(text))).slice(-500).reverse();
      main.querySelector('#wl').innerHTML = list.map(w => `<li data-seq="${w.seq}" class="wk-${esc(w.kind)}"><span class="wt">${new Date(w.t * 1000).toLocaleTimeString([], { hour12: false })}.${String(Math.round(w.t * 1000) % 1000).padStart(3, '0')}</span>
        <span class="wkind">${esc(w.kind)}</span><span class="wip">${esc(w.ip)}</span><span class="wsum">${esc(summary(w))}</span>
        ${open.has(w.seq) ? `<pre>${esc(JSON.stringify(w, null, 2))}</pre>` : ''}</li>`).join('') || '<li class="empty">Nothing yet. Entries appear as soon as the hub connects.</li>';
    });
    M.api('GET', '/debug/wire?limit=3000').then(r => { const seen = new Set(S.wire.map(w => w.seq)); S.wire = [...r.entries.filter(w => !seen.has(w.seq)), ...S.wire].sort((a, b) => a.seq - b.seq); M.emit(); }).catch(err => M.toast(esc(err.message), 'err'));
  },
  settings(main, sub) {
    sub = M.SECTIONS.some(s => s.id === sub) ? sub : 'notifications';
    const planned = s => s.feature && M.isPlanned(s.feature);
    main.innerHTML = `<div class="set-wrap"><nav class="set-nav">${M.SECTIONS.map(s => `<a href="#settings/${s.id}" class="${s.id === sub ? 'on' : ''}${planned(s) ? ' blocked' : ''}"><span class="ico">${I(s.icon)}</span><span>${s.title}${planned(s) ? '<small>Planned, unsupported</small>' : ''}</span></a>`).join('')}</nav><div id="set"></div></div>`;
    M.renderSettings(main.querySelector('#set'), sub);
    const nav = main.querySelector('.set-nav'), on = nav.querySelector('a.on');
    if (on && nav.scrollWidth > nav.clientWidth) nav.scrollLeft = on.offsetLeft - (nav.clientWidth - on.offsetWidth) / 2;
  },
};

M.gate(() => {
  document.getElementById('mark').innerHTML = I('home');
  M.userMenu(document.getElementById('user'));
  route = U.startRouter(pages, 'home', renderHeader);
  M.on(renderHeader);
});
