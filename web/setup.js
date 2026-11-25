/* OpenRoost360 first-run setup (setup.html). Every call before the owner exists carries the one-time
   setup code that the server prints at start-up. Planned features are shown greyed out. */
const M = OpenRoost, S = M.S, I = M.icon, esc = M.esc, SV = M.svc;
document.getElementById('mark').innerHTML = I('home');

const st = {
  site: 'Home', unit: 'F', code: '', codeOk: false, user: 'admin', pass: '', pass2: '', err: '',
  ph: SV.newPihole(), checks: null, checksRunning: false, serverIp: '', dns: 'all',
  path: null, watchFrom: 0, state: null, hubFound: false, sensors: {},   // sensors: id -> {name, room}
  mail: SV.newMail(),
  mx: { want: null, hs: '', user: '', pass: '', room: '', signedIn: false, tested: false },
};
const bundled = () => call('bundled');
const call = (path, body = {}) => M.api('POST', '/setup/' + path, { code: st.code.trim(), ...body });
const phPayload = () => ({ ...st.ph });

const STEPS = [
  { id: 'welcome', title: 'Welcome to OpenRoost360', render: welcome, ok: () => st.site.trim() },
  { id: 'account', title: 'Create the owner account', render: account,
    ok: () => /^[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}$/.test(st.code.trim()) && /^[A-Za-z0-9._-]{3,32}$/.test(st.user.trim()) && st.pass.length >= 12 && st.pass === st.pass2,
    why: 'Enter the setup code, a username and matching passwords (12+ characters).',
    leave: async () => { await call('verify'); st.codeOk = true; } },
  { id: 'pihole', title: 'Choose a Pi-hole', render: piholeChoice, ok: () => !!st.ph.mode, why: 'Choose which Pi-hole to use.' },
  { id: 'pihole-setup', title: () => st.ph.mode === 'bundled' ? 'OpenRoost\'s Pi-hole' : 'Connect your Pi-hole', render: el => SV.renderPiholeSetup(el, st.ph, () => { st.checks = null; nav(); }, { test: (url, password) => call('pihole', { url, password }), bundled }),
    ok: () => SV.piholeReady(st.ph), why: () => SV.piholeWhy(st.ph) },
  { id: 'server', title: 'Check this server', render: server, ok: () => st.checks && !st.checks.some(c => c.status === 'fail' && ['listener', 'time', 'pihole'].includes(c.id) || (c.status === 'fail' && c.id.startsWith('dns:'))), why: 'Fix the failed checks to continue.' },
  { id: 'network', title: 'Point the hub at OpenRoost', render: network, ok: () => true },
  { id: 'hub', title: 'Find your SmartBase', render: hub, ok: () => st.hubFound, why: 'Waiting for your hub to connect.' },
  { id: 'sensors', title: 'Name your sensors', render: sensors, ok: () => true },
  { id: 'keypad', title: 'Keypad & alarm settings', render: keypad, ok: () => true },
  { id: 'email', title: 'Email alerts', render: mailChoice, ok: () => !!st.mail.mode, why: 'Choose how OpenRoost should send email.' },
  { id: 'email-setup', skip: () => st.mail.mode === 'off', title: () => ({ 'relay-existing': 'Connect your mail relay', account: 'Connect your email account', 'relay-start': 'OpenRoost\'s mail relay' })[st.mail.mode] || 'Set up email',
    render: el => SV.renderMailSetup(el, st.mail, nav, { recipients: true, test: m => call('mail-test', { mail: m, site: st.site }), bundled }), ok: () => !SV.mailWhy(st.mail, true), why: () => SV.mailWhy(st.mail, true) },
  { id: 'matrix', title: 'Matrix alerts', render: matrix, ok: () => st.mx.want === false || (st.mx.want && st.mx.signedIn && /^[#!].+:.+/.test(st.mx.room)),
    why: () => st.mx.want == null ? 'Choose whether to send alerts to Matrix.' : !st.mx.signedIn ? 'Sign the bot in first.' : 'Enter the alert room.' },
  { id: 'done', title: 'You’re all set', render: done, ok: () => true },
];
let cur = 0, poll = null;
const body = document.getElementById('body');
const titleOf = x => typeof x.title === 'function' ? x.title() : x.title;

function go(i, dir = 1) {
  clearInterval(poll); poll = null;
  i = Math.max(0, Math.min(STEPS.length - 1, i));
  while (STEPS[i].skip && STEPS[i].skip() && i > 0 && i < STEPS.length - 1) i += dir;
  cur = i;
  const s = STEPS[cur], shown = STEPS.filter(x => !(x.skip && x.skip())), pos = shown.indexOf(s);
  document.getElementById('stepl').textContent = `Step ${pos + 1} of ${shown.length}`;
  document.getElementById('steph').textContent = titleOf(s);
  const bar = document.getElementById('bar'); bar.style.setProperty('--n', shown.length);
  bar.innerHTML = shown.map((x, i) => `<i class="${i < pos ? 'done' : i === pos ? 'on' : ''}" title="${esc(titleOf(x))}"></i>`).join('');
  body.innerHTML = ''; s.render(body); nav(); window.scrollTo(0, 0);
}
function nav() {
  const s = STEPS[cur], ok = !!s.ok(), next = document.getElementById('next');
  document.getElementById('back').hidden = cur === 0;
  next.disabled = !ok;
  next.textContent = cur === STEPS.length - 1 ? 'Finish and open the dashboard' : (s.id === 'sensors' && !Object.values(st.sensors).some(x => x.name)) ? 'Skip for now' : (s.id === 'email' && st.mail.mode === 'off') ? 'Skip email' : 'Continue';
  document.getElementById('hint').textContent = ok ? '' : (typeof s.why === 'function' ? s.why() : s.why || '');
}
document.getElementById('back').onclick = () => go(cur - 1, -1);
document.getElementById('next').onclick = async () => {
  const s = STEPS[cur], btn = document.getElementById('next');
  if (cur === STEPS.length - 1) return finish();
  if (s.leave) {
    btn.disabled = true;
    try { await s.leave(); } catch (e) { st.err = e.message; btn.disabled = false; M.toast(esc(e.message), 'err', 6000); s.render(body); return; }
  }
  go(cur + 1);
};

function welcome(el) {
  el.innerHTML = `<p class="su-lead">OpenRoost360 stands in for Roost's shut-down cloud, so your SmartBase, keypad and sensors keep working on your own network. This takes about 15 minutes.</p>
    <div class="eyebrow" style="margin:6px 0 0">What you'll need</div>
    <ul class="su-list">
      <li>${I('server')}<div><b>This server running OpenRoost</b><span>You're looking at it, so this part is done.</span></div></li>
      <li>${I('link')}<div><b>A Pi-hole (v6)</b><span>Yours (with an app password), or the one OpenRoost can run for you. OpenRoost adds two DNS lines so the hub finds this server instead of Roost's cloud.</span></div></li>
      <li>${I('home')}<div><b>Your SmartBase, on your Wi-Fi</b><span>Set up earlier with the Roost app.</span></div></li>
      <li>${I('wifi')}<div><b>Access to your router's settings</b><span>Only if the hub doesn't already use your Pi-hole for DNS.</span></div></li>
    </ul>
    <div class="eyebrow" style="margin:6px 0 0">About your home</div>
    <label class="su-f"><span>Home name</span><input class="in" id="site" value="${esc(st.site)}" maxlength="40"></label>
    <div class="su-f"><span>Temperature</span><span class="seg" role="radiogroup" aria-label="Temperature unit">
      ${[['F', '°F'], ['C', '°C']].map(([v, l]) => `<label><input type="radio" name="unit" value="${v}"${st.unit === v ? ' checked' : ''}><span>${l}</span></label>`).join('')}</span></div>`;
  el.querySelector('#site').oninput = e => { st.site = e.target.value; nav(); };
  el.querySelectorAll('[name=unit]').forEach(r => r.onchange = () => { st.unit = r.value; });
}

function account(el) {
  el.innerHTML = `<p>This is the owner account for the web app. It's separate from your keypad PINs, and its password is stored only as a salted Argon2id hash on the server.</p>
    <label class="su-f"><span>Setup code</span><input class="in" id="code" value="${esc(st.code)}" placeholder="XXXX-XXXX-XXXX" autocomplete="off" spellcheck="false" maxlength="14"></label>
    <span class="f-help su-help">Printed in the OpenRoost server's log when it starts, and saved in its data folder as <code>SETUP-CODE.txt</code>.</span>
    <label class="su-f"><span>Username</span><input class="in" id="u" value="${esc(st.user)}" autocomplete="username" maxlength="32"></label>
    <span class="f-help su-help">3–32 letters, digits, dots, dashes or underscores. You'll sign in with it.</span>
    <label class="su-f"><span>Password</span><input class="in" id="p" type="password" autocomplete="new-password" value="${esc(st.pass)}" maxlength="256"></label>
    <label class="su-f"><span>Confirm password</span><input class="in" id="p2" type="password" autocomplete="new-password" value="${esc(st.pass2)}" maxlength="256"></label>
    <span class="f-help su-help">At least 12 characters. A short sentence works well. Can't contain your username.</span>
    <div class="su-err" id="err" role="alert">${esc(st.err)}</div>
    <div class="note">${I('shield')} <span>Sign-in with Authentik and two-factor codes can be added later in <b>Settings → Account</b>. This password account stays as a break-glass login.</span></div>`;
  const err = el.querySelector('#err');
  el.querySelectorAll('input').forEach(i => i.oninput = () => {
    st.code = el.querySelector('#code').value; st.user = el.querySelector('#u').value; st.pass = el.querySelector('#p').value; st.pass2 = el.querySelector('#p2').value; st.err = '';
    err.textContent = st.pass && st.pass.length < 12 ? 'Use at least 12 characters.' : st.pass2 && st.pass !== st.pass2 ? 'Passwords don’t match.'
      : st.pass && st.user.trim() && st.pass.toLowerCase().includes(st.user.trim().toLowerCase()) ? 'The password can’t contain your username.' : '';
    nav();
  });
}

function piholeChoice(el) {
  el.innerHTML = `<p>The hub still looks up Roost's cloud by name. A Pi-hole answers those lookups with this server's address, so the hub connects here instead. Which Pi-hole should OpenRoost use?</p>${SV.choiceCards(SV.PH_OPTS, st.ph.mode, 'ph')}
    <p class="f-help">You can switch later in Settings → Hub &amp; network.</p>`;
  el.querySelectorAll('[data-choice]').forEach(b => b.onclick = () => {
    if (st.ph.mode !== b.dataset.v) { st.ph = Object.assign(SV.newPihole(), { mode: b.dataset.v }); st.checks = null; }
    piholeChoice(el); nav();
  });
}

const STATUS_ICON = { ok: 'check', fail: 'x', unknown: 'alert', wait: 'alert', planned: 'alert' };
function chkRow(c) {
  const cls = { ok: 'ok', fail: 'fail', unknown: 'wait', wait: 'wait', planned: 'wait' }[c.status] || 'wait';
  const act = c.status === 'fail' && c.fix ? `<button type="button" class="btn btn-sm btn-primary" data-fix="${esc(c.fix)}">Fix it</button>` : '';
  return `<div class="su-chk ${cls}"${c.status === 'planned' ? M.plannedAttrs(c.id === 'boot' ? 'pihole.bundled' : 'pihole.bundled') : ''}><span class="st">${I(STATUS_ICON[c.status] || 'alert')}</span><div><b>${esc(c.title)}</b><small>${esc(c.detail)}</small></div>${act}</div>`;
}
async function runChecks(el) {
  st.checksRunning = true; drawChecks(el); nav();
  try { const r = await call('checks', { ph: phPayload() }); st.checks = r.checks; st.serverIp = r.serverIp; }
  catch (e) { st.checks = [{ id: 'listener', title: 'Server checks', status: 'fail', detail: e.message }]; }
  st.checksRunning = false; drawChecks(el); nav();
}
function drawChecks(el) {
  const box = el.querySelector('#checks'); if (!box) return;
  box.innerHTML = st.checksRunning ? '<div class="scan-wait"><span class="spin"></span> Running checks…</div>' : (st.checks || []).map(chkRow).join('')
    + (st.manual && (st.checks || []).some(c => c.id.startsWith('dns:') && c.status === 'fail') ? M.manualDnsHTML(st.manual) : '');
  M.bindCopy(box);
  const bad = (st.checks || []).filter(c => c.status === 'fail').length;
  el.querySelector('#chk-sum').innerHTML = st.checksRunning ? '' : bad ? `<b style="color:var(--crit)">${bad} check${bad > 1 ? 's' : ''} need attention.</b>` : '<b style="color:var(--ok)">Server is ready.</b>';
  box.querySelectorAll('[data-fix]').forEach(b => b.onclick = async () => {
    b.disabled = true; b.innerHTML = '<span class="spin"></span>';
    try {
      const r = await call('fix/' + b.dataset.fix, { ph: phPayload() });
      if (r.manual) { st.manual = r; drawChecks(el); return; }
      M.toast(b.dataset.fix === 'dns' ? 'DNS lines added to OpenRoost\'s Pi-hole' : 'Port redirect added');
    } catch (e) { M.toast(esc(e.message), 'err', 6000); }
    runChecks(el);
  });
}
function server(el) {
  el.innerHTML = `<p>These checks make sure every piece is in place before we look for the hub. The port redirect and hub checks finish once the hub connects.</p>
    <div class="su-checks" id="checks"></div>
    <div class="su-row"><span id="chk-sum" style="margin-right:auto"></span><button type="button" class="btn btn-sm" id="rerun">Run checks again</button></div>`;
  el.querySelector('#rerun').onclick = () => runChecks(el);
  if (!st.checks) runChecks(el); else drawChecks(el);
}

function network(el) {
  const srv = st.serverIp || 'this server', ip = st.ph.mode === 'bundled' ? srv : (SV.phHostOf(st.ph) || 'your Pi-hole');
  const opts = [
    ['already', 'My router already uses this Pi-hole', `Your router already hands out ${ip} as DNS, so the hub uses it too. Nothing to change.`],
    ['all', 'Every device uses Pi-hole', `In your router's DHCP settings, set the DNS server to ${ip}.`],
    ['hub', 'Only the hub uses Pi-hole', `Give the hub a DHCP reservation with DNS set to ${ip}. Leaves your other devices alone (not every router can do this).`],
  ];
  const dns = (st.checks || []).filter(c => c.id.startsWith('dns:'));
  el.innerHTML = `<p>The Pi-hole now answers the Roost cloud names with ${esc(srv)}, but only for devices that ask it. Make sure the hub does:</p>
    <div class="su-choices su-choices-3" role="radiogroup">${opts.map(([v, t, d]) => `<button type="button" role="radio" aria-checked="${st.dns === v}" class="su-choice${st.dns === v ? ' on' : ''}" data-v="${v}"><b>${t}</b><span>${esc(d)}</span></button>`).join('')}</div>
    <div class="su-checks">${dns.map(chkRow).join('')}</div>
    <div class="note">${I('alert')} <span>The next step confirms the hub uses Pi-hole: it shows up here once it connects.</span></div>`;
  el.querySelectorAll('[data-v]').forEach(b => b.onclick = () => { st.dns = b.dataset.v; network(el); });
}

function hub(el) {
  el.innerHTML = `<p>Is your SmartBase already connected to your Wi-Fi?</p>
    <div class="su-choices" role="radiogroup">
      <button type="button" role="radio" aria-checked="${st.path === 'existing'}" class="su-choice${st.path === 'existing' ? ' on' : ''}" data-path="existing"><b>${I('wifi')} Yes, it's on my Wi-Fi</b><span>It was set up with the Roost app and hasn't been reset.</span></button>
      <button type="button" role="radio" class="su-choice" data-path="new"${M.plannedAttrs('hub.wifi')}><b>${I('plus')} No, it's new or reset</b><span>It needs to join your Wi-Fi first, through its own setup network.</span></button>
    </div><div id="hubflow" class="su-card"></div>`;
  el.querySelectorAll('[data-path="existing"]').forEach(b => b.onclick = () => { st.path = 'existing'; if (!st.watchFrom) st.watchFrom = Date.now() / 1000 - 600; hub(el); });
  if (st.path === 'existing') watch(el.querySelector('#hubflow'));
}
function watch(f) {
  const draw = () => {
    const s = st.state || {}, L = s.listener || {}, h = s.hub || {}, sess = L.session;
    const after = x => x && x.t >= st.watchFrom;
    const steps = [
      [after(L.lastTime) || !!sess, `Answered the hub's time request${L.lastTime ? ' from ' + esc(L.lastTime.peer) : ''}`],
      [!!sess || after(L.lastConnect), `MQTT connection from hub ${esc((sess || L.lastConnect || {}).id || '')}`],
      [!!(sess && sess.subscribed && sess.subscribed.length), 'Hub subscribed to /config and /commands; sent the empty /config'],
      [!!(h.firmware && h.firmware.hub && h.lastSeen >= st.watchFrom), 'Hub status received'],
    ];
    const n = steps.findIndex(x => !x[0]); const doneAll = n === -1;
    st.hubFound = doneAll && !!h.id;
    const nat = s.nat || [], natOk = nat.some(x => x.status === 'ok'), seen = s.hubSeen;
    const natBox = st.hubFound ? '' : `<div class="su-card nat-box"><div class="eyebrow su-eyebrow">Port 443 → OpenRoost</div>
      ${natOk ? `<div class="su-chk ok su-chk-tight"><span class="st">${I('check')}</span><div><b>Redirect in place</b><small>${nat.filter(x => x.status === 'ok').map(x => esc(x.ip)).join(', ')}: the hub's port 443 goes to the listener</small></div></div>`
        : `<p class="f-help">The hub talks to Roost's cloud on port 443, so this server sends the hub's port 443 traffic to OpenRoost's listener. That needs the hub's IP address.
          ${seen ? `OpenRoost spotted <b>${esc(seen.ip)}</b> asking Pi-hole for Roost's cloud; that's almost certainly the hub.` : 'Find it in your router\'s list of devices (it may show as an Espressif or Roost device), and give it a DHCP reservation so it keeps it.'}</p>
          ${nat.length ? `<div class="f-help err-t">${nat.map(x => `${esc(x.ip)}: ${x.status === 'unknown' ? 'can\'t check the rule (OpenRoost needs the NET_ADMIN permission)' : 'no redirect yet'}`).join(' · ')}</div>` : ''}
          <form class="su-row" data-natf><input class="in" name="ip" inputmode="decimal" placeholder="Hub IP, e.g. 192.168.1.50" value="${esc(st.natIp ?? (s.hubIp || (seen && seen.ip) || ''))}" required pattern="\\d{1,3}(\\.\\d{1,3}){3}" style="flex:1;min-width:160px" aria-label="The hub's IP address"><button class="btn btn-primary btn-sm">Add the redirect</button></form>
          <p class="f-help">OpenRoost keeps this rule in place from now on (after reboots and firewall reloads). You can also set <code>OPENROOST_HUB_IP</code> in <code>.env</code>.</p>`}</div>`;
    const html = `<ol class="su-steps">
        <li class="${doneAll ? 'done' : 'cur'}"><div><b>Connect the hub</b><p>If it's already connected through Pi-hole it shows up right away. Otherwise unplug the SmartBase for 10 seconds and plug it back in: when it starts it asks Pi-hole for Roost's cloud and gets sent here.</p></div></li>
        <li class="${doneAll ? 'done' : 'cur'}"><div><b>Listener detects the hub</b><p>Usually within a minute.</p>
          <ul class="su-log" aria-live="polite">${steps.map(([ok, t], i) => ok ? `<li>${I('check')}<span>${t}</span></li>` : i === n ? `<li class="wait"><span class="spin"></span><span>Waiting for the hub…</span></li>` : '').join('')}</ul></div></li>
      </ol>
      ${L.rejected ? `<div class="note note-blocked">${I('alert')} <span>Refused a device claiming to be hub ${esc(L.rejected.id)} because another hub is already trusted.</span></div>` : ''}
      ${st.hubFound ? `<div class="su-hub"><div class="su-hub-h">${I('check')}<div><b>Found your SmartBase</b><div class="f-help">OpenRoost will trust only this hub from now on.</div></div></div>
        <dl class="kv"><div><dt>Hub ID</dt><dd>${esc(h.id)}</dd></div><div><dt>Address</dt><dd>${esc(h.ip || '—')}</dd></div><div><dt>Firmware</dt><dd>${esc(h.firmware.hub)}</dd></div>
        <div><dt>Wi-Fi</dt><dd>${h.wifi ? esc(h.wifi.ssid) + ' · ' + h.wifi.rssi + ' dBm' : '—'}</dd></div><div><dt>Power</dt><dd>${h.power === 'mains' ? 'Mains' : h.power === 'battery' ? 'Battery' : '—'}</dd></div></dl></div>` : ''}
      ${natBox}
      ${!st.hubFound ? `<details class="note"><summary><b>Taking more than 2 minutes?</b></summary><ul class="steps"><li>Check the hub really uses your Pi-hole for DNS (previous step). Some routers only apply DHCP changes after the hub renews its lease, so restart it once more.</li><li>Look in Pi-hole's query log for the hub's address asking for <code>us-central1-roostprod.cloudfunctions.net</code>.</li><li>Make sure the port redirect above is in place for the hub's address.</li><li>The light ring should be solid, not blinking. Blinking means pairing or setup mode.</li></ul></details>` : ''}`;
    // only touch the page when something changed: rebuilding it every poll closed the dropdown and scrolled the page
    const typing = f.contains(document.activeElement) && document.activeElement.matches('input');
    if (!typing && M.setHTML(f, html)) {
      const form = f.querySelector('[data-natf]');
      if (form) {
        form.elements.ip.oninput = () => { st.natIp = form.elements.ip.value; };
        form.onsubmit = async e => {
          e.preventDefault(); const b = form.querySelector('button'); b.disabled = true; b.innerHTML = '<span class="spin"></span>';
          try { await call('fix/nat', { ip: form.elements.ip.value.trim() }); M.toast('Port redirect added. The hub connects within a minute or two.'); st.natIp = undefined; await tick(); }
          catch (err) { M.toast(esc(err.message), 'err', 8000); b.disabled = false; b.textContent = 'Add the redirect'; }
        };
      }
    }
    nav();
  };
  const tick = async () => { try { st.state = await call('state'); } catch (e) { /* keep last */ } draw(); };
  draw(); tick(); poll = setInterval(tick, 2000);
}

const PLACEHOLDER = { door: 'e.g. Front Door', motion: 'e.g. Hallway Motion', leak: 'e.g. Water Heater', keypad: 'e.g. Keypad', smoke: 'e.g. Smoke Listener' };
function sensors(el) {
  const seen = {};
  const draw = () => {
    const list = (st.state && st.state.sensors) || [];
    const rows = list.map(s => {
      const x = st.sensors[s.id] ||= { name: '', room: '' };
      const ping = seen[s.id] && seen[s.id] !== s.lastSeen && Date.now() / 1000 - s.lastSeen < 6;
      seen[s.id] = s.lastSeen;
      return `<div class="su-sen${ping ? ' ping' : ''}" data-id="${s.id}">
        <span class="ico">${I(M.TYPE_ICON[s.type] || 'chip')}</span>
        <input class="in" data-name value="${esc(x.name)}" placeholder="${esc(PLACEHOLDER[s.type] || 'Name')}" aria-label="Name for ${esc(s.typeLabel)} in slot ${s.id}" maxlength="40">
        <div class="combo"><input class="in" data-room value="${esc(x.room)}" placeholder="Room" autocomplete="off" role="combobox" aria-expanded="false" aria-autocomplete="list" aria-label="Room"><ul class="combo-list" role="listbox" hidden></ul></div>
        <div class="meta-l"><span>${esc(s.typeLabel)}</span><span>Slot <code>id ${s.id}</code></span><span>${esc(s.stateLabel || '')}</span><span class="ping-l">● Just reported</span></div></div>`;
    });
    if (el.querySelector('.su-sens') && el.querySelectorAll('.su-sen').length === list.length) {
      list.forEach(s => { const r = el.querySelector(`.su-sen[data-id="${s.id}"]`); const ping = Date.now() / 1000 - s.lastSeen < 6 && r.dataset.last && +r.dataset.last !== s.lastSeen; if (ping) { r.classList.add('ping'); setTimeout(() => r.classList.remove('ping'), 4000); } r.dataset.last = s.lastSeen; });
      return;
    }
    el.innerHTML = `<p>These sensors are already paired with your hub. Roost kept their names in its cloud, so they're gone. Give them names again.</p>
      <div class="note">${I('zap')} <span>Not sure which is which? Open a door or walk past a motion sensor. Its row lights up here when the hub reports it.</span></div>
      <div class="su-sens">${rows.join('') || '<div class="scan-wait"><span class="spin"></span> Waiting for sensors to report in… Open a door or trigger a sensor to make it show up.</div>'}</div>
      <div class="f-help">Sensors report when they check in or trip. You can name the rest later from Devices.</div>`;
    el.querySelectorAll('.su-sen').forEach(r => {
      const x = st.sensors[r.dataset.id]; r.dataset.last = (list.find(s => s.id == r.dataset.id) || {}).lastSeen;
      r.querySelector('[data-name]').oninput = e => { x.name = e.target.value.trim(); nav(); };
      const room = r.querySelector('[data-room]'); M.roomCombo(r.querySelector('.combo'));
      const sync = () => { x.room = room.value.trim(); };
      room.addEventListener('input', sync); room.addEventListener('change', sync); room.addEventListener('blur', () => setTimeout(sync, 200));
    });
  };
  const tick = async () => { try { st.state = await call('state'); } catch (e) { /* keep last */ } draw(); };
  draw(); tick(); poll = setInterval(tick, 2500);
}

function keypad(el) {
  el.innerHTML = `<p>Your keypad PINs, entry and exit delays, and door chime are stored on the hub itself, so <b>they keep working as they are</b>.</p>
    <div class="su-checks">
      <div class="su-chk ok"><span class="st">${I('check')}</span><div><b>Keypad PINs</b><small>Arming and disarming at the keypad works. OpenRoost sees which PIN was used (owner, guest or hostage).</small></div></div>
      <div class="su-chk ok"><span class="st">${I('check')}</span><div><b>Alarms & alerts</b><small>Intrusion, fire, leak, panic and hostage PIN reach OpenRoost.</small></div></div>
      <div class="su-chk wait"${M.plannedAttrs('hub.pins')}><span class="st">${I('alert')}</span><div><b>Changing PINs, delays and chime from OpenRoost</b><small>Needs the hub's settings format, which isn't cracked yet.</small></div></div>
    </div>`;
}

function mailChoice(el) {
  el.innerHTML = `<p>OpenRoost emails alerts like alarms, leaks and a hub going offline. How should it send email?</p>${SV.choiceCards(SV.MAIL_OPTS, st.mail.mode, 'mail')}
    <p class="f-help">You can change this later in Settings → Notifications.</p>`;
  el.querySelectorAll('[data-choice]').forEach(b => b.onclick = () => {
    if (st.mail.mode !== b.dataset.v) st.mail = Object.assign(SV.newMail(), { mode: b.dataset.v, to: st.mail.to });
    mailChoice(el); nav();
  });
}

function matrix(el) {
  const m = st.mx;
  el.innerHTML = `<p>OpenRoost can post alerts to a Matrix room (Element on every family phone). It uses a separate bot account on your homeserver.</p>
    <div class="su-choices" role="radiogroup">
      <button type="button" role="radio" aria-checked="${m.want === true}" class="su-choice${m.want === true ? ' on' : ''}" data-mx="1"><b>${I('chip')} Yes, send alerts to Matrix</b><span>You'll need the homeserver, a bot account and an alert room the bot is invited to.</span></button>
      <button type="button" role="radio" aria-checked="${m.want === false}" class="su-choice${m.want === false ? ' on' : ''}" data-mx="0"><b>${I('x')} Not now</b><span>You can set it up later in Settings → Notifications.</span></button>
    </div>
    ${m.want ? `<div class="su-card">
      <label class="su-f"><span>Homeserver</span><input class="in" id="hs" type="url" value="${esc(m.hs)}" placeholder="https://matrix.example.org" autocomplete="off"></label>
      <label class="su-f"><span>Bot account</span><input class="in" id="mu" value="${esc(m.user)}" placeholder="@openroost:example.org" autocomplete="off"></label>
      <label class="su-f"><span>Bot password</span><input class="in" id="mp" type="password" value="" placeholder="${m.signedIn ? 'Signed in · type to sign in again' : ''}" autocomplete="off"></label>
      <span class="f-help su-help">Used once to get an access token; OpenRoost stores only the token (encrypted).</span>
      <div class="su-row"><button type="button" class="btn btn-sm btn-primary" data-login>${m.signedIn ? 'Sign in again' : 'Sign bot in'}</button><span data-lmsg role="status">${m.signedIn ? `<b class="ok-t">${I('check')} Signed in</b>` : ''}</span></div>${m.note ? `<div class="f-help">${esc(m.note)}</div>` : ''}
      <label class="su-f"><span>Alert room</span><input class="in" id="mr" value="${esc(m.room)}" placeholder="#home-alerts:example.org" autocomplete="off"></label>
      <span class="f-help su-help">Room alias (<code>#room:server</code>) or ID (<code>!abc:server</code>). Invite the bot first. Encrypted rooms work: OpenRoost detects them and encrypts its messages.</span>
      <div class="su-row"><button type="button" class="btn btn-sm" data-test${m.signedIn ? '' : ' disabled'}>${I('chip')} Send a test message</button><span data-tmsg role="status"></span></div></div>` : ''}`;
  el.querySelectorAll('[data-mx]').forEach(b => b.onclick = () => { m.want = b.dataset.mx === '1'; matrix(el); nav(); });
  if (!m.want) return;
  const g = id => el.querySelector('#' + id);
  ['hs', 'mu', 'mr'].forEach(id => g(id).oninput = () => { m.hs = g('hs').value.trim(); m.user = g('mu').value.trim(); m.room = g('mr').value.trim(); nav(); });
  g('mp').oninput = () => { m.pass = g('mp').value; };
  el.querySelector('[data-login]').onclick = async e => {
    const msg = el.querySelector('[data-lmsg]'); e.currentTarget.disabled = true; msg.innerHTML = '<span class="spin"></span> Signing in…';
    try {
      const r = await call('matrix-login', { hs: m.hs, user: m.user, password: m.pass });
      const moved = r.hs && r.hs.replace(/\/$/, '') !== m.hs.replace(/\/$/, '');
      m.note = [moved ? `Found your server's Matrix address through ${m.hs}: ${r.hs}.` : '', r.note || ''].filter(Boolean).join(' ');
      if (r.hs) m.hs = r.hs;
      m.signedIn = true; m.pass = ''; matrix(el);
    }
    catch (err) { msg.innerHTML = `<b class="err-t">${esc(err.message)}</b>`; e.currentTarget.disabled = false; }
    nav();
  };
  el.querySelector('[data-test]').onclick = async e => {
    const msg = el.querySelector('[data-tmsg]'); e.currentTarget.disabled = true; msg.innerHTML = '<span class="spin"></span> Sending…';
    try { const r = await call('matrix-test', { room: m.room, site: st.site }); m.tested = true; msg.innerHTML = `<b class="ok-t">${I('check')} ${esc(r.result)}</b>`; }
    catch (err) { msg.innerHTML = `<b class="err-t">${esc(err.message)}</b>`; }
    e.currentTarget.disabled = false;
  };
}

function done(el) {
  const named = Object.values(st.sensors).filter(x => x.name).length, total = ((st.state && st.state.sensors) || []).length;
  const h = (st.state && st.state.hub) || {};
  const item = (cls, ic, t, d) => `<li class="${cls}"><span class="st">${I(ic)}</span><div><b>${t}</b><small>${d}</small></div></li>`;
  el.innerHTML = `<p class="su-lead">Here's what happens when you finish:</p>
    <ul class="su-sum">
      ${item('', 'check', 'Owner account', `<b>${esc(st.user)}</b>, password stored as a hash.`)}
      ${item('', 'check', 'DNS', SV.piholeSummary(st.ph))}
      ${item(st.hubFound ? '' : 'skip', st.hubFound ? 'check' : 'alert', 'Hub', st.hubFound ? `${esc(h.id)} at ${esc(h.ip || '?')}, trusted from now on` : 'Not found yet')}
      ${item(named ? '' : 'skip', named ? 'check' : 'edit', 'Sensors', `${total} found, ${named} named.${named < total ? ' Name the rest from Devices.' : ''}`)}
      ${item('warn', 'alert', 'Keypad PINs & delays', 'Working on the hub as before. Changing them from OpenRoost is planned.')}
      ${st.mail.mode === 'off' ? item('skip', 'mail', 'Email alerts', 'Off. Turn it on in Settings → Notifications.') : item('', 'check', 'Email alerts', `${SV.mailSummary(st.mail)}, to ${esc(st.mail.to)}.`)}
      ${st.mx.want ? item('', 'check', 'Matrix alerts', `${esc(st.mx.user)} posts to ${esc(st.mx.room)}.`) : item('skip', 'chip', 'Matrix alerts', 'Not set up. Add it in Settings → Notifications.')}
    </ul>
    <div class="note">${I('shield')} <span>Everything is saved on this server. Passwords and keys are encrypted; your account password is stored only as a hash.</span></div>`;
}

async function finish() {
  const next = document.getElementById('next'); next.disabled = true; next.textContent = 'Saving…';
  const sensorMeta = {}; Object.entries(st.sensors).forEach(([id, x]) => { if (x.name || x.room) sensorMeta[id] = { ...(x.name ? { name: x.name } : {}), ...(x.room ? { room: x.room } : {}) }; });
  const settings = Object.assign(M.defaultSettings(), { siteName: st.site.trim() || 'Home', tempUnit: st.unit, ph: st.ph, mail: st.mail, sensorMeta, rooms: S.rooms, publicUrl: location.origin });
  if (st.mx.want && st.mx.signedIn) Object.assign(settings, { mxOn: true, mxHs: st.mx.hs, mxUser: st.mx.user, mxRoom: st.mx.room });
  if (st.mail.to) settings.smtpTo = st.mail.to;
  const strip = o => JSON.parse(JSON.stringify(o, (k, v) => k.startsWith('_') ? undefined : v));
  const h = (st.state && st.state.hub) || {};
  try {
    await call('complete', { admin: { username: st.user.trim(), password: st.pass, display: st.user.trim() }, settings: strip(settings), hubId: st.hubFound ? h.id : undefined });
    st.pass = st.pass2 = '';
    location.replace('/');
  } catch (e) {
    next.disabled = false; nav();
    if (e.status === 409) { location.replace('/'); return; }
    st.err = e.message;
    if (e.status === 403 || e.status === 429 || (e.fields && Object.keys(e.fields).some(k => /password|username/.test(k)))) go(STEPS.findIndex(x => x.id === 'account'), -1);
    M.toast(esc(e.message), 'err', 8000);
  }
}

M.api('GET', '/status').then(async r => {
  if (r.setupDone) { location.replace('/'); return; }
  try { await M.loadFeatures(); } catch (e) { /* features greyed out by default */ }
  go(0);
}, () => { body.innerHTML = '<p>Can\'t reach the OpenRoost server.</p>'; });
