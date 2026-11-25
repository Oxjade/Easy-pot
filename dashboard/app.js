// EasyPot dashboard — dependency-free. Everything that comes from traffic (paths, user agents,
// self-reported agent text) is attacker-controlled, so it is ALWAYS escaped before rendering.
import { icon } from './icons.js';

const $ = (s, el = document) => el.querySelector(s);
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const fmt = n => Number(n ?? 0).toLocaleString();
const plural = (n, one, many) => `${fmt(n)} ${Number(n) === 1 ? one : many}`;
const SEVS = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_COLOR = { critical: 'var(--sev-critical)', high: 'var(--sev-high)', medium: 'var(--sev-medium)', low: 'var(--sev-low)', info: 'var(--sev-info)' };
const CLASS_LABEL = { llm_agent: 'AI agent', scanner: 'Scanner', bot: 'Bot', crawler: 'Crawler', human: 'Human', unknown: 'Unknown' };
const SIGNAL_LABEL = {
  agent_instruction_followed: 'AI agent followed planted instructions',
  honeytoken_replay: 'Stolen decoy credential used',
  cve_exploit_attempt: 'CVE exploit attempt',
  decoy_secret_file: 'Grabbed decoy secrets file',
  decoy_database_dump: 'Downloaded decoy database dump',
  decoy_source_exposure: 'Probed exposed source control',
  decoy_internal_api: 'Hit decoy internal API',
  decoy_api_docs: 'Read decoy API docs',
  decoy_admin_panel: 'Opened decoy admin panel',
  decoy_login_attempt: 'Tried to log in to decoy panel',
  decoy_debug_endpoint: 'Hit decoy debug endpoint',
  tripwire_link_followed: 'Followed hidden tripwire link',
  labyrinth_depth: 'Went deep into the labyrinth',
  attack_payload: 'Attack payload',
  path_probing: 'Path probing (404 burst)',
  id_enumeration: 'Object ID enumeration',
  scanner_tool: 'Known scanner tool',
  http_library: 'Scripted HTTP client',
  headless_browser: 'Headless browser',
  non_browser_client: 'Non-browser client',
  high_request_rate: 'High request rate',
  robotic_timing: 'Machine-regular timing',
  missing_user_agent: 'No user agent',
  declared_ai_crawler: 'Declared AI crawler',
  blocked_request: 'Blocked request',
};
const ACTION_LABEL = { block: 'Blocked', labyrinth: 'Sent to labyrinth', tarpit: 'Slowed down', allow: 'Allowed' };
const PAYLOAD_LABEL = { sqli: 'SQL injection', nosqli: 'NoSQL injection', xss: 'Cross-site scripting', path_traversal: 'Path traversal', command_injection: 'Command injection', ssti: 'Template injection', ssrf: 'Server-side request forgery' };
const CATEGORY_LABEL = { cve: 'CVE exploit traps', secrets: 'Secret files', source: 'Source control', database: 'Database dumps', admin: 'Admin panels', api: 'Internal APIs', debug: 'Debug endpoints' };
// Low-weight context signals: useful in an attacker's timeline, noise in a summary.
const NOISE = new Set(['blocked_request', 'non_browser_client', 'http_library', 'headless_browser', 'missing_user_agent', 'declared_ai_crawler']);
const label = s => SIGNAL_LABEL[s] ?? s.replace(/_/g, ' ');
const cap = s => String(s ?? '').charAt(0).toUpperCase() + String(s ?? '').slice(1);
const sevBadge = s => `<span class="sev sev-${esc(s)}"><i aria-hidden="true"></i>${esc(cap(s))}</span>`;
const sevSwatch = s => `<i style="background:${SEV_COLOR[s] ?? 'var(--sev-info)'}" aria-hidden="true"></i>`;
const clsTag = c => `<span class="tag ${c === 'llm_agent' ? 'tag-agent' : c === 'human' ? 'tag-human' : ''}">${esc(CLASS_LABEL[c] ?? c)}</span>`;
const blockedTag = () => '<span class="tag tag-blocked">Blocked</span>';
const actLabel = a => `<span class="act act-${esc(a)}">${esc(ACTION_LABEL[a] ?? a)}</span>`;
const empty = (title, body = '') => `<div class="empty"><strong>${esc(title)}</strong>${esc(body)}</div>`;

function ago(ts) {
  const s = Math.max(0, Math.round((Date.now() - Number(ts)) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
const when = ts => new Date(Number(ts)).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
function scoreColor(n) {
  return n >= 80 ? 'var(--sev-critical)' : n >= 55 ? 'var(--sev-high)' : n >= 30 ? 'var(--sev-medium)' : 'var(--sev-low)';
}
const riskCell = n => `<span class="risk"><b style="color:${scoreColor(n)}">${Math.round(n)}</b><span class="risk-bar"><i style="width:${Math.min(100, n)}%;background:${scoreColor(n)}"></i></span></span>`;

function describe(e) {
  const d = e.detail || {};
  if (e.signal === 'agent_instruction_followed') return d.selfReportedClient ? `says it is “${d.selfReportedClient}”` : 'followed the registration instruction';
  if (e.signal === 'honeytoken_replay') return `${d.kind} planted in ${d.plantedIn}${d.sameVisitor ? '' : ', reused by a different identity'}`;
  if (e.signal === 'attack_payload') return `${d.category}: ${d.sample ?? ''}`;
  if (e.signal === 'decoy_login_attempt') return `username “${d.username}”`;
  if (d.decoyName) return d.decoyName;
  if (d.tool || d.library || d.engine) return d.tool || d.library || d.engine;
  return `${e.method} ${e.path}`;
}

// Put the Carbon icons into the static shell.
document.querySelectorAll('[data-icon]').forEach(el => el.insertAdjacentHTML('afterbegin', icon(el.dataset.icon)));

// ---------------- state & API ----------------
const store = {
  get token() { try { return localStorage.getItem('easypot.token') || ''; } catch { return ''; } },
  set token(v) { try { v ? localStorage.setItem('easypot.token', v) : localStorage.removeItem('easypot.token'); } catch { /* storage unavailable */ } },
};
let TOKEN = store.token;
let hours = 24;
let es = null;
let liveHandlers = [];
let cleanups = [];

async function api(path, opts = {}) {
  const r = await fetch(path, { ...opts, headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json', ...(opts.headers || {}) } });
  if (r.status === 401) { logout(); throw new Error('unauthorized'); }
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}

function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { t.hidden = true; }, 2600);
}

// ---------------- auth ----------------
$('#login-form').addEventListener('submit', async e => {
  e.preventDefault();
  TOKEN = $('#token-input').value.trim();
  try {
    const r = await fetch('/api/overview?hours=1', { headers: { authorization: `Bearer ${TOKEN}` } });
    if (!r.ok) throw new Error();
    store.token = TOKEN;
    $('#login-error').textContent = '';
    boot();
  } catch { $('#login-error').textContent = 'That token wasn’t accepted. Check admin.token in your config.'; }
});
$('#logout').addEventListener('click', logout);
function logout() {
  store.token = '';
  TOKEN = '';
  es?.close();
  $('#app').hidden = true;
  if (!$('#login-art').firstChild) drawTerrain();
  $('#login').hidden = false;
}

// ---------------- live stream ----------------
function setLive(on) {
  $('#live').classList.toggle('on', on);
  $('#live-text').textContent = on ? 'Live' : 'Reconnecting';
}
function connectStream() {
  es?.close();
  es = new EventSource(`/api/stream?token=${encodeURIComponent(TOKEN)}`);
  es.addEventListener('open', () => setLive(true));
  es.addEventListener('error', () => setLive(false));
  es.addEventListener('signal', m => { const e = JSON.parse(m.data); liveHandlers.forEach(h => h(e)); });
}

// ---------------- router ----------------
const ROUTES = {
  overview: { title: 'Overview', sub: 'What tried to break in, and what got caught.', render: renderOverview },
  actors: { title: 'Attackers', sub: 'Every visitor that tripped something, ranked by risk.', render: renderActors },
  events: { title: 'Event log', sub: 'Every signal EasyPot recorded, newest first.', render: renderEvents },
  decoys: { title: 'Decoys', sub: 'The traps deployed on your site and how often each was triggered.', render: renderDecoys },
  blocks: { title: 'Blocklist', sub: 'IPs and visitors that are blocked right now. Your firewalls read this list.', render: renderBlocks },
  integrations: { title: 'Integrations', sub: 'Send EasyPot’s findings to Wazuh, your SIEM and your firewalls.', render: renderIntegrations },
};

async function route() {
  const name = (location.hash.replace('#/', '') || 'overview').split('/')[0];
  const r = ROUTES[name] ?? ROUTES.overview;
  document.querySelectorAll('.nav a').forEach(a => {
    const on = a.dataset.route === name;
    a.classList.toggle('active', on);
    on ? a.setAttribute('aria-current', 'page') : a.removeAttribute('aria-current');
  });
  $('#page-title').textContent = r.title;
  $('#page-sub').textContent = r.sub;
  document.title = `${r.title} · EasyPot`;
  $('#range').hidden = name !== 'overview';
  liveHandlers = [];
  cleanups.forEach(f => f()); cleanups = [];
  $('#view').innerHTML = '<div class="loading">Loading…</div>';
  try { await r.render($('#view')); } catch (err) {
    if (err.message !== 'unauthorized') $('#view').innerHTML = `<div class="panel">${empty('This view didn’t load', `The server answered ${err.message}. Refresh to try again.`)}</div>`;
  }
}
window.addEventListener('hashchange', route);
$('#range').addEventListener('click', e => {
  const b = e.target.closest('button'); if (!b) return;
  hours = Number(b.dataset.hours);
  $('#range').querySelectorAll('button').forEach(x => x.classList.toggle('on', x === b));
  route();
});

// ---------------- overview ----------------
async function renderOverview(view) {
  const o = await api(`/api/overview?hours=${hours}`);
  $('#site-name').textContent = o.site;
  $('#upstream').textContent = String(o.upstream).replace(/^https?:\/\//, '');
  const k = o.kpis;
  const span = hours === 24 ? 'the last 24 hours' : hours === 168 ? 'the last 7 days' : 'the last 30 days';
  const caught = k.agents || o.selfReports.length;

  const catchHtml = o.selfReports.length ? `
      <div>
        <h2 class="catch-title"><span class="count">${fmt(caught)}</span>${caught === 1 ? 'AI agent told us who it is' : 'AI agents told us who they are'}</h2>
        <p class="catch-sub">They followed instructions hidden in your pages and reported their model and task. That report is conclusive, so each one was blocked on the spot.</p>
      </div>
      <ol class="quotes">${o.selfReports.slice(0, 4).map(s => `
        <li class="quote" data-actor="${esc(s.id)}" tabindex="0">
          <q>${esc(s.self_report)}</q>
          <div class="quote-meta"><span class="mono">${esc(s.ip)}</span><span>${ago(s.last_seen)}</span></div>
        </li>`).join('')}
      </ol>` : `
      <div>
        <h2 class="catch-title"><span class="count">0</span>AI agents have identified themselves</h2>
      </div>
      <p class="catch-empty">Every page EasyPot serves carries instructions only an automated agent will read. When an agent follows them, it usually reports its model and the task it was given, and that report shows up here.</p>`;

  view.innerHTML = `
    <section class="catch" aria-label="AI agents caught">${catchHtml}</section>
    <section class="stats" aria-label="Totals for ${span}">
      ${stat('Requests', k.requests, `in ${span}`)}
      ${stat('Visitors', k.visitors, 'distinct identities')}
      ${stat('Threats', k.threats, 'medium severity or higher')}
      ${stat('Credential replays', k.replays, 'stolen decoy secrets used', k.replays ? 'alarm' : '')}
      ${stat('Active blocks', k.activeBlocks, 'IPs on the firewall feed')}
    </section>
    <section class="panel">
      <div class="panel-head"><h2>Threat activity</h2><div class="legend">${SEVS.slice(0, 4).map(s => `<span><i style="background:${SEV_COLOR[s]}"></i>${cap(s)}</span>`).join('')}</div></div>
      <div class="panel-body"><div class="chart-box" id="chart" role="img" aria-label="Threat events over ${span}, stacked by severity"></div></div>
    </section>
    <div class="split">
      <section class="panel">
        <div class="panel-head"><h2>What they tried</h2><span class="muted">MITRE ATT&amp;CK technique</span></div>
        ${rankList(o.bySignal.filter(s => !NOISE.has(s.signal)).slice(0, 10).map(s => ({ name: label(s.signal), n: s.n, tag: s.mitre })), 'Nothing suspicious yet', 'Signals appear here once a visitor trips a decoy or sends an attack payload.')}
      </section>
      <section class="panel">
        <div class="panel-head"><h2>Who’s knocking</h2><span class="muted">Visitors by type</span></div>
        ${rankList(o.byClass.filter(c => c.cls !== 'unknown').sort((a, b) => b.n - a.n).map(c => ({ name: CLASS_LABEL[c.cls] ?? c.cls, n: c.n })), 'No visitors yet', '')}
        ${o.payloads.length ? `<h3 class="sub-head">Attack payloads</h3>${rankList(o.payloads.map(p => ({ name: PAYLOAD_LABEL[p.category] ?? cap(String(p.category).replace(/_/g, ' ')), n: p.n })))}` : ''}
      </section>
    </div>
    <div class="split-wide">
      <section class="panel">
        <div class="panel-head"><h2>Highest-risk visitors</h2><a href="#/actors">See all attackers</a></div>
        ${actorTable(o.topActors)}
      </section>
      <section class="panel">
        <div class="panel-head"><h2>Live feed</h2><span class="muted">Newest first</span></div>
        <div class="feed" id="feed">${o.recent.length ? o.recent.map(e => feedItem(e)).join('') : empty('Waiting for traffic', 'Events stream in here as they happen.')}</div>
      </section>
    </div>`;

  mountChart($('#chart', view), o);
  bindActorClicks(view);
  liveHandlers.push(e => {
    const feed = $('#feed', view);
    if (!feed) return;
    feed.querySelector('.empty')?.remove();
    feed.insertAdjacentHTML('afterbegin', feedItem(e, true));
    while (feed.children.length > 60) feed.lastElementChild.remove();
    bindActorClicks(feed);
  });
}

function stat(name, value, note, cls = '') {
  return `<div class="stat ${cls}"><div class="stat-label">${esc(name)}</div><div class="stat-value">${fmt(value)}</div><div class="stat-note">${esc(note)}</div></div>`;
}

function rankList(rows, emptyTitle = 'Nothing yet', emptyBody = '') {
  if (!rows.length) return empty(emptyTitle, emptyBody);
  const max = Math.max(...rows.map(r => Number(r.n)), 1);
  return `<ol class="ranks">${rows.map(r => `
    <li class="rank"><span class="rank-name">${esc(r.name)}</span><span class="rank-tag">${esc(r.tag ?? '')}</span><span class="rank-n">${fmt(r.n)}</span>
      <span class="rank-bar" aria-hidden="true"><i style="width:${Math.max(2, (Number(r.n) / max) * 100)}%"></i></span></li>`).join('')}</ol>`;
}

// Draws at the container's real pixel size so text stays crisp; redraws on resize.
function mountChart(box, o) {
  const bucket = o.bucketMs;
  const end = Math.floor(Date.now() / bucket) * bucket;
  const n = o.hours <= 24 ? 24 : Math.round(o.hours / 24);
  const buckets = Array.from({ length: n }, (_, i) => end - (n - 1 - i) * bucket);
  const data = new Map(buckets.map(b => [b, { critical: 0, high: 0, medium: 0, low: 0 }]));
  for (const r of o.timeline) { const d = data.get(Number(r.bucket)); if (d && d[r.severity] !== undefined) d[r.severity] += Number(r.n); }
  const totals = [...data.values()].map(d => d.critical + d.high + d.medium + d.low);
  const raw = Math.max(4, ...totals);
  const mag = Math.pow(10, Math.floor(Math.log10(raw)));
  const stepY = raw / mag > 5 ? mag * 2 : raw / mag > 2 ? mag : mag / 2;
  const max = Math.ceil(raw / stepY) * stepY;

  const draw = () => {
    const W = box.clientWidth, H = box.clientHeight;
    if (!W || !H) return;
    const L = 36, B = 24, T = 6, R = 4;
    const bw = (W - L - R) / n;
    const y = v => H - B - (v / max) * (H - B - T);
    let grid = '';
    for (let t = 0; t <= max + 1e-9; t += stepY) grid += `<line class="grid-line" x1="${L}" x2="${W - R}" y1="${y(t)}" y2="${y(t)}"${t ? ' stroke-dasharray="2 4"' : ''}/><text x="${L - 10}" y="${y(t) + 4}" text-anchor="end">${+t.toFixed(2)}</text>`;
    let bars = '';
    const barW = Math.min(28, Math.max(3, bw * .62));
    buckets.forEach((b, i) => {
      let acc = 0;
      const x = L + i * bw + (bw - barW) / 2;
      for (const s of ['low', 'medium', 'high', 'critical']) {
        const v = data.get(b)[s];
        if (!v) continue;
        const y0 = y(acc), y1 = y(acc + v);
        bars += `<rect x="${x}" y="${y1}" width="${barW}" height="${Math.max(1, y0 - y1 - 1)}" rx="1.5" fill="${SEV_COLOR[s]}"><title>${new Date(b).toLocaleString()}: ${v} ${s}</title></rect>`;
        acc += v;
      }
    });
    const every = Math.ceil(n / Math.max(2, Math.floor((W - L) / 70)));
    const xl = buckets.map((b, i) => i % every === 0 ? `<text x="${L + i * bw + bw / 2}" y="${H - 6}" text-anchor="middle">${o.hours <= 24 ? new Date(b).getHours().toString().padStart(2, '0') + ':00' : new Date(b).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}</text>` : '').join('');
    box.innerHTML = `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" aria-hidden="true">${grid}${bars}${xl}</svg>`;
  };
  draw();
  const ro = new ResizeObserver(draw);
  ro.observe(box);
  cleanups.push(() => ro.disconnect());
}

function feedItem(e, isNew = false) {
  return `<div class="feed-item ${isNew ? 'new' : ''}" data-actor="${esc(e.actorId)}" tabindex="0">
    ${sevSwatch(e.severity)}
    <div style="min-width:0"><div class="what">${esc(label(e.signal))}</div><div class="meta"><span class="mono">${esc(e.ip)}</span><span>${esc(describe(e))}</span></div></div>
    <div class="when">${ago(e.ts)}</div></div>`;
}

function actorTable(rows) {
  if (!rows.length) return empty('No suspicious visitors yet', 'Visitors show up here once they trip a decoy or a detector.');
  return `<div class="table-wrap"><table><thead><tr><th>Visitor</th><th>Type</th><th>Risk</th><th class="r">Signals</th><th class="r">Last seen</th></tr></thead><tbody>
    ${rows.map(a => `<tr class="clickable" data-actor="${esc(a.id)}" tabindex="0">
      <td><div class="mono">${esc(a.ip)}</div><div class="cell-sub">${esc(a.ua || 'No user agent')}</div></td>
      <td><span class="tags">${clsTag(a.cls)}${a.blocked ? blockedTag() : ''}</span></td>
      <td>${riskCell(a.score)}</td><td class="r num">${fmt(a.signals)}</td><td class="r nowrap muted">${ago(a.last_seen)}</td></tr>`).join('')}
  </tbody></table></div>`;
}

function bindActorClicks(root) {
  root.querySelectorAll('[data-actor]').forEach(el => {
    el.onclick = () => openActor(el.dataset.actor);
    el.onkeydown = ev => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); openActor(el.dataset.actor); } };
  });
}

// ---------------- actors ----------------
async function renderActors(view) {
  let cls = '';
  const draw = async () => {
    const rows = await api(`/api/actors${cls ? `?class=${cls}` : ''}`);
    $('#actors-body', view).innerHTML = actorTable(rows);
    bindActorClicks(view);
  };
  view.innerHTML = `<div class="toolbar"><div class="seg" id="cls-seg" role="group" aria-label="Visitor type">
      ${[['', 'All'], ['llm_agent', 'AI agents'], ['scanner', 'Scanners'], ['bot', 'Bots'], ['crawler', 'Crawlers']].map(([v, t]) => `<button type="button" data-v="${v}" class="${v === cls ? 'on' : ''}">${t}</button>`).join('')}
    </div></div><section class="panel" id="actors-body"></section>`;
  $('#cls-seg', view).onclick = e => {
    const b = e.target.closest('button'); if (!b) return;
    cls = b.dataset.v;
    view.querySelectorAll('#cls-seg button').forEach(x => x.classList.toggle('on', x === b));
    draw();
  };
  await draw();
}

let lastFocus = null;
async function openActor(id) {
  const d = await api(`/api/actors/${encodeURIComponent(id)}`);
  const a = d.actor;
  const drawer = $('#drawer');
  if (drawer.hidden) lastFocus = document.activeElement;
  drawer.innerHTML = `
    <div class="drawer-head">
      <div><h2>${esc(a.ip)}</h2><div class="drawer-id">Visitor <span class="mono">${esc(a.id)}</span></div></div>
      <button class="btn btn-quiet btn-icon" id="drawer-close" type="button" aria-label="Close">${icon('close')}</button>
    </div>
    <div class="drawer-section">
      <div class="drawer-bar">
        <span class="tags">${clsTag(a.cls)}${d.blocked ? blockedTag() : ''}</span>
        ${riskCell(a.score)}
        <span class="spacer"></span>
        ${d.blocked ? `<button class="btn btn-sm" id="unblock" type="button">Unblock</button>` : `<button class="btn btn-danger btn-sm" id="block" type="button">Block visitor</button>`}
      </div>
      ${a.selfReport ? `<div class="said"><div class="said-label">What the agent said about itself</div><q>${esc(a.selfReport)}</q></div>` : ''}
    </div>
    <div class="drawer-section">
      <dl class="kv">
        <dt>User agent</dt><dd class="mono">${esc(a.ua || '—')}</dd>
        <dt>First seen</dt><dd>${when(a.firstSeen)}</dd>
        <dt>Last seen</dt><dd>${when(a.lastSeen)}</dd>
        <dt>Requests</dt><dd class="num">${fmt(a.requests)}</dd>
        <dt>Labyrinth depth</dt><dd>${a.labyrinthDepth ? plural(a.labyrinthDepth, 'page', 'pages') + ' deep' : '—'}</dd>
        <dt>Decoy secrets taken</dt><dd>${d.honeytokens.length ? `<span class="tags">${[...new Set(d.honeytokens.map(t => t.kind))].map(k => `<span class="tag">${esc(k)}</span>`).join('')}</span>` : '—'}</dd>
      </dl>
    </div>
    <div class="drawer-section">
      <h3>Timeline</h3>
      ${d.events.length ? `<ol class="timeline">${d.events.map(e => `
        <li class="tl-item">${sevSwatch(e.severity)}
          <div class="tl-h"><strong>${esc(label(e.signal))}</strong>${sevBadge(e.severity)}</div>
          <div class="tl-meta"><span>${when(e.ts)}</span>${actLabel(e.action)}</div>
          <pre>${esc(e.method)} ${esc(e.path)}${Object.keys(e.detail || {}).length ? '\n' + esc(JSON.stringify(e.detail, null, 2)) : ''}</pre>
        </li>`).join('')}</ol>` : empty('No events recorded')}
    </div>`;
  drawer.hidden = false;
  $('#drawer-backdrop').hidden = false;
  $('#drawer-close').onclick = closeDrawer;
  $('#drawer-close').focus();
  $('#block')?.addEventListener('click', async () => {
    await api('/api/blocks', { method: 'POST', body: JSON.stringify({ target: a.ip, reason: 'manual (dashboard)' }) });
    await api('/api/blocks', { method: 'POST', body: JSON.stringify({ target: a.id, reason: 'manual (dashboard)' }) });
    toast(`Blocked ${a.ip}`); openActor(id);
  });
  $('#unblock')?.addEventListener('click', async () => {
    await api(`/api/blocks/${encodeURIComponent(a.ip)}`, { method: 'DELETE' });
    await api(`/api/blocks/${encodeURIComponent(a.id)}`, { method: 'DELETE' });
    toast(`Unblocked ${a.ip}`); openActor(id);
  });
}
function closeDrawer() {
  if ($('#drawer').hidden) return;
  $('#drawer').hidden = true; $('#drawer-backdrop').hidden = true;
  lastFocus?.focus?.();
}
$('#drawer-backdrop').addEventListener('click', closeDrawer);
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDrawer(); });

// ---------------- events ----------------
async function renderEvents(view) {
  let sev = 'critical,high,medium';
  const draw = async () => {
    const rows = await api(`/api/events?limit=300${sev ? `&severity=${sev}` : ''}`);
    $('#ev-body', view).innerHTML = rows.length ? rows.map(evRow).join('') : `<tr><td colspan="6">${empty('No events at this severity', 'Try a wider filter.')}</td></tr>`;
    bindActorClicks(view);
  };
  view.innerHTML = `<div class="toolbar"><div class="seg" id="sev-seg" role="group" aria-label="Minimum severity">
      ${[['critical,high,medium', 'Medium and up'], ['critical,high', 'High and up'], ['critical', 'Critical'], ['', 'Everything']].map(([v, t]) => `<button type="button" data-v="${v}" class="${v === sev ? 'on' : ''}">${t}</button>`).join('')}
    </div></div>
    <section class="panel"><div class="table-wrap"><table><thead><tr><th>Severity</th><th>Signal</th><th>Source</th><th>Request</th><th>Response</th><th class="r">When</th></tr></thead><tbody id="ev-body"></tbody></table></div></section>`;
  $('#sev-seg', view).onclick = e => {
    const b = e.target.closest('button'); if (!b) return;
    sev = b.dataset.v;
    view.querySelectorAll('#sev-seg button').forEach(x => x.classList.toggle('on', x === b));
    draw();
  };
  await draw();
  liveHandlers.push(e => {
    if (sev && !sev.split(',').includes(e.severity)) return;
    const body = $('#ev-body', view);
    body?.querySelector('.empty')?.closest('tr')?.remove();
    body?.insertAdjacentHTML('afterbegin', evRow(e));
    bindActorClicks(view);
  });
}
function evRow(e) {
  return `<tr class="clickable" data-actor="${esc(e.actorId)}" tabindex="0"><td>${sevBadge(e.severity)}</td>
    <td><div>${esc(label(e.signal))}</div><div class="cell-sub">${esc(describe(e))}</div></td>
    <td class="nowrap"><div class="mono">${esc(e.ip)}</div><div class="cell-sub">${esc(CLASS_LABEL[e.actorClass] ?? e.actorClass)}</div></td>
    <td class="cell-trunc mono">${esc(e.method)} ${esc(e.path)}</td><td class="nowrap">${actLabel(e.action)}</td><td class="r nowrap muted">${ago(e.ts)}</td></tr>`;
}

// ---------------- decoys ----------------
async function renderDecoys(view) {
  const ds = await api('/api/decoys');
  const cats = [...new Set(ds.map(d => d.category))];
  if (!ds.length) { view.innerHTML = `<div class="panel">${empty('No decoys deployed', 'Check the decoys section of your config.')}</div>`; return; }
  view.innerHTML = cats.map(c => {
    const list = ds.filter(d => d.category === c).sort((a, b) => b.hits - a.hits);
    const hot = list.filter(d => d.hits).length;
    return `<section class="panel">
      <div class="panel-head"><h2>${esc(CATEGORY_LABEL[c] ?? cap(c))}</h2><span class="counts">${plural(list.length, 'trap', 'traps')}, ${fmt(hot)} triggered</span></div>
      <div class="table-wrap"><table class="decoy-table"><colgroup><col class="c-name"><col><col class="c-weight"><col class="c-last"><col class="c-hits"></colgroup><thead><tr><th>Decoy</th><th>Paths</th><th class="r">Weight</th><th class="r">Last triggered</th><th class="r">Hits</th></tr></thead><tbody>
      ${list.map(d => `<tr>
        <td class="decoy-name">${esc(d.name)}</td>
        <td>${d.paths.length ? `<div class="paths">${d.paths.slice(0, 5).map(p => `<span class="path">${esc(p)}</span>`).join('')}${d.paths.length > 5 ? `<span class="dim">and ${d.paths.length - 5} more</span>` : ''}</div>` : '<span class="dim">Dynamic</span>'}</td>
        <td class="r num muted">${d.weight}</td>
        <td class="r nowrap ${d.lastHit ? '' : 'dim'}">${d.lastHit ? ago(d.lastHit) : 'Never'}</td>
        <td class="r"><span class="hits ${d.hits ? 'hot' : ''}">${fmt(d.hits)}</span></td></tr>`).join('')}
      </tbody></table></div></section>`;
  }).join('');
}

// ---------------- blocks ----------------
async function renderBlocks(view) {
  const draw = async () => {
    const bs = await api('/api/blocks');
    $('#bl-count', view).textContent = plural(bs.length, 'entry', 'entries');
    $('#bl-body', view).innerHTML = bs.length ? bs.map(b => `<tr>
      <td class="mono">${esc(b.target)}</td><td>${b.kind === 'ip' ? 'IP address' : 'Visitor'}</td><td>${esc(b.reason)}</td>
      <td><span class="tag">${esc(cap(b.source))}</span></td><td class="nowrap muted">${ago(b.created)}</td>
      <td class="nowrap muted">${b.expires ? when(b.expires) : 'Never'}</td>
      <td class="r"><button class="btn btn-sm" type="button" data-unblock="${esc(b.target)}">Unblock</button></td></tr>`).join('')
      : `<tr><td colspan="7">${empty('Nothing is blocked', 'Visitors are blocked automatically when they cross the risk threshold, or you can add one above.')}</td></tr>`;
    view.querySelectorAll('[data-unblock]').forEach(btn => btn.onclick = async () => {
      await api(`/api/blocks/${encodeURIComponent(btn.dataset.unblock)}`, { method: 'DELETE' });
      toast(`Unblocked ${btn.dataset.unblock}`); draw();
    });
  };
  view.innerHTML = `
    <section class="panel">
      <div class="panel-head"><h2>Blocked now</h2><span class="muted" id="bl-count"></span></div>
      <form class="add-block" id="bl-form">
        <input id="bl-target" placeholder="IP address or visitor ID" aria-label="IP address or visitor ID" required>
        <input id="bl-reason" placeholder="Reason (optional)" aria-label="Reason">
        <select id="bl-ttl" aria-label="Block for"><option value="60">For 1 hour</option><option value="1440" selected>For 24 hours</option><option value="10080">For 7 days</option><option value="0">Permanently</option></select>
        <button class="btn btn-primary" type="submit">Block</button>
      </form>
      <div class="table-wrap"><table><thead><tr><th>Target</th><th>Kind</th><th>Reason</th><th>Added by</th><th>Added</th><th>Expires</th><th></th></tr></thead><tbody id="bl-body"></tbody></table></div>
    </section>`;
  $('#bl-form', view).onsubmit = async e => {
    e.preventDefault();
    const target = $('#bl-target').value.trim();
    await api('/api/blocks', { method: 'POST', body: JSON.stringify({ target, reason: $('#bl-reason').value.trim() || 'manual', ttlMinutes: Number($('#bl-ttl').value) }) });
    e.target.reset(); toast(`Blocked ${target}`); draw();
  };
  await draw();
}

// ---------------- integrations ----------------
async function renderIntegrations(view) {
  const c = await api('/api/config');
  const base = location.origin;
  const feed = p => `${base}${p}?token=${c.feedToken}`;
  const i = c.integrations;
  const state = (on, yes, no) => `<span class="state ${on ? 'on' : ''}"><i aria-hidden="true"></i>${on ? yes : no}</span>`;
  view.innerHTML = `
    <section class="panel"><div class="panel-head"><h2>Firewall blocklist feed</h2><span class="muted">Your firewall pulls it, refreshed every minute</span></div>
      <div class="panel-body">
        <p class="prose">Point your firewall’s external IP list at this URL. Palo Alto (External Dynamic List), FortiGate (Threat Feed), pfSense and OPNsense (URL Table) and Sophos read it directly.</p>
        ${copyField(feed('/feeds/blocklist.txt'), 'Plain text blocklist')}
        <div class="field-grid">
          <div><div class="field-label">JSON, with the reason for each block</div>${copyField(feed('/feeds/blocklist.json'), 'JSON blocklist')}</div>
          <div><div class="field-label">STIX 2.1, for MISP and OpenCTI</div>${copyField(feed('/feeds/stix.json'), 'STIX bundle')}</div>
        </div>
      </div>
    </section>
    <div class="split">
      <section class="panel"><div class="panel-head"><h2>Wazuh</h2>${state(i.fileLog.enabled, 'Event log on', 'Event log off')}</div>
        <div class="panel-body"><ol class="steps">
          <li>On the Wazuh agent, add a <code class="inline">&lt;localfile&gt;</code> with <code class="inline">log_format json</code> that reads <code class="inline">${esc(i.fileLog.path)}</code>.</li>
          <li>On the manager, copy <code class="inline">integrations/wazuh/easypot_rules.xml</code> into <code class="inline">/var/ossec/etc/rules/</code>.</li>
          <li>Turn on the <code class="inline">firewall-drop</code> active response for rules <code class="inline">100710</code> to <code class="inline">100713</code> so every agent blocks caught attackers.</li>
        </ol></div>
      </section>
      <section class="panel"><div class="panel-head"><h2>SIEM over syslog</h2>${state(i.syslog.enabled, 'Sending', 'Not set up')}</div>
        <div class="panel-body">${i.syslog.enabled
          ? `<dl class="kv"><dt>Destination</dt><dd class="mono">${esc(i.syslog.protocol)}://${esc(i.syslog.host)}:${esc(i.syslog.port)}</dd><dt>Format</dt><dd>${esc(String(i.syslog.format).toUpperCase())}</dd><dt>Sends</dt><dd>${esc(cap(i.syslog.minSeverity))} severity and up</dd></dl>`
          : `<p class="prose">Set <code class="inline">integrations.syslog</code> in your config to stream JSON or CEF to Splunk, Elastic, Sentinel or QRadar. Every event carries its MITRE ATT&amp;CK technique ID.</p>`}</div>
      </section>
    </div>
    <div class="split">
      <section class="panel"><div class="panel-head"><h2>Alerts</h2>${state(i.webhooks.length, plural(i.webhooks.length, 'webhook', 'webhooks'), 'No webhooks')}</div>
        <div class="panel-body">${i.webhooks.length
          ? `<dl class="kv">${i.webhooks.map(w => `<dt>${esc(cap(w.type))}</dt><dd><span class="mono">${esc(w.url)}</span><div class="dim">${esc(cap(w.minSeverity))} severity and up</div></dd>`).join('')}</dl>`
          : '<p class="prose">Add a Slack or generic webhook under <code class="inline">integrations.webhooks</code>. Generic webhooks work with Shuffle, TheHive, Tines and XSOAR.</p>'}</div>
      </section>
      <section class="panel"><div class="panel-head"><h2>Detection policy</h2></div>
        <div class="panel-body"><dl class="kv">
          <dt>Slow down at</dt><dd>Risk score ${c.thresholds.tarpit}</dd>
          <dt>Send to labyrinth at</dt><dd>Risk score ${c.thresholds.labyrinth}</dd>
          <dt>Block at</dt><dd>Risk score ${c.thresholds.block}${c.autoBlock ? '<div class="dim">Conclusive signals block immediately</div>' : ''}</dd>
          <dt>Block length</dt><dd>${plural(Math.round(c.blockTtlMinutes / 60), 'hour', 'hours')}<div class="dim">Blocked visitors get a ${esc(c.blockMode)} response</div></dd>
          <dt>Decoys tailored to</dt><dd><span class="tags">${c.stack.map(s => `<span class="tag">${esc(s)}</span>`).join('')}</span></dd>
        </dl></div>
      </section>
    </div>`;
  view.querySelectorAll('[data-copy]').forEach(b => b.onclick = async () => {
    try { await navigator.clipboard.writeText(b.dataset.copy); toast('Copied to clipboard'); } catch { toast('Couldn’t copy. Select the text instead.'); }
  });
}
const copyField = (v, name) => `<div class="field"><code>${esc(v)}</code><button class="btn btn-sm" type="button" data-copy="${esc(v)}" aria-label="Copy ${esc(name)} URL">${icon('copy')}Copy</button></div>`;

// ---------------- sign-in art ----------------
// Line-art terrain behind the sign-in form: two ribbed hills falling into a valley floor whose
// perspective lines converge under the form. Decorative only.
function drawTerrain() {
  const W = 1440, H = 900, N = 54, cx = W / 2;
  let hills = '';
  for (let i = 0; i <= N; i++) {
    const t = i / N;
    const edge = 90 + t * 640, dip = 760 + t * 110, spread = 300 + t * 160;
    hills += `<path d="M-60 ${edge.toFixed(1)} C${spread.toFixed(1)} ${(edge + 40).toFixed(1)} ${(cx - 260).toFixed(1)} ${dip.toFixed(1)} ${cx} ${dip.toFixed(1)} S${(W - spread).toFixed(1)} ${(edge + 40).toFixed(1)} ${W + 60} ${edge.toFixed(1)}" stroke-opacity="${(0.18 + 0.5 * (1 - t)).toFixed(2)}"/>`;
  }
  let floor = '';
  for (let i = -30; i <= 30; i++) floor += `<path d="M${cx + i * 2.2} 690 L${cx + i * 46} ${H + 10}"/>`;
  $('#login-art').innerHTML = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMax slice" fill="none">
    <defs>
      <linearGradient id="ln" x1="0" x2="1"><stop offset="0" stop-color="#fff" stop-opacity=".6"/><stop offset=".28" stop-color="#fff" stop-opacity=".08"/><stop offset=".5" stop-color="#fff" stop-opacity=".02"/><stop offset=".72" stop-color="#fff" stop-opacity=".08"/><stop offset="1" stop-color="#fff" stop-opacity=".6"/></linearGradient>
      <linearGradient id="fl" y1="0" y2="1"><stop offset="0" stop-color="#fff" stop-opacity="0"/><stop offset="1" stop-color="#fff" stop-opacity=".14"/></linearGradient>
      <radialGradient id="vg" cx=".5" cy=".46" r=".55"><stop offset=".4" stop-color="#000" stop-opacity=".92"/><stop offset="1" stop-color="#000" stop-opacity="0"/></radialGradient>
      <radialGradient id="glow" cx=".5" cy="1" r=".5"><stop offset="0" stop-color="#fff" stop-opacity=".1"/><stop offset="1" stop-color="#fff" stop-opacity="0"/></radialGradient>
    </defs>
    <rect width="${W}" height="${H}" fill="url(#glow)"/>
    <g stroke="url(#fl)" stroke-width=".7">${floor}</g>
    <g stroke="url(#ln)" stroke-width=".8">${hills}</g>
    <rect width="${W}" height="${H}" fill="url(#vg)"/>
  </svg>`;
}

// ---------------- boot ----------------
function boot() {
  $('#login').hidden = true;
  $('#app').hidden = false;
  if (!location.hash) location.hash = '#/overview';
  connectStream();
  route();
}
if (TOKEN) boot(); else { drawTerrain(); $('#login').hidden = false; }
