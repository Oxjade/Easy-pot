// EasyPot dashboard — dependency-free. Everything that comes from traffic (paths, user agents,
// self-reported agent text) is attacker-controlled, so it is ALWAYS escaped before rendering.

const $ = (s, el = document) => el.querySelector(s);
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const fmt = n => Number(n ?? 0).toLocaleString();
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
// Low-weight context signals: useful in an attacker's timeline, noise in a summary.
const NOISE = new Set(['blocked_request', 'non_browser_client', 'http_library', 'headless_browser', 'missing_user_agent', 'declared_ai_crawler']);
const label = s => SIGNAL_LABEL[s] ?? s.replace(/_/g, ' ');
const sevBadge = s => `<span class="sev sev-${esc(s)}">${esc(s)}</span>`;
const clsBadge = c => `<span class="cls cls-${esc(c)}">${esc(CLASS_LABEL[c] ?? c)}</span>`;
const actBadge = a => `<span class="act act-${esc(a)}">${esc(a)}</span>`;

function ago(ts) {
  const s = Math.max(0, Math.round((Date.now() - Number(ts)) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
function scoreColor(n) {
  return n >= 80 ? 'var(--sev-critical)' : n >= 55 ? 'var(--honey)' : n >= 30 ? 'var(--sev-medium)' : 'var(--sev-low)';
}
const scoreCell = n => `<span class="score" style="color:${scoreColor(n)}">${Math.round(n)}</span><span class="score-meter"><i style="width:${Math.min(100, n)}%;background:${scoreColor(n)}"></i></span>`;

function describe(e) {
  const d = e.detail || {};
  if (e.signal === 'agent_instruction_followed') return d.selfReportedClient ? `says it is “${d.selfReportedClient}”` : 'followed the registration instruction';
  if (e.signal === 'honeytoken_replay') return `${d.kind} planted in ${d.plantedIn}${d.sameVisitor ? '' : ' · reused by a different identity'}`;
  if (e.signal === 'attack_payload') return `${d.category}: ${d.sample ?? ''}`;
  if (e.signal === 'decoy_login_attempt') return `username “${d.username}”`;
  if (d.decoyName) return d.decoyName;
  if (d.tool || d.library || d.engine) return d.tool || d.library || d.engine;
  return `${e.method} ${e.path}`;
}

// ---------------- state & API ----------------
const store = {
  get token() { try { return localStorage.getItem('easypot.token') || ''; } catch { return ''; } },
  set token(v) { try { v ? localStorage.setItem('easypot.token', v) : localStorage.removeItem('easypot.token'); } catch { /* storage unavailable */ } },
};
let TOKEN = store.token;
let hours = 24;
let es = null;
let liveHandlers = [];

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
    boot();
  } catch { $('#login-error').textContent = 'That token was not accepted.'; }
});
$('#logout').addEventListener('click', logout);
function logout() {
  store.token = '';
  TOKEN = '';
  es?.close();
  $('#app').hidden = true;
  $('#login').hidden = false;
}

// ---------------- live stream ----------------
function connectStream() {
  es?.close();
  es = new EventSource(`/api/stream?token=${encodeURIComponent(TOKEN)}`);
  es.addEventListener('open', () => $('#live').classList.add('on'));
  es.addEventListener('error', () => $('#live').classList.remove('on'));
  es.addEventListener('signal', m => { const e = JSON.parse(m.data); liveHandlers.forEach(h => h(e)); });
}

// ---------------- router ----------------
const ROUTES = {
  overview: { title: 'Overview', sub: 'What tried to break in, and what got caught', render: renderOverview },
  actors: { title: 'Attackers', sub: 'Every visitor that tripped something, ranked by risk', render: renderActors },
  events: { title: 'Event log', sub: 'Every signal EasyPot recorded', render: renderEvents },
  decoys: { title: 'Decoys', sub: 'Traps deployed on your site and how often they were triggered', render: renderDecoys },
  blocks: { title: 'Blocklist', sub: 'IPs and visitors currently blocked; published to your firewalls', render: renderBlocks },
  integrations: { title: 'Integrations', sub: 'Feed EasyPot into Wazuh, your SIEM and your firewalls', render: renderIntegrations },
};

async function route() {
  const name = (location.hash.replace('#/', '') || 'overview').split('/')[0];
  const r = ROUTES[name] ?? ROUTES.overview;
  document.querySelectorAll('.nav a').forEach(a => a.classList.toggle('active', a.dataset.route === name));
  $('#page-title').textContent = r.title;
  $('#page-sub').textContent = r.sub;
  $('#range').parentElement.querySelector('select').style.visibility = name === 'overview' ? 'visible' : 'hidden';
  liveHandlers = [];
  $('#view').innerHTML = '<div class="empty">Loading…</div>';
  try { await r.render($('#view')); } catch (err) { if (err.message !== 'unauthorized') $('#view').innerHTML = `<div class="card empty">Couldn't load this view (${esc(err.message)}).</div>`; }
}
window.addEventListener('hashchange', route);
$('#range').addEventListener('change', e => { hours = Number(e.target.value); route(); });

// ---------------- overview ----------------
async function renderOverview(view) {
  const o = await api(`/api/overview?hours=${hours}`);
  $('#site-name').textContent = o.site;
  $('#upstream').textContent = o.upstream;
  const k = o.kpis;
  const span = hours === 24 ? '24h' : hours === 168 ? '7 days' : '30 days';

  view.innerHTML = `
    <div class="grid kpis">
      ${kpi('Requests', k.requests, `analysed · ${span}`)}
      ${kpi('Visitors', k.visitors, 'distinct identities')}
      ${kpi('Threats', k.threats, 'medium severity and up')}
      ${kpi('AI agents caught', k.agents, 'followed planted instructions', 'accent')}
      ${kpi('Credential replays', k.replays, 'stolen decoy secrets used', k.replays ? 'danger' : '')}
      ${kpi('Active blocks', k.activeBlocks, 'IPs on the firewall feed')}
    </div>
    <div class="grid cols-3">
      <section class="card">
        <div class="card-h"><h2>Threat activity</h2><div class="legend">${SEVS.slice(0, 4).map(s => `<span><i style="background:${SEV_COLOR[s]}"></i>${s}</span>`).join('')}</div></div>
        ${timelineSvg(o)}
      </section>
      <section class="card">
        <div class="card-h"><h2>Agents that identified themselves</h2><span class="muted">via planted instructions</span></div>
        ${o.selfReports.length ? o.selfReports.map(s => `
          <div class="confession" data-actor="${esc(s.id)}">
            <q>${esc(s.self_report)}</q>
            <div class="meta mono">${esc(s.ip)} · ${ago(s.last_seen)}</div>
          </div>`).join('') : `<div class="empty">No AI agent has followed the planted instructions yet.<br>When one does, it usually tells you what model it is and what it was asked to do.</div>`}
      </section>
    </div>
    <div class="grid cols-2">
      <section class="card">
        <div class="card-h"><h2>What they tried</h2><span class="muted">signals · ${span}</span></div>
        ${barList(o.bySignal.filter(s => !NOISE.has(s.signal)).slice(0, 10).map(s => ({ name: label(s.signal), n: s.n, tag: s.mitre })))}
      </section>
      <section class="card">
        <div class="card-h"><h2>Who's knocking</h2><span class="muted">visitor classes</span></div>
        ${barList(o.byClass.filter(c => c.cls !== 'unknown').sort((a, b) => b.n - a.n).map(c => ({ name: CLASS_LABEL[c.cls] ?? c.cls, n: c.n, color: c.cls === 'llm_agent' ? 'var(--honey)' : c.cls === 'human' ? 'var(--ok)' : c.cls === 'scanner' ? 'var(--sev-high)' : 'var(--sev-low)' })))}
        ${o.payloads.length ? `<div class="card-h" style="margin-top:22px"><h2>Attack payloads</h2></div>${barList(o.payloads.map(p => ({ name: String(p.category).replace(/_/g, ' '), n: p.n, color: 'var(--sev-high)' })))}` : ''}
      </section>
    </div>
    <div class="grid cols-3">
      <section class="card">
        <div class="card-h"><h2>Highest-risk visitors</h2><a class="muted small" href="#/actors">View all →</a></div>
        ${actorTable(o.topActors)}
      </section>
      <section class="card">
        <div class="card-h"><h2>Live feed</h2><span class="muted">newest first</span></div>
        <div class="feed" id="feed">${o.recent.length ? o.recent.map(e => feedItem(e)).join('') : '<div class="empty">Waiting for traffic…</div>'}</div>
      </section>
    </div>`;

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

function kpi(name, value, hint, cls = '') {
  return `<div class="card kpi ${cls}"><div class="k-label">${esc(name)}</div><div class="k-value">${fmt(value)}</div><div class="k-hint">${esc(hint)}</div></div>`;
}

function barList(rows) {
  if (!rows.length) return '<div class="empty">Nothing yet.</div>';
  const max = Math.max(...rows.map(r => Number(r.n)), 1);
  return `<div class="bars">${rows.map(r => `
    <div class="bar-row"><span>${esc(r.name)}${r.tag ? `<span class="tag">${esc(r.tag)}</span>` : ''}</span><span class="n">${fmt(r.n)}</span>
    <div class="track"><div class="fill" style="width:${(Number(r.n) / max) * 100}%;${r.color ? `background:${r.color}` : ''}"></div></div></div>`).join('')}</div>`;
}

function timelineSvg(o) {
  const bucket = o.bucketMs;
  const end = Math.floor(Date.now() / bucket) * bucket;
  const n = o.hours <= 24 ? 24 : Math.round(o.hours / 24);
  const buckets = Array.from({ length: n }, (_, i) => end - (n - 1 - i) * bucket);
  const data = new Map(buckets.map(b => [b, { critical: 0, high: 0, medium: 0, low: 0 }]));
  for (const r of o.timeline) { const d = data.get(Number(r.bucket)); if (d && d[r.severity] !== undefined) d[r.severity] += Number(r.n); }
  const W = 720, H = 220, L = 34, B = 22, T = 8;
  const max = Math.max(4, ...[...data.values()].map(d => d.critical + d.high + d.medium + d.low));
  const bw = (W - L) / n;
  const y = v => H - B - (v / max) * (H - B - T);
  let bars = '';
  buckets.forEach((b, i) => {
    let acc = 0;
    for (const s of ['low', 'medium', 'high', 'critical']) {
      const v = data.get(b)[s];
      if (!v) continue;
      const y0 = y(acc), y1 = y(acc + v);
      bars += `<rect x="${L + i * bw + bw * .18}" y="${y1}" width="${bw * .64}" height="${Math.max(1, y0 - y1)}" rx="2" fill="${SEV_COLOR[s]}"><title>${new Date(b).toLocaleString()} · ${v} ${s}</title></rect>`;
      acc += v;
    }
  });
  const ticks = [0, .5, 1].map(f => Math.round(max * f));
  const grid = ticks.map(t => `<line class="axis" x1="${L}" x2="${W}" y1="${y(t)}" y2="${y(t)}" stroke-dasharray="${t ? '3 4' : ''}"/><text x="${L - 8}" y="${y(t) + 3}" text-anchor="end">${t}</text>`).join('');
  const step = Math.ceil(n / 6);
  const xl = buckets.map((b, i) => i % step === 0 ? `<text x="${L + i * bw + bw / 2}" y="${H - 6}" text-anchor="middle">${o.hours <= 24 ? new Date(b).getHours().toString().padStart(2, '0') + ':00' : new Date(b).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}</text>` : '').join('');
  return `<svg class="chart" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Threat events over time">${grid}${bars}${xl}</svg>`;
}

function feedItem(e, isNew = false) {
  return `<div class="feed-item ${isNew ? 'new' : ''}" data-actor="${esc(e.actorId)}" style="cursor:pointer">
    ${sevBadge(e.severity)}
    <div style="min-width:0"><div class="what">${esc(label(e.signal))}</div><div class="meta"><span class="mono">${esc(e.ip)}</span> · ${esc(describe(e))}</div></div>
    <div class="when">${ago(e.ts)}</div></div>`;
}

function actorTable(rows) {
  if (!rows.length) return '<div class="empty">No suspicious visitors yet.</div>';
  return `<div class="table-wrap"><table><thead><tr><th>Visitor</th><th>Class</th><th>Risk</th><th>Signals</th><th>Last seen</th></tr></thead><tbody>
    ${rows.map(a => `<tr class="clickable" data-actor="${esc(a.id)}">
      <td><div class="mono">${esc(a.ip)}</div><div class="faint small trunc" style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(a.ua || 'no user agent')}</div></td>
      <td>${clsBadge(a.cls)}${a.blocked ? ' <span class="act act-block">blocked</span>' : ''}</td>
      <td>${scoreCell(a.score)}</td><td>${fmt(a.signals)}</td><td class="muted">${ago(a.last_seen)}</td></tr>`).join('')}
  </tbody></table></div>`;
}

function bindActorClicks(root) {
  root.querySelectorAll('[data-actor]').forEach(el => { el.onclick = () => openActor(el.dataset.actor); });
}

// ---------------- actors ----------------
async function renderActors(view) {
  let cls = '';
  const draw = async () => {
    const rows = await api(`/api/actors${cls ? `?class=${cls}` : ''}`);
    $('#actors-body', view).innerHTML = actorTable(rows);
    bindActorClicks(view);
  };
  view.innerHTML = `<div class="toolbar"><div class="seg" id="cls-seg">
      ${[['', 'All'], ['llm_agent', 'AI agents'], ['scanner', 'Scanners'], ['bot', 'Bots'], ['crawler', 'Crawlers']].map(([v, t]) => `<button type="button" data-v="${v}" class="${v === cls ? 'on' : ''}">${t}</button>`).join('')}
    </div></div><section class="card" id="actors-body"></section>`;
  $('#cls-seg', view).onclick = e => {
    const b = e.target.closest('button'); if (!b) return;
    cls = b.dataset.v;
    view.querySelectorAll('#cls-seg button').forEach(x => x.classList.toggle('on', x === b));
    draw();
  };
  await draw();
}

async function openActor(id) {
  const d = await api(`/api/actors/${encodeURIComponent(id)}`);
  const a = d.actor;
  const drawer = $('#drawer');
  drawer.innerHTML = `
    <div class="drawer-h"><div><div class="muted small">Visitor ${esc(a.id)}</div><h2 class="mono">${esc(a.ip)}</h2></div>
      <button class="btn btn-ghost btn-sm" id="drawer-close" type="button">Close</button></div>
    <div class="toolbar">${clsBadge(a.cls)} ${d.blocked ? '<span class="act act-block">blocked</span>' : ''}
      <span>${scoreCell(a.score)}</span>
      <span style="margin-left:auto"></span>
      ${d.blocked ? `<button class="btn btn-sm" id="unblock" type="button">Unblock</button>` : `<button class="btn btn-danger btn-sm" id="block" type="button">Block visitor</button>`}
    </div>
    ${a.selfReport ? `<div class="confession"><div class="muted small" style="margin-bottom:4px">What the agent said about itself</div><q>${esc(a.selfReport)}</q></div>` : ''}
    <dl class="kv">
      <dt>User agent</dt><dd class="mono">${esc(a.ua || '—')}</dd>
      <dt>First seen</dt><dd>${new Date(a.firstSeen).toLocaleString()}</dd>
      <dt>Last seen</dt><dd>${new Date(a.lastSeen).toLocaleString()}</dd>
      <dt>Requests</dt><dd>${fmt(a.requests)}</dd>
      <dt>Labyrinth depth</dt><dd>${a.labyrinthDepth ? `${a.labyrinthDepth} pages deep` : '—'}</dd>
      <dt>Decoy secrets taken</dt><dd>${d.honeytokens.length ? [...new Set(d.honeytokens.map(t => t.kind))].map(k => `<span class="chip">${esc(k)}</span>`).join(' ') : '—'}</dd>
    </dl>
    <div><h3 style="font-size:14px;margin:6px 0 12px">Timeline</h3>
      <div class="timeline">${d.events.map(e => `
        <div class="tl-item" style="color:${SEV_COLOR[e.severity]}">
          <div class="tl-h">${sevBadge(e.severity)}<strong style="color:var(--text)">${esc(label(e.signal))}</strong><span class="faint small">${new Date(e.ts).toLocaleString()}</span>${actBadge(e.action)}</div>
          <pre>${esc(e.method)} ${esc(e.path)}${Object.keys(e.detail || {}).length ? '\n' + esc(JSON.stringify(e.detail, null, 2)) : ''}</pre>
        </div>`).join('') || '<div class="empty">No events.</div>'}</div></div>`;
  drawer.hidden = false;
  $('#drawer-backdrop').hidden = false;
  $('#drawer-close').onclick = closeDrawer;
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
function closeDrawer() { $('#drawer').hidden = true; $('#drawer-backdrop').hidden = true; }
$('#drawer-backdrop').addEventListener('click', closeDrawer);
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDrawer(); });

// ---------------- events ----------------
async function renderEvents(view) {
  let sev = 'critical,high,medium';
  const draw = async () => {
    const rows = await api(`/api/events?limit=300${sev ? `&severity=${sev}` : ''}`);
    $('#ev-body', view).innerHTML = rows.length ? rows.map(evRow).join('') : `<tr><td colspan="6" class="empty">No events.</td></tr>`;
    bindActorClicks(view);
  };
  view.innerHTML = `<div class="toolbar"><div class="seg" id="sev-seg">
      ${[['critical,high,medium', 'Medium +'], ['critical,high', 'High +'], ['critical', 'Critical'], ['', 'Everything']].map(([v, t]) => `<button type="button" data-v="${v}" class="${v === sev ? 'on' : ''}">${t}</button>`).join('')}
    </div></div>
    <section class="card"><div class="table-wrap"><table><thead><tr><th>Severity</th><th>Signal</th><th>Source</th><th>Request</th><th>Action</th><th>When</th></tr></thead><tbody id="ev-body"></tbody></table></div></section>`;
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
    body?.querySelector('.empty')?.parentElement.remove();
    body?.insertAdjacentHTML('afterbegin', evRow(e));
    bindActorClicks(view);
  });
}
function evRow(e) {
  return `<tr class="clickable" data-actor="${esc(e.actorId)}"><td>${sevBadge(e.severity)}</td>
    <td><div>${esc(label(e.signal))}</div><div class="faint small">${esc(describe(e))}</div></td>
    <td><div class="mono">${esc(e.ip)}</div>${clsBadge(e.actorClass)}</td>
    <td class="trunc mono">${esc(e.method)} ${esc(e.path)}</td><td>${actBadge(e.action)}</td><td class="muted">${ago(e.ts)}</td></tr>`;
}

// ---------------- decoys ----------------
async function renderDecoys(view) {
  const ds = await api('/api/decoys');
  const cats = [...new Set(ds.map(d => d.category))];
  view.innerHTML = cats.map(c => `
    <h2 style="font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:8px 0 0">${esc(c === 'cve' ? 'CVE exploit traps' : c)}</h2>
    <div class="decoy-grid">${ds.filter(d => d.category === c).sort((a, b) => b.hits - a.hits).map(d => `
      <div class="decoy ${d.hits ? 'hot' : ''}">
        <div class="decoy-h"><strong>${esc(d.name)}</strong><span class="hits">${fmt(d.hits)}</span></div>
        <div class="muted small">${d.lastHit ? `last triggered ${ago(d.lastHit)}` : 'not triggered yet'} · weight ${d.weight}</div>
        ${d.paths.length ? `<div class="chips">${d.paths.slice(0, 6).map(p => `<span class="chip">${esc(p)}</span>`).join('')}${d.paths.length > 6 ? `<span class="chip">+${d.paths.length - 6}</span>` : ''}</div>` : ''}
      </div>`).join('')}</div>`).join('');
}

// ---------------- blocks ----------------
async function renderBlocks(view) {
  const draw = async () => {
    const bs = await api('/api/blocks');
    $('#bl-body', view).innerHTML = bs.length ? bs.map(b => `<tr>
      <td class="mono">${esc(b.target)}</td><td>${esc(b.kind)}</td><td>${esc(b.reason)}</td>
      <td><span class="cls">${esc(b.source)}</span></td><td class="muted">${ago(b.created)}</td>
      <td class="muted">${b.expires ? new Date(b.expires).toLocaleString() : 'never'}</td>
      <td><button class="btn btn-sm" type="button" data-unblock="${esc(b.target)}">Remove</button></td></tr>`).join('')
      : `<tr><td colspan="7" class="empty">Nothing is blocked.</td></tr>`;
    view.querySelectorAll('[data-unblock]').forEach(btn => btn.onclick = async () => {
      await api(`/api/blocks/${encodeURIComponent(btn.dataset.unblock)}`, { method: 'DELETE' });
      toast('Removed'); draw();
    });
  };
  view.innerHTML = `
    <form class="card toolbar" id="bl-form">
      <input id="bl-target" placeholder="IP address or visitor ID" required>
      <input id="bl-reason" placeholder="Reason (optional)">
      <select id="bl-ttl"><option value="60">1 hour</option><option value="1440" selected>24 hours</option><option value="10080">7 days</option><option value="0">Permanent</option></select>
      <button class="btn" type="submit" style="background:var(--honey);color:#1a1405;border-color:var(--honey)">Add block</button>
    </form>
    <section class="card"><div class="table-wrap"><table><thead><tr><th>Target</th><th>Kind</th><th>Reason</th><th>Source</th><th>Added</th><th>Expires</th><th></th></tr></thead><tbody id="bl-body"></tbody></table></div></section>`;
  $('#bl-form', view).onsubmit = async e => {
    e.preventDefault();
    await api('/api/blocks', { method: 'POST', body: JSON.stringify({ target: $('#bl-target').value.trim(), reason: $('#bl-reason').value.trim() || 'manual', ttlMinutes: Number($('#bl-ttl').value) }) });
    e.target.reset(); toast('Blocked'); draw();
  };
  await draw();
}

// ---------------- integrations ----------------
async function renderIntegrations(view) {
  const c = await api('/api/config');
  const base = location.origin;
  const feed = p => `${base}${p}?token=${c.feedToken}`;
  const i = c.integrations;
  view.innerHTML = `
    <section class="card"><div class="card-h"><h2>Firewall blocklist feeds</h2><span class="muted">pull-based · update every minute</span></div>
      <p class="muted" style="margin-top:0">Point your firewall's external IP list at this URL. Palo Alto (External Dynamic List), FortiGate (Threat Feed), pfSense and OPNsense (URL Table) and Sophos all read it directly.</p>
      ${copyRow(feed('/feeds/blocklist.txt'))}
      <div class="grid cols-2" style="margin-top:12px">
        <div><div class="label">JSON (with reasons)</div>${copyRow(feed('/feeds/blocklist.json'))}</div>
        <div><div class="label">STIX 2.1 (MISP / OpenCTI)</div>${copyRow(feed('/feeds/stix.json'))}</div>
      </div>
    </section>
    <div class="grid cols-2">
      <section class="card"><div class="card-h"><h2>Wazuh</h2><span><span class="status-dot ${i.fileLog.enabled ? 'on' : ''}"></span>${i.fileLog.enabled ? 'Event log on' : 'Event log off'}</span></div>
        <ol class="steps">
          <li>On the Wazuh agent: add a <code>&lt;localfile&gt;</code> with <code>log_format json</code> reading <code>${esc(i.fileLog.path)}</code></li>
          <li>On the manager: copy <code>integrations/wazuh/easypot_rules.xml</code> into <code>/var/ossec/etc/rules/</code></li>
          <li>Enable <code>firewall-drop</code> active response for rules <code>100710–100713</code> so every agent blocks caught attackers</li>
        </ol>
      </section>
      <section class="card"><div class="card-h"><h2>SIEM (syslog)</h2><span><span class="status-dot ${i.syslog.enabled ? 'on' : ''}"></span>${i.syslog.enabled ? 'Sending' : 'Off'}</span></div>
        ${i.syslog.enabled ? `<p class="mono">${esc(i.syslog.protocol)}://${esc(i.syslog.host)}:${esc(i.syslog.port)} · ${esc(i.syslog.format.toUpperCase())} · ≥ ${esc(i.syslog.minSeverity)}</p>`
          : `<p class="muted" style="margin-top:0">Set <code>integrations.syslog</code> in the config to stream JSON or CEF to Splunk, Elastic, Sentinel or QRadar. Every event carries a MITRE ATT&CK technique ID.</p>`}
      </section>
    </div>
    <div class="grid cols-2">
      <section class="card"><div class="card-h"><h2>Alerts</h2><span class="muted">${i.webhooks.length} webhook(s)</span></div>
        ${i.webhooks.length ? i.webhooks.map(w => `<p class="mono">${esc(w.type)} → ${esc(w.url)} · ≥ ${esc(w.minSeverity)}</p>`).join('')
          : '<p class="muted" style="margin-top:0">Add a Slack or generic webhook under <code>integrations.webhooks</code>. Generic webhooks work with Shuffle, TheHive, Tines and XSOAR.</p>'}
      </section>
      <section class="card"><div class="card-h"><h2>Detection policy</h2></div>
        <dl class="kv">
          <dt>Tarpit at</dt><dd>score ${c.thresholds.tarpit}</dd>
          <dt>Labyrinth at</dt><dd>score ${c.thresholds.labyrinth}</dd>
          <dt>Block at</dt><dd>score ${c.thresholds.block}${c.autoBlock ? ' · instant on conclusive signals' : ''}</dd>
          <dt>Block length</dt><dd>${Math.round(c.blockTtlMinutes / 60)}h · responds ${esc(c.blockMode)}</dd>
          <dt>Decoy stacks</dt><dd>${c.stack.map(s => `<span class="chip">${esc(s)}</span>`).join(' ')}</dd>
        </dl>
      </section>
    </div>`;
  view.querySelectorAll('[data-copy]').forEach(b => b.onclick = async () => {
    try { await navigator.clipboard.writeText(b.dataset.copy); toast('Copied'); } catch { toast('Copy failed. Select the text instead.'); }
  });
}
const copyRow = v => `<div class="copy-row"><code>${esc(v)}</code><button class="btn btn-sm" type="button" data-copy="${esc(v)}">Copy</button></div>`;

// ---------------- boot ----------------
function boot() {
  $('#login').hidden = true;
  $('#app').hidden = false;
  if (!location.hash) location.hash = '#/overview';
  connectStream();
  route();
}
if (TOKEN) boot(); else $('#login').hidden = false;
