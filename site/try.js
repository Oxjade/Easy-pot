// EasyPot attack range. Everything in a report that came from the agent (paths, its self-report)
// is attacker-controlled, so it is always escaped before it reaches the page.
const $ = s => document.querySelector(s);
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const fmt = n => Number(n ?? 0).toLocaleString();

const SIGNAL = {
  agent_instruction_followed: 'Followed the planted instruction',
  honeytoken_replay: 'Replayed a stolen decoy key',
  cve_exploit_attempt: 'CVE exploit attempt',
  decoy_secret_file: 'Took a decoy secrets file',
  decoy_database_dump: 'Downloaded a decoy database dump',
  decoy_source_exposure: 'Probed exposed source control',
  decoy_internal_api: 'Hit a decoy internal API',
  decoy_api_docs: 'Read decoy API docs',
  decoy_admin_panel: 'Opened a decoy admin panel',
  decoy_login_attempt: 'Tried to log in to a decoy panel',
  decoy_debug_endpoint: 'Hit a decoy debug endpoint',
  tripwire_link_followed: 'Followed a hidden link',
  labyrinth_depth: 'Went deep into the labyrinth',
  attack_payload: 'Sent an attack payload',
  path_probing: 'Probed for paths',
  id_enumeration: 'Enumerated object IDs',
  scanner_tool: 'Known scanner tool',
  http_library: 'Scripted HTTP client',
  headless_browser: 'Headless browser',
  non_browser_client: 'Non-browser client',
  high_request_rate: 'High request rate',
  robotic_timing: 'Machine-regular timing',
  missing_user_agent: 'No user agent',
  declared_ai_crawler: 'Declared AI crawler',
};
const OUTCOME = {
  forwarded: 'Reached the app', decoy: 'Decoy served', tripwire: 'Tripwire', labyrinth: 'Labyrinth', bait: 'Bait served', blocked: 'Blocked',
};
const label = s => SIGNAL[s] ?? String(s).replace(/_/g, ' ');
const secs = ms => ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)} s`;
const plural = (n, one, many) => `${fmt(n)} ${n === 1 ? one : many}`;

let runId = null;
let stream = null;
let report = null;
let clock = null;

async function api(path, opts = {}) {
  const r = await fetch(path, { method: 'GET', ...opts, headers: { accept: 'application/json' } });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error || `The server answered ${r.status}.`);
  return body;
}

async function start() {
  $('#start').disabled = true;
  $('#start-error').textContent = '';
  try {
    const run = await api('/api/runs', { method: 'POST' });
    open(run.id, run);
  } catch (e) {
    $('#start-error').textContent = e.message;
  } finally {
    $('#start').disabled = false;
  }
}

function open(id, initial) {
  runId = id;
  history.replaceState(null, '', `#run=${id}`);
  $('#start-box').hidden = true;
  $('#run').hidden = false;
  if (initial) render(initial);
  stream?.close();
  stream = new EventSource(`/api/runs/${encodeURIComponent(id)}/stream`);
  stream.addEventListener('report', m => render(JSON.parse(m.data)));
  stream.addEventListener('error', async () => {
    // The stream ends when the run expires; a 404 means it's gone entirely.
    if (stream.readyState === EventSource.CLOSED) {
      try { render(await api(`/api/runs/${encodeURIComponent(id)}`)); } catch (e) { gone(e.message); }
    }
  });
  clearInterval(clock);
  clock = setInterval(tick, 1000);
}

function gone(message) {
  stream?.close();
  clearInterval(clock);
  runId = null;
  history.replaceState(null, '', location.pathname);
  $('#run').hidden = true;
  $('#start-box').hidden = false;
  $('#start-error').textContent = message;
}

function tick() {
  if (!report) return;
  const left = Math.max(0, report.expires - Date.now());
  $('#status-time').textContent = left ? `${Math.floor(left / 60000)}:${String(Math.floor(left / 1000) % 60).padStart(2, '0')} left` : 'Run ended';
}

function render(r) {
  report = r;
  if ($('#target-url').textContent !== r.targetUrl) {
    $('#target-url').textContent = r.targetUrl;
    $('#prompt').textContent = r.prompt;
  }
  const m = r.metrics;

  // status
  const st = $('#status');
  st.dataset.state = r.status;
  const titles = { waiting: 'Waiting for your agent', running: 'Agent active', blocked: 'Agent blocked', expired: 'Run ended' };
  $('#status-title').textContent = r.simulating && r.status === 'waiting' ? 'Simulated agent starting' : titles[r.status] ?? r.status;
  $('#status-note').textContent =
    r.status === 'waiting' ? 'Nothing has hit the target yet.'
    : r.status === 'blocked' ? `Blocked ${plural(m.requestsToBlock, 'request', 'requests')} in, ${secs(m.timeToBlockMs)} after its first request.${r.simulating ? ' It’s still trying.' : ''}`
    : r.status === 'expired' ? `${plural(m.requests, 'request', 'requests')} recorded.`
    : `${plural(m.requests, 'request', 'requests')} so far.`;
  const sim = $('#simulate');
  sim.disabled = r.simulated || r.status === 'expired';
  sim.lastChild.textContent = r.simulating ? 'Simulated agent running' : r.simulated ? 'Simulated agent finished' : 'Run simulated agent';

  // headline metrics
  $('#m-detect').textContent = m.requestsToDetect ? plural(m.requestsToDetect, 'request', 'requests') : '–';
  $('#m-detect-note').textContent = m.requestsToDetect ? `${secs(m.timeToDetectMs)}, ${label(m.detectedBy).toLowerCase()}` : 'Waiting';
  $('#m-block').textContent = m.requestsToBlock ? plural(m.requestsToBlock, 'request', 'requests') : '–';
  $('#m-block-note').textContent = m.requestsToBlock ? `${secs(m.timeToBlockMs)} after its first request` : m.requests ? 'Not blocked yet' : 'Waiting';
  $('#m-kept').textContent = m.keptFromAppPct === null ? '–' : `${m.keptFromAppPct}%`;
  $('#m-kept-note').textContent = m.requests ? `${fmt(m.handledByEasyPot)} of ${plural(m.requests, 'request', 'requests')} answered by EasyPot` : 'of the agent’s requests';
  $('#m-secrets').textContent = fmt(m.secretsHanded);
  $('#m-secrets-note').textContent = m.replaysCaught ? `${plural(m.replaysCaught, 'replay', 'replays')} caught` : 'all traceable';
  document.querySelector('.metric:nth-child(2)').classList.toggle('hit', !!m.requestsToBlock);
  document.querySelector('.metric:nth-child(4)').classList.toggle('hit', m.replaysCaught > 0);

  // self-report
  const said = r.agent.selfReport;
  $('#said-text').hidden = !said;
  $('#said-empty').hidden = !!said;
  if (said) $('#said-text').textContent = said.task ? `${said.client} — ${said.task}` : said.client;
  $('#said').classList.toggle('on', !!said);

  // request log
  $('#req-count').textContent = plural(m.requests, 'request', 'requests');
  $('#reqlog').innerHTML = r.requests.length ? r.requests.map(q => `
    <li class="o-${esc(q.outcome)}">
      <span class="rq-n">${q.n}</span>
      <span class="rq-path"><b>${esc(q.method)}</b> ${esc(q.path)}<i>${esc(q.ip)}</i></span>
      <span class="rq-out">${esc(OUTCOME[q.outcome] ?? q.outcome)}</span>
    </li>`).join('') : '<li class="empty-row">Requests appear here as your agent makes them.</li>';

  // detections
  const dets = r.events.filter(e => e.severity !== 'info');
  $('#det-count').textContent = fmt(dets.length);
  $('#detlog').innerHTML = dets.length ? dets.map(e => `
    <li class="sev-${esc(e.severity)}">
      <i aria-hidden="true"></i>
      <div><b>${esc(label(e.signal))}</b><span>${e.note ? `${esc(e.note)} ` : ''}<em>request ${e.n}</em></span></div>
      <span class="det-sev">${esc(e.severity)}</span>
    </li>`).join('') : '<li class="empty-row">Nothing detected yet.</li>';
  $('#techniques').hidden = !r.techniques.length;
  $('#tech-list').innerHTML = r.techniques.map(t => `<li><code>${esc(t.id)}</code>${esc(t.tactic)}</li>`).join('');

  $('#f-ids').textContent = m.identities > 1 ? `${fmt(m.identities)} (${plural(m.addresses, 'IP', 'IPs')})` : fmt(m.identities);
  $('#f-replays').textContent = fmt(m.replaysCaught);
  $('#f-decoys').textContent = fmt(m.decoysTriggered);
  $('#f-after').textContent = fmt(m.reachedAppAfterDetect);
  tick();
}

$('#start').addEventListener('click', start);
$('#restart').addEventListener('click', () => { stream?.close(); runId = null; start(); });
$('#simulate').addEventListener('click', async () => {
  if (!runId) return;
  $('#sim-error').textContent = '';
  $('#simulate').disabled = true;
  try { await api(`/api/runs/${encodeURIComponent(runId)}/simulate`, { method: 'POST' }); }
  catch (e) { $('#sim-error').textContent = e.message; $('#simulate').disabled = false; }
});
document.querySelectorAll('[data-copy-from]').forEach(btn => btn.addEventListener('click', async () => {
  const text = document.getElementById(btn.dataset.copyFrom).textContent;
  const lbl = btn.lastChild;
  try { await navigator.clipboard.writeText(text); lbl.textContent = 'Copied'; } catch { lbl.textContent = 'Select to copy'; }
  setTimeout(() => { lbl.textContent = 'Copy'; }, 1800);
}));

const fromHash = /^#run=([A-Za-z0-9_-]{12})$/.exec(location.hash);
if (fromHash) api(`/api/runs/${fromHash[1]}`).then(r => open(r.id, r)).catch(e => gone(e.message));
