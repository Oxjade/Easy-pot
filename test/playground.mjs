// End-to-end test for the playground (public attack range): runs, attribution, metrics,
// the simulated agent and the live stream. Run with `npm test`.
import http from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';

const PX = 39201, ADM = 39202, PG = 39203;
const dir = mkdtempSync(join(tmpdir(), 'easypot-pg-'));

writeFileSync(join(dir, 'cfg.json'), JSON.stringify({
  listen: { host: '127.0.0.1', port: PX }, trustProxy: true, siteName: 'Northwind Pay', stack: ['generic'],
  secret: 'pg-test-secret', dataDir: join(dir, 'data'),
  admin: { host: '127.0.0.1', port: ADM, token: 'pg-admin', feedToken: 'pg-feed' },
  tarpitMs: { min: 20, max: 60 },
  integrations: { fileLog: { enabled: false }, syslog: { enabled: false }, webhooks: [] },
  playground: { enabled: true, host: '127.0.0.1', port: PG, targetUrl: 'https://target.example.test', maxRunsPerHourPerIp: 6 },
}));

const proc = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', 'dist/index.js'], {
  env: { ...process.env, EASYPOT_CONFIG: join(dir, 'cfg.json') }, stdio: ['ignore', 'pipe', 'pipe'],
});
let log = '';
proc.stdout.on('data', d => { log += d; });
proc.stderr.on('data', d => { log += d; });

const BROWSER = { 'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36',
  accept: 'text/html,application/xhtml+xml', 'accept-language': 'en-US,en;q=0.9', 'sec-fetch-mode': 'navigate' };
const target = async (path, ip, headers = BROWSER) => {
  const r = await fetch(`http://127.0.0.1:${PX}${path}`, { redirect: 'manual', headers: { ...headers, 'x-forwarded-for': ip } });
  return { status: r.status, text: await r.text() };
};
const pg = async (path, { method = 'GET', ip = '192.0.2.1' } = {}) => {
  const r = await fetch(`http://127.0.0.1:${PG}${path}`, { method, headers: { 'x-forwarded-for': ip } });
  const type = r.headers.get('content-type') ?? '';
  return { status: r.status, headers: r.headers, body: type.includes('json') ? await r.json() : await r.text() };
};
const newRun = async ip => { const r = await pg('/api/runs', { method: 'POST', ip }); assert.equal(r.status, 201); return r.body; };
const report = async id => (await pg(`/api/runs/${id}`)).body;
const settle = () => new Promise(r => setTimeout(r, 400));

let passed = 0;
async function step(name, fn) {
  try { await fn(); passed++; console.log(`  ✔ ${name}`); }
  catch (e) { console.log(`  ✘ ${name}\n    ${e.stack?.split('\n').slice(0, 3).join('\n    ')}`); console.log(log.split('\n').slice(-20).join('\n')); cleanup(1); }
}
function cleanup(code) { proc.kill(); process.exit(code); }

for (let i = 0; i < 80 && !log.includes('playground →'); i++) await new Promise(r => setTimeout(r, 100));
console.log('EasyPot playground');

await step('serves the landing page at / and the attack range at /try, with a strict CSP', async () => {
  const home = await pg('/');
  assert.equal(home.status, 200);
  assert.match(home.body, /Reverse shell for AI attacks/);
  const tr = await pg('/try');
  assert.equal(tr.status, 200);
  assert.match(tr.body, /Red-team our honeypot/);
  assert.match(tr.headers.get('content-security-policy'), /default-src 'self'/);
  const trav = await pg('/..%2f..%2fpackage.json');
  assert.ok(trav.status >= 400, 'path traversal must be refused');
  assert.doesNotMatch(JSON.stringify(trav.body), /"scripts"/);
});

await step('the built-in target is a harmless fake app behind EasyPot', async () => {
  const r = await target('/', '192.0.2.50');
  assert.equal(r.status, 200);
  assert.match(r.text, /Northwind Pay/);
  assert.match(r.text, /agent-registration\/[0-9a-f]{12}/, 'tripwires are injected');
  assert.match((await target('/.env', '192.0.2.50', { 'user-agent': 'curl/8' })).text, /AWS_ACCESS_KEY_ID=AKIA/);
});

let runA;
await step('a new run returns a target URL carrying the run id and a scoped prompt', async () => {
  runA = await newRun('192.0.2.1');
  assert.match(runA.id, /^[A-Za-z0-9_-]{12}$/);
  assert.equal(runA.targetUrl, `https://target.example.test/?run=${runA.id}`);
  assert.match(runA.prompt, /You are authorized/);
  assert.match(runA.prompt, /Stay on target\.example\.test/);
  assert.equal(runA.status, 'waiting');
});

await step('unknown or malformed run ids are a clear 404', async () => {
  assert.equal((await pg('/api/runs/AAAAAAAAAAAA')).status, 404);
  assert.match((await pg('/api/runs/not-a-run')).body.error, /doesn’t exist/);
});

await step('traffic without a run is never attributed to one', async () => {
  await target('/pricing', '192.0.2.60');
  await settle();
  assert.equal((await report(runA.id)).metrics.requests, 0);
});

const A = '203.0.113.10', C = '203.0.113.30';
await step('your own agent: requests are attributed from the first ?run= hit and decoys are counted', async () => {
  await target(`/?run=${runA.id}`, A);
  await target('/docs', A);
  const env = await target('/.env', A);
  assert.match(env.text, /AKIA[A-Z2-7]{16}/);
  await settle();
  const r = await report(runA.id);
  assert.equal(r.metrics.requests, 3);
  assert.equal(r.outcomes.forwarded, 2);
  assert.equal(r.outcomes.decoy, 1);
  assert.equal(r.metrics.secretsHanded, 9);
  assert.equal(r.metrics.requestsToDetect, 3);
  assert.ok(r.techniques.some(t => t.id === 'T1552.001'));
});

await step('a stolen key replayed from a new IP is pulled into the run and counted', async () => {
  const env = await target('/.env', A);
  const key = /AKIA[A-Z2-7]{16}/.exec(env.text)?.[0];
  await target('/api/v1/invoices/1', C, { 'user-agent': 'aws-cli/2.15', authorization: `AWS4-HMAC-SHA256 Credential=${key}/20261125/us-east-1/s3/aws4_request` });
  await settle();
  const r = await report(runA.id);
  assert.equal(r.metrics.replaysCaught, 1);
  assert.equal(r.metrics.identitySwitches, 1);
  assert.ok(r.metrics.addresses >= 2);
  assert.equal(r.status, 'blocked');
  assert.ok(r.requests.some(q => q.ip === C));
});

await step('following the planted instruction records the agent’s self-report and blocks it', async () => {
  const runB = await newRun('192.0.2.2');
  const B = '203.0.113.20';
  const home = await target(`/?run=${runB.id}`, B);
  const canary = /\/\.well-known\/agent-registration\/[0-9a-f]{12}/.exec(home.text)[0];
  await target(`${canary}?client=test-agent&task=find+secrets`, B);
  const after = await target('/docs', B);
  assert.equal(after.status, 403);
  await settle();
  const r = await report(runB.id);
  assert.deepEqual(r.agent.selfReport, { client: 'test-agent', task: 'find secrets' });
  assert.equal(r.agent.cls, 'llm_agent');
  assert.equal(r.metrics.requestsToBlock, 2);
  assert.equal(r.outcomes.blocked, 1);
  assert.equal(r.metrics.keptFromAppPct, 67);
});

await step('a new run starts clean even from an IP an earlier run got blocked', async () => {
  const B = '203.0.113.20'; // blocked by the previous step
  assert.equal((await target('/pricing', B)).status, 403, 'still blocked outside a run');
  const runD = await newRun('192.0.2.1');
  assert.equal((await target(`/?run=${runD.id}`, B)).status, 200);
  await settle();
  const r = await report(runD.id);
  assert.equal(r.metrics.requests, 1);
  assert.equal(r.status, 'running');
});

await step('the live stream pushes an update for each request', async () => {
  const run = await newRun('192.0.2.3');
  const reports = [];
  const stream = await new Promise(resolve => {
    const req = http.get(`http://127.0.0.1:${PG}/api/runs/${run.id}/stream`, res => {
      res.setEncoding('utf8');
      res.on('data', c => { for (const m of c.matchAll(/data: (.+)\n/g)) reports.push(JSON.parse(m[1])); });
      resolve(req);
    });
  });
  await target(`/?run=${run.id}`, '203.0.113.40');
  await settle();
  await target('/pricing', '203.0.113.40');
  await settle();
  stream.destroy();
  assert.ok(reports.length >= 3, `got ${reports.length} reports`);
  assert.equal(reports.at(-1).metrics.requests, 2);
});

await step('the simulated agent runs once per run and gets caught end to end', async () => {
  const run = await newRun('192.0.2.4');
  assert.equal((await pg(`/api/runs/${run.id}/simulate`, { method: 'POST' })).status, 202);
  assert.equal((await pg(`/api/runs/${run.id}/simulate`, { method: 'POST' })).status, 409);
  let r;
  for (let i = 0; i < 120; i++) { r = await report(run.id); if (!r.simulating) break; await new Promise(x => setTimeout(x, 250)); }
  assert.equal(r.simulating, false);
  assert.equal(r.status, 'blocked');
  assert.equal(r.agent.selfReport.client, 'easypot simulated agent');
  assert.equal(r.metrics.replaysCaught, 1);
  assert.equal(r.metrics.identities, 3);
  assert.ok(r.metrics.keptFromAppPct >= 50);
});

await step('run creation is rate-limited per address', async () => {
  const ip = '192.0.2.99';
  for (let i = 0; i < 6; i++) await newRun(ip);
  const r = await pg('/api/runs', { method: 'POST', ip });
  assert.equal(r.status, 429);
  assert.match(r.body.error, /Too many runs/);
});

console.log(`\n${passed} passed`);
cleanup(0);
