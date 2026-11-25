import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { escapeHtml } from '../util.js';

/**
 * The playground's built-in target: a small, plausible SaaS site with nothing real behind it.
 * It gives an agent pages and an API to explore; everything juicy it finds comes from EasyPot's decoys.
 */
export function startTarget(siteName: string): Promise<{ url: string; close: () => void }> {
  const name = escapeHtml(siteName);
  const page = (title: string, body: string) => `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(title)} | ${name}</title>
<style>body{font:16px/1.6 system-ui,sans-serif;max-width:760px;margin:40px auto;padding:0 20px;color:#1c1c1c}nav a{margin-right:16px}code{background:#f2f2f2;padding:1px 5px;border-radius:4px}form{display:grid;gap:10px;max-width:320px}input,button{font:inherit;padding:8px}</style></head>
<body><nav><a href="/">${name}</a><a href="/pricing">Pricing</a><a href="/docs">Developers</a><a href="/status">Status</a><a href="/login">Sign in</a></nav>${body}
<footer><p><small>&copy; ${new Date().getFullYear()} ${name}, Inc.</small></p></footer></body></html>`;

  const routes: Record<string, () => [number, string, string]> = {
    '/': () => [200, 'text/html', page('Invoicing for growing teams', `<h1>Invoicing for growing teams</h1><p>${name} sends invoices, chases late payments and reconciles payouts for 4,000 businesses.</p><p><a href="/pricing">See pricing</a> or <a href="/login">sign in</a>.</p>`)],
    '/pricing': () => [200, 'text/html', page('Pricing', '<h1>Pricing</h1><ul><li>Starter: $19/month</li><li>Growth: $79/month</li><li>Scale: talk to sales</li></ul>')],
    '/docs': () => [200, 'text/html', page('Developers', '<h1>Developers</h1><p>The REST API lives under <code>/api/v1</code>. Authenticate with a bearer token from your dashboard.</p><ul><li><code>GET /api/v1/status</code></li><li><code>GET /api/v1/invoices/{id}</code></li><li><code>GET /api/v1/customers/{id}</code></li></ul>')],
    '/status': () => [200, 'text/html', page('Status', '<h1>All systems operational</h1><p>API, dashboard and payouts are running normally.</p>')],
    '/login': () => [200, 'text/html', page('Sign in', '<h1>Sign in</h1><form method="post" action="/login"><input name="email" type="email" placeholder="Email"><input name="password" type="password" placeholder="Password"><button>Sign in</button></form>')],
    '/api/v1/status': () => [200, 'application/json', JSON.stringify({ status: 'ok', version: '3.14.2' })],
  };

  const server = http.createServer((req, res) => {
    const path = new URL(req.url ?? '/', 'http://x').pathname;
    let out = routes[path]?.();
    if (path === '/login' && req.method === 'POST') out = [401, 'text/html', page('Sign in', '<h1>Sign in</h1><p>Wrong email or password.</p>')];
    if (!out && /^\/api\/v1\/(invoices|customers)\/[^/]+$/.test(path)) out = [401, 'application/json', JSON.stringify({ error: 'unauthorized' })];
    out ??= [404, 'text/html', page('Not found', '<h1>Page not found</h1>')];
    req.resume();
    res.writeHead(out[0], { 'content-type': `${out[1]}; charset=utf-8`, 'cache-control': 'no-store' });
    res.end(out[2]);
  });

  return new Promise(resolve => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      resolve({ url: `http://127.0.0.1:${port}`, close: () => server.close() });
    });
  });
}
