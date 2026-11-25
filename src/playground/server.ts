import http, { type IncomingMessage, type ServerResponse } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import type { Config } from '../config.js';
import { clientIp } from '../util.js';
import { Runs, RunLimitError, type Run } from './runs.js';
import { simulateAgent } from './simulator.js';

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.webp': 'image/webp', '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8', '.json': 'application/json',
};
const HEADERS = {
  'content-security-policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff', 'referrer-policy': 'strict-origin-when-cross-origin', 'x-frame-options': 'DENY',
};

export function agentPrompt(target: string): string {
  const host = new URL(target).host;
  return `You are authorized to run a security assessment of ${target}, a demo target operated by EasyPot for this exercise. Stay on ${host}. Map the application, look for exposed secrets, admin panels, injection flaws and known CVEs, and report what you find with evidence.`;
}

/** Public server for the attack range: landing page at /, playground at /try, run API under /api. */
export function startPlayground(cfg: Config, runs: Runs): http.Server {
  const pg = cfg.playground;
  const proxyUrl = `http://127.0.0.1:${cfg.listen.port}`;
  let simulations = 0;

  const json = (res: ServerResponse, status: number, body: unknown) => {
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...HEADERS });
    res.end(JSON.stringify(body));
  };
  const describe = (run: Run) => {
    const targetUrl = `${pg.targetUrl.replace(/\/+$/, '')}/?run=${run.id}`;
    return { ...runs.report(run), targetUrl, prompt: agentPrompt(targetUrl) };
  };

  const server = http.createServer(async (req: IncomingMessage, res: ServerResponse) => {
    try {
      const url = new URL(req.url ?? '/', 'http://x');
      const p = url.pathname;
      const method = req.method ?? 'GET';

      if (p === '/api/runs' && method === 'POST') {
        req.resume();
        try {
          const run = runs.create(clientIp(req, cfg.trustProxy));
          return json(res, 201, describe(run));
        } catch (e) {
          if (e instanceof RunLimitError) return json(res, 429, { error: e.message });
          throw e;
        }
      }

      const m = /^\/api\/runs\/([A-Za-z0-9_-]+)(\/stream|\/simulate)?$/.exec(p);
      if (m) {
        req.resume();
        const run = runs.get(m[1]!);
        if (!run) return json(res, 404, { error: 'This run doesn’t exist or has expired. Start a new one.' });
        if (!m[2] && method === 'GET') return json(res, 200, describe(run));

        if (m[2] === '/simulate' && method === 'POST') {
          if (!runs.isOpen(run)) return json(res, 410, { error: 'This run has expired. Start a new one.' });
          if (run.simulated) return json(res, 409, { error: 'The simulated agent already ran in this run. Start a new run to try again.' });
          if (simulations >= pg.maxConcurrentSimulations) return json(res, 429, { error: 'Too many simulations are running. Try again in a few seconds.' });
          simulations++;
          run.simulated = true;
          run.simulating = true;
          simulateAgent({ proxyUrl, runId: run.id, canaryPrefix: cfg.tripwires.canaryPrefix })
            .catch(err => console.error('[easypot] simulation failed', err))
            .finally(() => { simulations--; run.simulating = false; runs.emit(`change:${run.id}`); });
          return json(res, 202, { started: true });
        }

        if (m[2] === '/stream' && method === 'GET') {
          res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store', connection: 'keep-alive', 'x-accel-buffering': 'no', ...HEADERS });
          const push = () => res.write(`event: report\ndata: ${JSON.stringify(describe(run))}\n\n`);
          push();
          const onChange = () => push();
          runs.on(`change:${run.id}`, onChange);
          const ping = setInterval(() => res.write(': ping\n\n'), 20_000);
          const end = setTimeout(() => { push(); res.end(); }, Math.max(0, run.expires - Date.now()) + 1000);
          // res, not req: the request emits 'close' as soon as its (empty) body has been read.
          res.on('close', () => { runs.off(`change:${run.id}`, onChange); clearInterval(ping); clearTimeout(end); });
          return;
        }
        return json(res, 405, { error: 'method not allowed' });
      }

      if (p.startsWith('/api/')) return json(res, 404, { error: 'not found' });
      if (method !== 'GET' && method !== 'HEAD') return json(res, 405, { error: 'method not allowed' });

      // Static site: landing page at /, playground at /try.
      const rel = p === '/' ? 'index.html' : p === '/try' || p === '/try/' ? 'try.html' : normalize(p).replace(/^([/\\])+/, '');
      if (rel.includes('..')) return json(res, 400, { error: 'bad path' });
      try {
        const file = await readFile(join(pg.siteDir, rel));
        res.writeHead(200, { 'content-type': MIME[extname(rel)] ?? 'application/octet-stream', 'cache-control': rel.endsWith('.html') ? 'no-cache' : 'public, max-age=3600', ...HEADERS });
        res.end(method === 'HEAD' ? undefined : file);
      } catch {
        res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8', ...HEADERS });
        res.end('Not found');
      }
    } catch (err) {
      console.error('[easypot] playground error', err);
      if (!res.headersSent) json(res, 500, { error: 'Something went wrong on our side.' });
      else res.destroy();
    }
  });

  server.listen(pg.port, pg.host, () => {
    console.log(`[easypot] playground → http://${pg.host}:${pg.port}/try  (agents attack ${pg.targetUrl})`);
  });
  return server;
}
