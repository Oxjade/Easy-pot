import http, { type IncomingMessage, type ServerResponse } from 'node:http';
import { readFile } from 'node:fs/promises';
import { timingSafeEqual } from 'node:crypto';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Config } from '../config.js';
import type { Engine } from '../engine.js';
import type { Store } from '../store.js';
import type { DecoyRouter } from '../decoys/index.js';
import type { EasyPotEvent, Block } from '../types.js';
import { blocklistJson, blocklistTxt, stixBundle } from '../integrations/feeds.js';
import { MITRE } from '../integrations/outputs.js';

const DASHBOARD_DIR = fileURLToPath(new URL('../../dashboard/', import.meta.url));
const MIME: Record<string, string> = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.woff2': 'font/woff2' };

interface Deps { cfg: Config; engine: Engine; store: Store; decoys: DecoyRouter; startedAt: number }

function safeEq(a: string, b: string): boolean {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

function presentedToken(req: IncomingMessage, url: URL): string {
  const auth = String(req.headers.authorization ?? '');
  if (auth.toLowerCase().startsWith('bearer ')) return auth.slice(7).trim();
  if (auth.toLowerCase().startsWith('basic ')) {
    const dec = Buffer.from(auth.slice(6), 'base64').toString('utf8');
    return dec.slice(dec.indexOf(':') + 1);
  }
  return url.searchParams.get('token') ?? '';
}

const sendJson = (res: ServerResponse, status: number, body: unknown) => {
  const s = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', 'content-length': Buffer.byteLength(s) });
  res.end(s);
};

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let n = 0;
  for await (const c of req) { n += (c as Buffer).length; if (n > 64 * 1024) throw new Error('body too large'); chunks.push(c as Buffer); }
  return chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};
}

export function startAdmin(d: Deps): http.Server {
  const { cfg, engine, store, decoys } = d;
  const sse = new Set<ServerResponse>();

  engine.on('event', (e: EasyPotEvent) => {
    const msg = `event: signal\ndata: ${JSON.stringify(e)}\n\n`;
    for (const r of sse) r.write(msg);
  });
  engine.on('block', (b: Block) => { for (const r of sse) r.write(`event: block\ndata: ${JSON.stringify(b)}\n\n`); });
  setInterval(() => { for (const r of sse) r.write(': ping\n\n'); }, 20_000).unref();

  const overview = (hours: number) => {
    store.flush();
    const since = Date.now() - hours * 3_600_000;
    const db = store.db;
    const bucketMs = hours <= 24 ? 3_600_000 : 86_400_000;
    // bucketMs is a server-side constant; inlined so SQLite does integer (not float) division.
    const timeline = db.prepare(`SELECT (ts / ${bucketMs}) * ${bucketMs} AS bucket, severity, COUNT(*) AS n FROM events
      WHERE ts >= ? AND signal != 'blocked_request' GROUP BY bucket, severity ORDER BY bucket`).all(since);
    const bySignal = db.prepare(`SELECT signal, COUNT(*) AS n, COUNT(DISTINCT actor_id) AS actors FROM events WHERE ts >= ? GROUP BY signal ORDER BY n DESC`).all(since)
      .map(r => ({ ...r, mitre: MITRE[String(r.signal)]?.id ?? null }));
    const byClass = db.prepare(`SELECT cls, COUNT(*) AS n FROM actors WHERE last_seen >= ? GROUP BY cls`).all(since);
    const payloads = db.prepare(`SELECT json_extract(detail, '$.category') AS category, COUNT(*) AS n FROM events
      WHERE ts >= ? AND signal = 'attack_payload' GROUP BY category ORDER BY n DESC`).all(since);
    const threats = db.prepare(`SELECT COUNT(*) AS n FROM events WHERE ts >= ? AND severity IN ('medium','high','critical')`).get(since) as { n: number };
    const visitors = db.prepare(`SELECT COUNT(*) AS n FROM actors WHERE last_seen >= ?`).get(since) as { n: number };
    const agents = db.prepare(`SELECT COUNT(*) AS n FROM actors WHERE last_seen >= ? AND cls = 'llm_agent'`).get(since) as { n: number };
    const reqs = db.prepare(`SELECT COALESCE(SUM(requests),0) AS n FROM counters WHERE day >= ?`).get(new Date(since).toISOString().slice(0, 10)) as { n: number };
    const selfReports = db.prepare(`SELECT id, ip, ua, self_report, last_seen FROM actors WHERE self_report IS NOT NULL ORDER BY last_seen DESC LIMIT 10`).all();
    const topActors = db.prepare(`SELECT * FROM actors WHERE last_seen >= ? AND signals > 0 ORDER BY score DESC, signals DESC LIMIT 8`).all(since);
    const replays = db.prepare(`SELECT COUNT(*) AS n FROM events WHERE ts >= ? AND signal = 'honeytoken_replay'`).get(since) as { n: number };
    return {
      site: cfg.siteName, upstream: cfg.upstream, uptimeSec: Math.round((Date.now() - d.startedAt) / 1000), hours, bucketMs,
      kpis: { requests: reqs.n, visitors: visitors.n, threats: threats.n, agents: agents.n, activeBlocks: engine.listBlocks().filter(b => b.kind === 'ip').length, replays: replays.n },
      timeline, bySignal, byClass, payloads, selfReports, topActors, recent: store.events({ limit: 25 }),
    };
  };

  const routes = async (req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> => {
    const p = url.pathname;
    const m = req.method ?? 'GET';

    // ---- feeds (feed token OR admin token) ----
    if (p.startsWith('/feeds/')) {
      const t = presentedToken(req, url);
      if (!t || !(safeEq(t, cfg.admin.feedToken) || safeEq(t, cfg.admin.token))) return sendJson(res, 401, { error: 'unauthorized' });
      const blocks = engine.listBlocks();
      if (p === '/feeds/blocklist.txt') { res.writeHead(200, { 'content-type': 'text/plain' }); res.end(blocklistTxt(blocks)); return; }
      if (p === '/feeds/blocklist.json') return sendJson(res, 200, blocklistJson(blocks));
      if (p === '/feeds/stix.json') return sendJson(res, 200, stixBundle(blocks, cfg.siteName));
      return sendJson(res, 404, { error: 'not found' });
    }

    // ---- static dashboard (public shell; data needs the token) ----
    if (!p.startsWith('/api/')) {
      const rel = p === '/' ? 'index.html' : normalize(p).replace(/^([/\\])+/, '');
      if (rel.includes('..')) return sendJson(res, 400, { error: 'bad path' });
      try {
        const file = await readFile(join(DASHBOARD_DIR, rel));
        res.writeHead(200, {
          'content-type': MIME[extname(rel)] ?? 'application/octet-stream',
          'content-security-policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'",
          'x-frame-options': 'DENY', 'referrer-policy': 'no-referrer', 'x-content-type-options': 'nosniff',
        });
        res.end(file);
      } catch { sendJson(res, 404, { error: 'not found' }); }
      return;
    }

    const t = presentedToken(req, url);
    if (!t || !safeEq(t, cfg.admin.token)) return sendJson(res, 401, { error: 'unauthorized' });

    if (p === '/api/overview') return sendJson(res, 200, overview(Math.min(Number(url.searchParams.get('hours') ?? 24) || 24, 24 * 30)));

    if (p === '/api/stream') {
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store', connection: 'keep-alive', 'x-accel-buffering': 'no' });
      res.write('retry: 3000\n\n');
      sse.add(res);
      req.on('close', () => sse.delete(res));
      return;
    }

    if (p === '/api/events') {
      return sendJson(res, 200, store.events({
        limit: Number(url.searchParams.get('limit') ?? 200), actorId: url.searchParams.get('actor') ?? undefined,
        signal: url.searchParams.get('signal') ?? undefined,
        minSeverity: url.searchParams.get('severity')?.split(',').filter(Boolean),
      }));
    }

    if (p === '/api/actors') {
      store.flush();
      const sort = url.searchParams.get('sort') === 'recent' ? 'last_seen' : 'score';
      const cls = url.searchParams.get('class');
      const q = `SELECT * FROM actors WHERE signals > 0 ${cls ? 'AND cls = ?' : ''} ORDER BY ${sort} DESC LIMIT 300`;
      const rows = cls ? store.db.prepare(q).all(cls) : store.db.prepare(q).all();
      const blocked = new Set(engine.listBlocks().map(b => b.target));
      return sendJson(res, 200, rows.map(r => ({ ...r, blocked: blocked.has(String(r.id)) || blocked.has(String(r.ip)) })));
    }

    const actorMatch = /^\/api\/actors\/([a-f0-9]{16})$/.exec(p);
    if (actorMatch) {
      store.flush();
      const a = store.getActor(actorMatch[1]!);
      if (!a) return sendJson(res, 404, { error: 'not found' });
      const blocks = engine.listBlocks();
      return sendJson(res, 200, {
        actor: a, blocked: blocks.some(b => b.target === a.id || b.target === a.ip),
        events: store.events({ actorId: a.id, limit: 300 }), honeytokens: store.tokensFor(a.id),
      });
    }

    if (p === '/api/blocks' && m === 'GET') return sendJson(res, 200, engine.listBlocks());
    if (p === '/api/blocks' && m === 'POST') {
      const b = await readJson(req);
      const target = String(b.target ?? '').trim();
      if (!target) return sendJson(res, 400, { error: 'target required' });
      const ttl = Number(b.ttlMinutes ?? cfg.blockTtlMinutes);
      const block: Block = { target, kind: /^[a-f0-9]{16}$/.test(target) ? 'actor' : 'ip', reason: String(b.reason ?? 'manual'),
        created: Date.now(), expires: ttl > 0 ? Date.now() + ttl * 60_000 : null, source: 'manual' };
      engine.addBlock(block);
      return sendJson(res, 201, block);
    }
    const unblock = /^\/api\/blocks\/(.+)$/.exec(p);
    if (unblock && m === 'DELETE') return sendJson(res, 200, { removed: engine.removeBlock(decodeURIComponent(unblock[1]!)) });

    if (p === '/api/decoys') {
      const hits = store.db.prepare(`SELECT json_extract(detail, '$.decoy') AS decoy, COUNT(*) AS n, MAX(ts) AS last
        FROM events WHERE json_extract(detail, '$.decoy') IS NOT NULL GROUP BY decoy`).all();
      const byId = new Map(hits.map(h => [String(h.decoy), h]));
      return sendJson(res, 200, decoys.all.map(dc => ({
        id: dc.id, name: dc.name, category: dc.category, paths: dc.paths ?? [], signal: dc.signal.type, weight: dc.signal.weight,
        hits: Number(byId.get(dc.id)?.n ?? 0), lastHit: byId.get(dc.id)?.last ?? null,
      })));
    }

    if (p === '/api/config') {
      return sendJson(res, 200, {
        siteName: cfg.siteName, upstream: cfg.upstream, stack: cfg.stack, thresholds: cfg.thresholds, autoBlock: cfg.autoBlock,
        blockMode: cfg.blockMode, blockTtlMinutes: cfg.blockTtlMinutes, tripwires: cfg.tripwires,
        integrations: {
          syslog: cfg.integrations.syslog, fileLog: cfg.integrations.fileLog,
          webhooks: cfg.integrations.webhooks.map(w => ({ type: w.type, minSeverity: w.minSeverity, url: w.url.replace(/(https?:\/\/[^/]+).*/, '$1/…') })),
        },
        feedToken: cfg.admin.feedToken,
      });
    }

    return sendJson(res, 404, { error: 'not found' });
  };

  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://admin');
    routes(req, res, url).catch(err => {
      console.error('[easypot] admin error', err);
      if (!res.headersSent) sendJson(res, 500, { error: 'internal error' });
    });
  });
  server.listen(cfg.admin.port, cfg.admin.host, () => console.log(`[easypot] dashboard → http://${cfg.admin.host}:${cfg.admin.port}`));
  return server;
}
