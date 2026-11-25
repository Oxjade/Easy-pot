import http from 'node:http';
import https from 'node:https';
import { loadConfig } from './config.js';
import { Store } from './store.js';
import { Engine } from './engine.js';
import { Detectors } from './detectors.js';
import { Honeytokens } from './honeytokens.js';
import { BUILTIN_DECOYS, DecoyRouter, loadCvePack } from './decoys/index.js';
import { Proxy } from './proxy.js';
import { startAdmin } from './admin/server.js';
import { wireOutputs } from './integrations/outputs.js';

/**
 * Before enabling decoys, make sure none of them shadow a real page on the protected site.
 * Compares each decoy path against how the upstream answers a path that can't exist (soft-404 aware).
 */
async function probeUpstream(upstream: string, router: DecoyRouter): Promise<void> {
  const base = new URL(upstream);
  const lib = base.protocol === 'https:' ? https : http;
  const get = (path: string) => new Promise<{ status: number; len: number } | null>(resolve => {
    const r = lib.request(new URL(path, base), { method: 'GET', timeout: 4000, headers: { 'user-agent': 'easypot-probe' } }, res => {
      let len = 0;
      res.on('data', c => { len += c.length; });
      res.on('end', () => resolve({ status: res.statusCode ?? 0, len }));
    });
    r.on('error', () => resolve(null));
    r.on('timeout', () => { r.destroy(); resolve(null); });
    r.end();
  });
  const baseline = await get(`/easypot-probe-${Date.now().toString(36)}-does-not-exist`);
  if (!baseline) { console.warn('[easypot] upstream unreachable at startup; skipping decoy collision probe'); return; }
  const disabled: string[] = [];
  for (const path of router.probePaths()) {
    const r = await get(path);
    if (!r || r.status === 404 || r.status === 410) continue;
    const softNotFound = r.status === baseline.status && Math.abs(r.len - baseline.len) < 64;
    if (r.status >= 200 && r.status < 400 && !softNotFound) { router.disablePath(path); disabled.push(path); }
  }
  if (disabled.length) console.warn(`[easypot] ${disabled.length} decoy path(s) exist on the real site and were disabled: ${disabled.join(', ')}`);
}

async function main(): Promise<void> {
  const cfg = loadConfig();
  const store = new Store(cfg.dataDir);
  const engine = new Engine(cfg, store);
  const detectors = new Detectors();
  const tokens = new Honeytokens(store, cfg.siteName);
  const decoys = new DecoyRouter([...BUILTIN_DECOYS, ...loadCvePack(cfg.decoys.cvePack)], cfg.stack, cfg.decoys.exclude);
  wireOutputs(cfg, engine);

  if (cfg.decoys.enabled && cfg.decoys.probeUpstream) await probeUpstream(cfg.upstream, decoys);

  const proxy = new Proxy({ cfg, engine, detectors, tokens, decoys, store });
  const server = http.createServer({ requestTimeout: 120_000, headersTimeout: 30_000 }, proxy.handler);
  server.on('upgrade', proxy.upgradeHandler);
  server.listen(cfg.listen.port, cfg.listen.host, () => {
    console.log(`[easypot] protecting ${cfg.upstream} on http://${cfg.listen.host}:${cfg.listen.port}`);
    console.log(`[easypot] ${decoys.all.length} decoys active (${decoys.all.filter(d => d.category === 'cve').length} CVE), stacks: ${cfg.stack.join(', ')}`);
  });
  const admin = startAdmin({ cfg, engine, store, decoys, startedAt: Date.now() });

  const prune = setInterval(() => store.prune(cfg.retentionDays), 3_600_000);
  prune.unref();

  const shutdown = () => {
    console.log('[easypot] shutting down');
    server.close();
    admin.close();
    store.close();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch(err => { console.error('[easypot] fatal:', err); process.exit(1); });
