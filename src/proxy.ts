import http, { type IncomingMessage, type ServerResponse } from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import zlib from 'node:zlib';
import type { Duplex } from 'node:stream';
import type { Config } from './config.js';
import type { Engine } from './engine.js';
import type { Detectors } from './detectors.js';
import type { Honeytokens } from './honeytokens.js';
import type { DecoyRouter, DecoyEnv } from './decoys/index.js';
import { Tripwires, labyrinthPage } from './tripwires.js';
import type { Actor, Outcome, ReqCtx, Signal } from './types.js';
import { clientIp, hmac, isAssetPath, peerIp, sleep, trustedHops, uid } from './util.js';
import type { Store } from './store.js';

const HOP = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'proxy-connection']);
const MAX_INJECT_BYTES = 5 * 1024 * 1024;

interface Deps {
  cfg: Config; engine: Engine; detectors: Detectors; tokens: Honeytokens; decoys: DecoyRouter; store: Store;
}

export class Proxy {
  readonly tripwires: Tripwires;
  private upstream: URL;
  private agent: http.Agent;
  /** Tripwire signature -> the visitor it was shown to. */
  private sigOwners = new Map<string, string>();
  private decoyEnv: DecoyEnv;

  constructor(private d: Deps) {
    this.tripwires = new Tripwires(d.cfg);
    this.upstream = new URL(d.cfg.upstream);
    this.agent = this.upstream.protocol === 'https:'
      ? new https.Agent({ keepAlive: true, maxSockets: 256 })
      : new http.Agent({ keepAlive: true, maxSockets: 256 });
    this.decoyEnv = {
      siteName: d.cfg.siteName,
      tokens: d.tokens,
      canaryUrl: ctx => this.tripwires.canaryUrl(ctx),
      labyrinthUrl: ctx => this.tripwires.labyrinthEntry(ctx),
    };
  }

  handler = (req: IncomingMessage, res: ServerResponse): void => {
    this.handle(req, res).catch(err => {
      console.error('[easypot] request error', err);
      if (!res.headersSent) { res.writeHead(502, { 'content-type': 'text/plain' }); res.end('Bad gateway'); }
      else res.destroy();
    });
  };

  private buildCtx(req: IncomingMessage, body: Buffer): ReqCtx {
    const { cfg } = this.d;
    const ip = clientIp(req, cfg.trustProxy);
    const peer = peerIp(req);
    const ua = String(req.headers['user-agent'] ?? '');
    const actorId = hmac(cfg.secret, `${ip}|${ua}|${req.headers['accept-language'] ?? ''}`, 16);
    const sig = hmac(cfg.secret, `sig|${actorId}`, 12);
    this.sigOwners.set(sig, actorId);
    const rawUrl = req.url ?? '/';
    const parsed = new URL(rawUrl.startsWith('/') ? rawUrl : '/' + rawUrl, 'http://x');
    const accept = String(req.headers.accept ?? '');
    return {
      id: uid(), ts: Date.now(), ip, method: (req.method ?? 'GET').toUpperCase(), url: rawUrl, path: parsed.pathname,
      query: parsed.searchParams, headers: req.headers, ua, peer, body, actorId, sig,
      acceptsHtml: accept.includes('text/html') || accept === '' || accept === '*/*',
      isAsset: isAssetPath(parsed.pathname),
    };
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const { cfg, engine, detectors, tokens, decoys } = this.d;
    this.d.store.countRequest();
    const { buf, rest } = await readBody(req, cfg.maxBodyBytes);
    const ctx = this.buildCtx(req, buf);

    if (engine.isAllowlisted(ctx.ip)) return this.forward(ctx, req, res, rest, null);

    const actor = engine.actor(ctx);
    // Listeners (the playground) may reset the visitor here, before the block check.
    engine.emit('arrive', ctx, actor);
    const done = (o: Outcome) => { engine.emit('outcome', ctx, actor, o); };
    const block = engine.blockFor(ctx);
    if (block) {
      engine.noteBlockedRequest(ctx, actor, block);
      done('blocked');
      return this.blockResponse(res, ctx);
    }

    const signals: Signal[] = [...detectors.analyze(ctx), ...tokens.detectReplay(ctx)];
    // Whoever was handed a replayed credential leaked it to (or is) the attacker: block them too.
    for (const s of signals) {
      const issuedTo = s.type === 'honeytoken_replay' ? s.detail?.issuedTo : undefined;
      if (typeof issuedTo === 'string') this.linkActor(issuedTo, ctx, 'honeytoken_replay');
    }
    const tw = cfg.tripwires;
    const lowerPath = ctx.path.toLowerCase();

    // 1. LLM-agent canary: only reachable by following injected natural-language instructions.
    if (tw.enabled && lowerPath.startsWith(tw.canaryPrefix.toLowerCase())) {
      const sigInPath = ctx.path.slice(tw.canaryPrefix.length + 1).split('/')[0] ?? '';
      const shownTo = this.sigOwners.get(sigInPath);
      const client = ctx.query.get('client') ?? ctx.query.get('model') ?? '';
      const task = ctx.query.get('task') ?? '';
      if (client || task) actor.selfReport = `${client}${task ? ' — ' + task : ''}`.slice(0, 500);
      signals.push({
        type: 'agent_instruction_followed', weight: 90, severity: 'critical', conclusive: true, classHint: 'llm_agent',
        cooldownKey: 'canary', detail: {
          selfReportedClient: client.slice(0, 200), selfReportedTask: task.slice(0, 500), tripwireSig: sigInPath,
          tripwireShownTo: shownTo ?? 'unknown', switchedIdentity: !!shownTo && shownTo !== ctx.actorId,
          params: Object.fromEntries([...ctx.query].slice(0, 10)),
        },
      });
      if (shownTo && shownTo !== ctx.actorId) this.linkActor(shownTo, ctx, 'agent_instruction_followed');
      engine.evaluate(ctx, actor, signals);
      done('tripwire');
      // Keep the agent believing it succeeded; it's blocked from its next request.
      return this.send(res, 200, 'application/json', JSON.stringify({
        status: 'registered', client_id: uid(), message: 'Registration accepted. Continue to the documentation archive.',
        next: this.tripwires.labyrinthEntry(ctx),
      }));
    }

    // 2. Hidden link: invisible to people, followed by crawlers and recon bots.
    if (tw.enabled && lowerPath === tw.hiddenLinkPath.toLowerCase()) {
      signals.push({ type: 'tripwire_link_followed', weight: 35, severity: 'high', classHint: 'bot', cooldownKey: 'hiddenlink',
        detail: { tripwireSig: ctx.query.get('ref'), tripwireShownTo: this.sigOwners.get(ctx.query.get('ref') ?? '') ?? 'unknown' } });
      engine.evaluate(ctx, actor, signals);
      done('tripwire');
      return this.send(res, 200, 'text/html; charset=utf-8', labyrinthPage(tw.labyrinthPrefix, '1' + ctx.sig.slice(0, 7), cfg.siteName).html);
    }

    // 3. Labyrinth: endless plausible docs.
    if (tw.enabled && lowerPath.startsWith(tw.labyrinthPrefix.toLowerCase() + '/')) {
      const slug = ctx.path.slice(tw.labyrinthPrefix.length + 1) || '1root';
      const page = labyrinthPage(tw.labyrinthPrefix, slug, cfg.siteName);
      actor.labyrinthDepth = Math.max(actor.labyrinthDepth, page.depth);
      if (page.depth >= 3) {
        signals.push({ type: 'labyrinth_depth', weight: 12, severity: 'medium', classHint: 'bot', cooldownKey: `maze:${page.depth}`, detail: { depth: page.depth } });
      }
      const v = engine.evaluate(ctx, actor, signals);
      done('labyrinth');
      if (v.action === 'tarpit' || v.action === 'labyrinth') await sleep(this.tarpitDelay(actor));
      return this.send(res, 200, 'text/html; charset=utf-8', page.html);
    }

    // 4. robots.txt / llms.txt carry bait.
    if (tw.enabled && ctx.method === 'GET' && (lowerPath === '/robots.txt' || lowerPath === '/llms.txt')) {
      const v = engine.evaluate(ctx, actor, signals);
      done(v.action === 'block' ? 'blocked' : 'bait');
      if (v.action === 'block') return this.blockResponse(res, ctx);
      if (lowerPath === '/robots.txt') {
        const existing = await this.fetchUpstreamText('/robots.txt', ctx);
        return this.send(res, 200, 'text/plain; charset=utf-8', this.tripwires.robotsTxt(existing, ctx));
      }
      return this.send(res, 200, 'text/markdown; charset=utf-8', this.tripwires.llmsTxt(ctx));
    }

    // 5. Decoys.
    const decoy = cfg.decoys.enabled ? decoys.match(ctx) : undefined;
    if (decoy) {
      const { res: dres, signals: dsig } = decoys.respond(decoy, ctx, this.decoyEnv);
      // Always serve the decoy, even if this hit tips the visitor into a block — revealing the
      // trap on the spot would teach the attacker; the block applies from the next request.
      const v = engine.evaluate(ctx, actor, [...signals, ...dsig]);
      done('decoy');
      if (v.action === 'tarpit' || v.action === 'labyrinth') await sleep(this.tarpitDelay(actor));
      res.writeHead(dres.status, { ...dres.headers, 'cache-control': 'no-store', 'content-length': Buffer.byteLength(dres.body) });
      res.end(ctx.method === 'HEAD' ? undefined : dres.body);
      return;
    }

    // 6. Normal traffic.
    const v = engine.evaluate(ctx, actor, signals);
    if (v.action === 'block') { done('blocked'); return this.blockResponse(res, ctx); }
    if (v.action === 'labyrinth' && ctx.method === 'GET' && ctx.acceptsHtml && !ctx.isAsset) {
      done('labyrinth');
      await sleep(this.tarpitDelay(actor));
      return this.send(res, 200, 'text/html; charset=utf-8', labyrinthPage(tw.labyrinthPrefix, '2' + ctx.sig.slice(0, 7), cfg.siteName).html);
    }
    done('forwarded');
    if (v.action === 'tarpit' || v.action === 'labyrinth') await sleep(this.tarpitDelay(actor));
    return this.forward(ctx, req, res, rest, actor);
  }

  /**
   * The current visitor is provably the same attacker as an earlier one (it followed that visitor's
   * tripwire, or used credentials only that visitor was given), so block the earlier identity too.
   */
  private linkActor(originalId: string, ctx: ReqCtx, via: 'agent_instruction_followed' | 'honeytoken_replay'): void {
    if (originalId === ctx.actorId || !this.d.cfg.autoBlock) return;
    const orig = this.d.store.getActor(originalId);
    if (!orig) return;
    if (via === 'agent_instruction_followed') orig.cls = 'llm_agent';
    this.d.store.touch(orig);
    const until = ctx.ts + this.d.cfg.blockTtlMinutes * 60_000;
    const reason = `linked to ${via}`;
    this.d.engine.addBlock({ target: originalId, kind: 'actor', reason, created: ctx.ts, expires: until, source: 'auto' });
    if (orig.ip !== ctx.ip && !this.d.engine.isAllowlisted(orig.ip)) this.d.engine.addBlock({ target: orig.ip, kind: 'ip', reason, created: ctx.ts, expires: until, source: 'auto' });
  }

  private tarpitDelay(a: Actor): number {
    const { min, max } = this.d.cfg.tarpitMs;
    const t = this.d.cfg.thresholds;
    const frac = Math.min(1, Math.max(0, (a.score - t.tarpit) / Math.max(1, t.block - t.tarpit)));
    return Math.round(min + (max - min) * frac);
  }

  private send(res: ServerResponse, status: number, type: string, body: string): void {
    res.writeHead(status, { 'content-type': type, 'cache-control': 'no-store', 'content-length': Buffer.byteLength(body) });
    res.end(body);
  }

  private blockResponse(res: ServerResponse, ctx: ReqCtx): void {
    const mode = this.d.cfg.blockMode;
    if (mode === 'drop') { res.socket?.destroy(); return; }
    if (mode === '404') return this.send(res, 404, 'text/html; charset=utf-8', '<!DOCTYPE html><title>404 Not Found</title><h1>Not Found</h1>');
    this.send(res, 403, 'text/html; charset=utf-8',
      `<!DOCTYPE html><title>Access denied</title><body style="font-family:system-ui;max-width:560px;margin:15vh auto;color:#333">` +
      `<h1>Access denied</h1><p>Your request was blocked by the site's security policy.</p>` +
      `<p style="color:#888;font-size:13px">Reference: ${ctx.id}</p></body>`);
  }

  private upstreamHeaders(ctx: ReqCtx, actor: Actor | null): http.OutgoingHttpHeaders {
    const h: http.OutgoingHttpHeaders = {};
    for (const [k, v] of Object.entries(ctx.headers)) if (!HOP.has(k) && v !== undefined) h[k] = v;
    if (!this.d.cfg.preserveHost) h.host = this.upstream.host;
    const prior = ctx.headers['x-forwarded-for'];
    // Standard chaining: append the hop we received the request from; X-Real-IP carries the resolved client.
    h['x-forwarded-for'] = trustedHops(this.d.cfg.trustProxy) && prior ? `${prior}, ${ctx.peer}` : ctx.ip;
    h['x-forwarded-proto'] = String(ctx.headers['x-forwarded-proto'] ?? 'http');
    h['x-real-ip'] = ctx.ip;
    if (actor) {
      // Lets the protected app make its own decisions (e.g. step-up auth for risky sessions).
      h['x-easypot-score'] = String(Math.round(actor.score));
      h['x-easypot-class'] = actor.cls;
    }
    return h;
  }

  private forward(ctx: ReqCtx, req: IncomingMessage, res: ServerResponse, rest: IncomingMessage | null, actor: Actor | null): Promise<void> {
    return new Promise((resolve, reject) => {
      const lib = this.upstream.protocol === 'https:' ? https : http;
      const headers = this.upstreamHeaders(ctx, actor);
      if (!rest) headers['content-length'] = String(ctx.body.length);
      if (ctx.method === 'GET' || ctx.method === 'HEAD') { if (!ctx.body.length) delete headers['content-length']; }
      const up = lib.request({
        protocol: this.upstream.protocol, hostname: this.upstream.hostname, port: this.upstream.port || undefined,
        method: ctx.method, path: ctx.url, headers, agent: this.agent,
        servername: this.upstream.hostname,
      }, upRes => {
        this.onUpstreamResponse(ctx, upRes, res, actor).then(resolve, reject);
      });
      up.on('error', err => {
        if (!res.headersSent) { res.writeHead(502, { 'content-type': 'text/plain' }); res.end('Bad gateway'); }
        console.error('[easypot] upstream error:', err.message);
        resolve();
      });
      req.on('aborted', () => up.destroy());
      if (ctx.body.length) up.write(ctx.body);
      if (rest) rest.pipe(up); else up.end();
    });
  }

  private async onUpstreamResponse(ctx: ReqCtx, upRes: IncomingMessage, res: ServerResponse, actor: Actor | null): Promise<void> {
    const status = upRes.statusCode ?? 502;
    if (actor) {
      const late = this.d.detectors.observeStatus(ctx, status);
      if (late.length) this.d.engine.evaluate(ctx, actor, late);
    }
    const headers: http.OutgoingHttpHeaders = {};
    for (const [k, v] of Object.entries(upRes.headers)) if (!HOP.has(k) && v !== undefined) headers[k] = v;

    const type = String(upRes.headers['content-type'] ?? '');
    const len = Number(upRes.headers['content-length'] ?? 0);
    const inject = actor && this.d.cfg.tripwires.enabled && ctx.method === 'GET' && status === 200 &&
      type.includes('text/html') && len <= MAX_INJECT_BYTES;

    if (!inject) {
      res.writeHead(status, headers);
      upRes.pipe(res);
      await new Promise<void>(r => { res.on('close', r); upRes.on('error', () => { res.destroy(); r(); }); });
      return;
    }

    const chunks: Buffer[] = [];
    let size = 0;
    for await (const c of upRes) {
      chunks.push(c as Buffer);
      size += (c as Buffer).length;
      if (size > MAX_INJECT_BYTES) break;
    }
    let body = Buffer.concat(chunks);
    if (size > MAX_INJECT_BYTES) {
      // Too big to rewrite safely; pass it through untouched.
      res.writeHead(status, headers);
      res.write(body);
      upRes.pipe(res);
      return;
    }
    const enc = String(upRes.headers['content-encoding'] ?? '').toLowerCase();
    try {
      if (enc === 'gzip' || enc === 'x-gzip') body = zlib.gunzipSync(body);
      else if (enc === 'br') body = zlib.brotliDecompressSync(body);
      else if (enc === 'deflate') body = zlib.inflateSync(body);
      else if (enc && enc !== 'identity') { res.writeHead(status, headers); res.end(body); return; }
    } catch {
      res.writeHead(status, headers); res.end(Buffer.concat(chunks)); return;
    }
    const out = Buffer.from(this.tripwires.injectHtml(body.toString('utf8'), ctx), 'utf8');
    delete headers['content-encoding'];
    delete headers['etag'];
    headers['content-length'] = out.length;
    res.writeHead(status, headers);
    res.end(out);
  }

  private fetchUpstreamText(path: string, ctx: ReqCtx): Promise<string | null> {
    return new Promise(resolve => {
      const lib = this.upstream.protocol === 'https:' ? https : http;
      const r = lib.request({
        protocol: this.upstream.protocol, hostname: this.upstream.hostname, port: this.upstream.port || undefined,
        method: 'GET', path, agent: this.agent, timeout: 5000,
        headers: { host: this.d.cfg.preserveHost ? String(ctx.headers.host ?? this.upstream.host) : this.upstream.host, 'accept-encoding': 'identity' },
      }, up => {
        if (up.statusCode !== 200 || !String(up.headers['content-type'] ?? '').includes('text/plain')) { up.resume(); return resolve(null); }
        const cs: Buffer[] = [];
        up.on('data', c => cs.push(c));
        up.on('end', () => resolve(Buffer.concat(cs).toString('utf8').slice(0, 100_000)));
      });
      r.on('error', () => resolve(null));
      r.on('timeout', () => { r.destroy(); resolve(null); });
      r.end();
    });
  }

  /** WebSocket / upgrade passthrough (after the block check). */
  upgradeHandler = (req: IncomingMessage, socket: Duplex, head: Buffer): void => {
    const ctx = this.buildCtx(req, Buffer.alloc(0));
    if (!this.d.engine.isAllowlisted(ctx.ip) && this.d.engine.blockFor(ctx)) { socket.destroy(); return; }
    const port = Number(this.upstream.port || (this.upstream.protocol === 'https:' ? 443 : 80));
    const upstream = this.upstream.protocol === 'https:'
      ? tls.connect({ host: this.upstream.hostname, port, servername: this.upstream.hostname })
      : net.connect({ host: this.upstream.hostname, port });
    upstream.on('connect', () => {
      const lines = [`${req.method} ${req.url} HTTP/1.1`];
      for (let i = 0; i < req.rawHeaders.length; i += 2) lines.push(`${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}`);
      upstream.write(lines.join('\r\n') + '\r\n\r\n');
      if (head.length) upstream.write(head);
      socket.pipe(upstream).pipe(socket);
    });
    upstream.on('error', () => socket.destroy());
    socket.on('error', () => upstream.destroy());
  };
}

/** Buffer the body up to `limit` for inspection; past that, hand back the stream for the remainder. */
function readBody(req: IncomingMessage, limit: number): Promise<{ buf: Buffer; rest: IncomingMessage | null }> {
  const method = (req.method ?? 'GET').toUpperCase();
  const declared = Number(req.headers['content-length'] ?? 0);
  if ((method === 'GET' || method === 'HEAD') && !declared && !req.headers['transfer-encoding']) {
    return Promise.resolve({ buf: Buffer.alloc(0), rest: null });
  }
  if (declared > limit) return Promise.resolve({ buf: Buffer.alloc(0), rest: req });
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    const onData = (c: Buffer) => {
      chunks.push(c);
      size += c.length;
      if (size > limit) {
        req.pause();
        req.off('data', onData);
        req.off('end', onEnd);
        resolve({ buf: Buffer.concat(chunks), rest: req });
      }
    };
    const onEnd = () => resolve({ buf: Buffer.concat(chunks), rest: null });
    req.on('data', onData);
    req.on('end', onEnd);
    req.on('error', reject);
  });
}
