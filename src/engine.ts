import { EventEmitter } from 'node:events';
import type { Config } from './config.js';
import type { Store } from './store.js';
import type { Action, Actor, ActorClass, Block, EasyPotEvent, ReqCtx, Signal } from './types.js';
import { ipInCidr, uid } from './util.js';

const CLASS_RANK: Record<ActorClass, number> = { unknown: 0, human: 1, crawler: 2, bot: 3, scanner: 4, llm_agent: 5 };
const COOLDOWN_MS = 60_000;

export interface Verdict { actor: Actor; action: Action; events: EasyPotEvent[] }

/**
 * Turns signals into a decaying risk score per visitor, decides what to do,
 * and emits events for every integration to consume.
 */
export class Engine extends EventEmitter {
  private blocks = new Map<string, Block>();
  private cooldowns = new Map<string, number>();
  private lastBlockedLog = new Map<string, number>();

  constructor(private cfg: Config, private store: Store) {
    super();
    this.setMaxListeners(100);
    for (const b of store.activeBlocks()) this.blocks.set(b.target, b);
    setInterval(() => {
      const now = Date.now();
      for (const [k, t] of this.cooldowns) if (now - t > COOLDOWN_MS) this.cooldowns.delete(k);
      for (const [k, b] of this.blocks) if (b.expires && b.expires < now) this.blocks.delete(k);
    }, 30_000).unref();
  }

  isAllowlisted(ip: string): boolean {
    return this.cfg.allowlist.ips.includes(ip) || this.cfg.allowlist.cidrs.some(c => ipInCidr(ip, c));
  }

  actor(ctx: ReqCtx): Actor {
    let a = this.store.getActor(ctx.actorId);
    if (!a) {
      a = { id: ctx.actorId, ip: ctx.ip, ua: ctx.ua, firstSeen: ctx.ts, lastSeen: ctx.ts, score: 0, scoreTs: ctx.ts,
        cls: 'unknown', requests: 0, signals: 0, selfReport: null, labyrinthDepth: 0 };
    }
    a.ip = ctx.ip;
    a.lastSeen = ctx.ts;
    a.requests++;
    this.decay(a, ctx.ts);
    this.store.touch(a);
    return a;
  }

  private decay(a: Actor, now: number): void {
    const dt = now - a.scoreTs;
    if (dt > 0) {
      a.score *= Math.pow(0.5, dt / (this.cfg.halfLifeMinutes * 60_000));
      if (a.score < 0.5) a.score = 0;
      a.scoreTs = now;
    }
  }

  blockFor(ctx: Pick<ReqCtx, 'ip' | 'actorId'>): Block | undefined {
    const now = Date.now();
    for (const key of [ctx.ip, ctx.actorId]) {
      const b = this.blocks.get(key);
      if (b && (!b.expires || b.expires > now)) return b;
    }
    return undefined;
  }

  /** Throttle "blocked request" events so a blocked flood doesn't flood the SIEM too. */
  noteBlockedRequest(ctx: ReqCtx, a: Actor, b: Block): void {
    const last = this.lastBlockedLog.get(a.id) ?? 0;
    if (ctx.ts - last < 60_000) return;
    this.lastBlockedLog.set(a.id, ctx.ts);
    this.emitEvent(this.makeEvent(ctx, a, { type: 'blocked_request', weight: 0, severity: 'info', detail: { reason: b.reason } }, 'block'));
  }

  /** Apply signals, update score/class, decide an action. */
  evaluate(ctx: ReqCtx, a: Actor, signals: Signal[]): Verdict {
    const events: EasyPotEvent[] = [];
    let conclusive: Signal | undefined;

    for (const s of signals) {
      const key = `${a.id}|${s.cooldownKey ?? s.type}`;
      if (s.cooldownKey && this.cooldowns.has(key)) continue;
      if (s.cooldownKey) this.cooldowns.set(key, ctx.ts);

      a.score = Math.min(200, a.score + s.weight);
      a.signals++;
      if (s.classHint && CLASS_RANK[s.classHint] > CLASS_RANK[a.cls]) a.cls = s.classHint;
      if (s.conclusive) conclusive ??= s;
      events.push(this.makeEvent(ctx, a, s, 'allow'));
    }
    if (a.cls === 'unknown' && a.requests >= 3 && a.score === 0 && ctx.headers['sec-fetch-mode']) a.cls = 'human';

    let action = this.actionFor(a.score);
    if (conclusive && this.cfg.autoBlock) action = 'block';
    if (action === 'block' && !this.blockFor(ctx)) {
      const reason = conclusive ? conclusive.type : `risk score ${Math.round(a.score)}`;
      this.addBlock({ target: ctx.ip, kind: 'ip', reason, created: ctx.ts, expires: ctx.ts + this.cfg.blockTtlMinutes * 60_000, source: 'auto' });
      this.addBlock({ target: a.id, kind: 'actor', reason, created: ctx.ts, expires: ctx.ts + this.cfg.blockTtlMinutes * 60_000, source: 'auto' });
    }

    for (const e of events) {
      e.action = action;
      e.score = Math.round(a.score);
      e.actorClass = a.cls;
      this.emitEvent(e);
    }
    this.store.touch(a);
    return { actor: a, action, events };
  }

  actionFor(score: number): Action {
    const t = this.cfg.thresholds;
    if (score >= t.block) return 'block';
    if (score >= t.labyrinth) return 'labyrinth';
    if (score >= t.tarpit) return 'tarpit';
    return 'allow';
  }

  addBlock(b: Block): void {
    this.blocks.set(b.target, b);
    this.store.upsertBlock(b);
    this.emit('block', b);
  }

  removeBlock(target: string): boolean {
    const had = this.blocks.delete(target);
    const dbHad = this.store.deleteBlock(target);
    if (had || dbHad) this.emit('unblock', target);
    return had || dbHad;
  }

  listBlocks(): Block[] {
    const now = Date.now();
    return [...this.blocks.values()].filter(b => !b.expires || b.expires > now).sort((x, y) => y.created - x.created);
  }

  private makeEvent(ctx: ReqCtx, a: Actor, s: Signal, action: Action): EasyPotEvent {
    return {
      id: uid(), ts: ctx.ts, actorId: a.id, ip: ctx.ip, method: ctx.method, path: ctx.url, ua: ctx.ua,
      signal: s.type, severity: s.severity, weight: s.weight, score: Math.round(a.score), action,
      actorClass: a.cls, detail: s.detail ?? {},
    };
  }

  private emitEvent(e: EasyPotEvent): void {
    this.store.insertEvent(e);
    this.emit('event', e);
  }
}
