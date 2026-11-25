import { randomBytes } from 'node:crypto';
import { EventEmitter } from 'node:events';
import type { Engine } from '../engine.js';
import type { Honeytokens } from '../honeytokens.js';
import { MITRE } from '../integrations/outputs.js';
import { SEVERITY_RANK } from '../types.js';
import type { Actor, ActorClass, EasyPotEvent, Outcome, ReqCtx, Severity } from '../types.js';

const RUN_ID = /^[A-Za-z0-9_-]{12}$/;
const MAX_RUNS = 2000;
const MAX_REQUESTS_KEPT = 300;
const MAX_EVENTS_KEPT = 200;
const CLASS_RANK: Record<ActorClass, number> = { unknown: 0, human: 1, crawler: 2, bot: 3, scanner: 4, llm_agent: 5 };
const OUTCOMES: Outcome[] = ['forwarded', 'decoy', 'tripwire', 'labyrinth', 'bait', 'blocked'];

interface RunRequest { n: number; ts: number; method: string; path: string; ip: string; outcome: Outcome }
interface RunEvent { n: number; ts: number; signal: string; severity: Severity; method: string; path: string; ip: string; action: string; note: string }

export interface Run {
  id: string;
  created: number;
  expires: number;
  ownerIp: string;
  simulated: boolean;
  simulating: boolean;
  ips: Set<string>;
  actors: Set<string>;
  total: number;
  outcomes: Record<Outcome, number>;
  requests: RunRequest[];
  events: RunEvent[];
  firstTs: number | null;
  detected: { ts: number; n: number; signal: string } | null;
  blocked: { ts: number; n: number; reason: string } | null;
  forwardedBeforeDetect: number;
  forwardedAfterDetect: number;
  selfReport: { client: string; task: string } | null;
  identitySwitches: number;
  decoys: Map<string, number>;
  techniques: Map<string, { id: string; tactic: string; signals: Set<string> }>;
  cls: ActorClass;
  peakScore: number;
  secrets: number;
  replays: number;
}

/**
 * Tracks playground runs: which visitors belong to which run, and what EasyPot did to them.
 * A run is claimed by the first request carrying ?run=<id>; from then on the visitor's IP and
 * fingerprint belong to the run, and EasyPot's own attribution (tripwire owner, honeytoken owner)
 * pulls in identities the agent switches to.
 */
export class Runs extends EventEmitter {
  private runs = new Map<string, Run>();
  private byActor = new Map<string, string>();
  private byIp = new Map<string, string>();
  private created = new Map<string, number[]>();
  private pending = new Map<string, NodeJS.Timeout>();

  constructor(private engine: Engine, private tokens: Honeytokens, private opts: { runMinutes: number; maxRunsPerHourPerIp: number }) {
    super();
    this.setMaxListeners(0);
    engine.on('arrive', (ctx: ReqCtx, a: Actor) => this.onArrive(ctx, a));
    engine.on('outcome', (ctx: ReqCtx, a: Actor, o: Outcome) => this.onOutcome(ctx, a, o));
    engine.on('event', (e: EasyPotEvent) => this.onEvent(e));
    setInterval(() => this.sweep(), 60_000).unref();
  }

  create(ownerIp: string): Run {
    const now = Date.now();
    const recent = (this.created.get(ownerIp) ?? []).filter(t => now - t < 3_600_000);
    if (recent.length >= this.opts.maxRunsPerHourPerIp) throw new RunLimitError('Too many runs from this address. Try again in an hour.');
    if (this.runs.size >= MAX_RUNS) this.sweep(true);
    if (this.runs.size >= MAX_RUNS) throw new RunLimitError('The playground is busy. Try again in a few minutes.');
    recent.push(now);
    this.created.set(ownerIp, recent);
    const id = randomBytes(9).toString('base64url');
    const run: Run = {
      id, created: now, expires: now + this.opts.runMinutes * 60_000, ownerIp, simulated: false, simulating: false,
      ips: new Set(), actors: new Set(), total: 0, outcomes: Object.fromEntries(OUTCOMES.map(o => [o, 0])) as Record<Outcome, number>,
      requests: [], events: [], firstTs: null, detected: null, blocked: null, forwardedBeforeDetect: 0, forwardedAfterDetect: 0,
      selfReport: null, identitySwitches: 0, decoys: new Map(), techniques: new Map(), cls: 'unknown', peakScore: 0, secrets: 0, replays: 0,
    };
    this.runs.set(id, run);
    return run;
  }

  get(id: string): Run | undefined {
    if (!RUN_ID.test(id)) return undefined;
    return this.runs.get(id);
  }

  isOpen(run: Run): boolean { return Date.now() < run.expires; }

  // ---------------- attribution ----------------

  private live(id: string | undefined): Run | undefined {
    const run = id ? this.runs.get(id) : undefined;
    return run && this.isOpen(run) ? run : undefined;
  }

  private bind(run: Run, ip: string, actorId: string): void {
    run.ips.add(ip);
    run.actors.add(actorId);
    this.byIp.set(ip, run.id);
    this.byActor.set(actorId, run.id);
  }

  private runFor(ip: string, actorId: string): Run | undefined {
    const byActor = this.live(this.byActor.get(actorId));
    if (byActor) return byActor;
    const byIp = this.live(this.byIp.get(ip));
    if (byIp) this.bind(byIp, ip, actorId); // same address, new fingerprint (e.g. the agent changed its user agent)
    return byIp;
  }

  private onArrive(ctx: ReqCtx, a: Actor): void {
    const claim = ctx.query.get('run');
    if (!claim || !RUN_ID.test(claim)) return;
    const run = this.live(claim);
    if (!run || run.actors.has(a.id)) return;
    // A new run starts clean, even if this address was blocked by an earlier run.
    this.engine.resetVisitor(a, ctx.ip);
    this.bind(run, ctx.ip, a.id);
  }

  private onOutcome(ctx: ReqCtx, a: Actor, outcome: Outcome): void {
    const run = this.runFor(ctx.ip, a.id);
    if (!run) return;
    run.total++;
    run.outcomes[outcome]++;
    run.firstTs ??= ctx.ts;
    if (outcome === 'forwarded') run.detected ? run.forwardedAfterDetect++ : run.forwardedBeforeDetect++;
    run.requests.push({ n: run.total, ts: ctx.ts, method: ctx.method, path: ctx.url.slice(0, 300), ip: ctx.ip, outcome });
    if (run.requests.length > MAX_REQUESTS_KEPT) run.requests.shift();
    run.peakScore = Math.max(run.peakScore, Math.round(a.score));
    if (CLASS_RANK[a.cls] > CLASS_RANK[run.cls]) run.cls = a.cls;
    run.secrets = Math.max(run.secrets, ...[...run.actors].map(id => this.tokens.issuedCount(id)));
    this.changed(run);
  }

  private onEvent(e: EasyPotEvent): void {
    const d = e.detail ?? {};
    // EasyPot's own attribution: the agent may come back from a new identity, but the tripwire
    // or the stolen key it uses was issued to a visitor we already know.
    const linkedFrom = e.signal === 'agent_instruction_followed' ? d.tripwireShownTo
      : e.signal === 'honeytoken_replay' ? d.issuedTo : undefined;
    let run = this.runFor(e.ip, e.actorId);
    if (!run && typeof linkedFrom === 'string') {
      run = this.live(this.byActor.get(linkedFrom));
      if (run) this.bind(run, e.ip, e.actorId);
    }
    if (!run) return;
    if (typeof linkedFrom === 'string' && linkedFrom !== e.actorId && run.actors.has(linkedFrom)) run.identitySwitches++;
    if (e.signal === 'blocked_request') return;

    const n = run.total + 1; // events fire before the request's outcome is counted
    if (!run.detected && SEVERITY_RANK[e.severity] >= SEVERITY_RANK.high) run.detected = { ts: e.ts, n, signal: e.signal };
    if (!run.blocked && e.action === 'block') {
      run.blocked = { ts: e.ts, n, reason: e.signal };
      run.detected ??= { ts: e.ts, n, signal: e.signal };
    }
    if (e.signal === 'agent_instruction_followed') {
      run.selfReport = { client: String(d.selfReportedClient ?? '').slice(0, 200), task: String(d.selfReportedTask ?? '').slice(0, 500) };
    }
    if (e.signal === 'honeytoken_replay') run.replays++;
    if (typeof d.decoyName === 'string') run.decoys.set(d.decoyName, (run.decoys.get(d.decoyName) ?? 0) + 1);
    const m = MITRE[e.signal];
    if (m) {
      const t = run.techniques.get(m.id) ?? { id: m.id, tactic: m.tactic, signals: new Set<string>() };
      t.signals.add(e.signal);
      run.techniques.set(m.id, t);
    }
    run.events.push({ n, ts: e.ts, signal: e.signal, severity: e.severity, method: e.method, path: e.path.slice(0, 300), ip: e.ip, action: e.action, note: note(e) });
    if (run.events.length > MAX_EVENTS_KEPT) run.events.shift();
    this.changed(run);
  }

  /** Coalesce bursts of activity into one update per run every 250 ms. */
  private changed(run: Run): void {
    if (this.pending.has(run.id)) return;
    this.pending.set(run.id, setTimeout(() => { this.pending.delete(run.id); this.emit(`change:${run.id}`); }, 250));
  }

  private sweep(force = false): void {
    const now = Date.now();
    const grace = force ? 0 : 10 * 60_000;
    for (const [id, run] of this.runs) {
      if (now < run.expires + grace) continue;
      this.runs.delete(id);
      for (const ip of run.ips) if (this.byIp.get(ip) === id) this.byIp.delete(ip);
      for (const a of run.actors) if (this.byActor.get(a) === id) this.byActor.delete(a);
    }
    for (const [ip, ts] of this.created) if (ts.every(t => now - t > 3_600_000)) this.created.delete(ip);
  }

  // ---------------- report ----------------

  report(run: Run) {
    const now = Date.now();
    const status = !this.isOpen(run) ? 'expired' : run.blocked ? 'blocked' : run.total ? 'running' : 'waiting';
    const kept = run.total - run.outcomes.forwarded;
    return {
      id: run.id,
      status,
      created: run.created,
      expires: run.expires,
      now,
      simulated: run.simulated,
      simulating: run.simulating,
      metrics: {
        requests: run.total,
        timeToDetectMs: run.detected && run.firstTs !== null ? run.detected.ts - run.firstTs : null,
        requestsToDetect: run.detected?.n ?? null,
        detectedBy: run.detected?.signal ?? null,
        timeToBlockMs: run.blocked && run.firstTs !== null ? run.blocked.ts - run.firstTs : null,
        requestsToBlock: run.blocked?.n ?? null,
        blockedFor: run.blocked?.reason ?? null,
        keptFromAppPct: run.total ? Math.round((kept / run.total) * 100) : null,
        handledByEasyPot: kept,
        reachedAppBeforeDetect: run.forwardedBeforeDetect,
        reachedAppAfterDetect: run.forwardedAfterDetect,
        decoysTriggered: [...run.decoys.values()].reduce((s, n) => s + n, 0),
        secretsHanded: run.secrets,
        replaysCaught: run.replays,
        identitySwitches: run.identitySwitches,
        identities: run.actors.size,
        addresses: run.ips.size,
      },
      outcomes: run.outcomes,
      agent: { selfReport: run.selfReport, cls: run.cls, peakScore: run.peakScore },
      decoys: [...run.decoys].map(([name, hits]) => ({ name, hits })).sort((x, y) => y.hits - x.hits),
      techniques: [...run.techniques.values()].map(t => ({ id: t.id, tactic: t.tactic, signals: [...t.signals] })),
      events: run.events.slice(-80).reverse(),
      requests: run.requests.slice(-60).reverse(),
    };
  }
}

export class RunLimitError extends Error {}

function note(e: EasyPotEvent): string {
  const d = e.detail ?? {};
  if (e.signal === 'agent_instruction_followed') return d.selfReportedClient ? `says it is “${d.selfReportedClient}”` : 'followed the planted instruction';
  if (e.signal === 'honeytoken_replay') return `${d.kind} issued in ${String(d.plantedIn ?? '').split(',')[0]}${d.sameVisitor ? '' : ', replayed from a new identity'}`;
  if (e.signal === 'attack_payload') return `${d.category ?? 'payload'}`;
  if (e.signal === 'decoy_login_attempt') return `username “${d.username}”`;
  if (typeof d.decoyName === 'string') return d.decoyName;
  if (d.tool || d.library || d.engine) return String(d.tool || d.library || d.engine);
  return '';
}
