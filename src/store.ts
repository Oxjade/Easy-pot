import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import type { Actor, Block, EasyPotEvent } from './types.js';

type Row = Record<string, unknown>;

/**
 * Persistence on Node's built-in SQLite. Actors live in memory and are flushed
 * periodically; events and blocks are written through.
 */
export class Store {
  readonly db: DatabaseSync;
  readonly actors = new Map<string, Actor>();
  private dirty = new Set<string>();
  private flushTimer: NodeJS.Timeout;

  constructor(dataDir: string) {
    mkdirSync(dataDir, { recursive: true });
    this.db = new DatabaseSync(join(dataDir, 'easypot.db'));
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = NORMAL;
      CREATE TABLE IF NOT EXISTS actors (
        id TEXT PRIMARY KEY, ip TEXT, ua TEXT, first_seen INTEGER, last_seen INTEGER,
        score REAL, score_ts INTEGER, cls TEXT, requests INTEGER, signals INTEGER,
        self_report TEXT, labyrinth_depth INTEGER
      );
      CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY, ts INTEGER, actor_id TEXT, ip TEXT, method TEXT, path TEXT, ua TEXT,
        signal TEXT, severity TEXT, weight REAL, score REAL, action TEXT, actor_class TEXT, detail TEXT
      );
      CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
      CREATE INDEX IF NOT EXISTS events_actor ON events(actor_id, ts);
      CREATE INDEX IF NOT EXISTS events_signal ON events(signal, ts);
      CREATE TABLE IF NOT EXISTS blocks (
        target TEXT PRIMARY KEY, kind TEXT, reason TEXT, created INTEGER, expires INTEGER, source TEXT
      );
      CREATE TABLE IF NOT EXISTS honeytokens (
        token TEXT PRIMARY KEY, actor_id TEXT, kind TEXT, issued INTEGER, decoy_path TEXT
      );
      CREATE INDEX IF NOT EXISTS honeytokens_actor ON honeytokens(actor_id);
      CREATE TABLE IF NOT EXISTS counters (day TEXT PRIMARY KEY, requests INTEGER);
    `);
    for (const r of this.db.prepare('SELECT * FROM actors WHERE last_seen > ?').all(Date.now() - 86_400_000) as Row[]) {
      this.actors.set(String(r.id), rowToActor(r));
    }
    this.flushTimer = setInterval(() => this.flush(), 5000);
    this.flushTimer.unref();
    // Visitors live in the database; keep only recently active ones in memory, or every
    // visitor ever seen (or every address an attacker rotates through) would stay there forever.
    setInterval(() => this.evictIdle(), 60_000).unref();
  }

  /** Drop visitors idle for 30 minutes from memory once they're safely written to the database. */
  evictIdle(idleMs = 30 * 60_000): void {
    this.flush();
    const cutoff = Date.now() - idleMs;
    for (const [id, a] of this.actors) if (a.lastSeen < cutoff && !this.dirty.has(id)) this.actors.delete(id);
  }

  getActor(id: string): Actor | undefined {
    const mem = this.actors.get(id);
    if (mem) return mem;
    const r = this.db.prepare('SELECT * FROM actors WHERE id = ?').get(id) as Row | undefined;
    if (!r) return undefined;
    const a = rowToActor(r);
    this.actors.set(id, a);
    return a;
  }

  touch(a: Actor): void {
    this.actors.set(a.id, a);
    this.dirty.add(a.id);
  }

  flush(): void {
    if (!this.dirty.size) return;
    const stmt = this.db.prepare(`INSERT INTO actors VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(id) DO UPDATE SET ip=excluded.ip, ua=excluded.ua, last_seen=excluded.last_seen,
      score=excluded.score, score_ts=excluded.score_ts, cls=excluded.cls, requests=excluded.requests,
      signals=excluded.signals, self_report=excluded.self_report, labyrinth_depth=excluded.labyrinth_depth`);
    this.db.exec('BEGIN');
    try {
      for (const id of this.dirty) {
        const a = this.actors.get(id);
        if (!a) continue;
        stmt.run(a.id, a.ip, a.ua, a.firstSeen, a.lastSeen, a.score, a.scoreTs, a.cls, a.requests,
          a.signals, a.selfReport, a.labyrinthDepth);
      }
      this.db.exec('COMMIT');
    } catch (e) {
      this.db.exec('ROLLBACK');
      throw e;
    }
    this.dirty.clear();
    // Keep the in-memory working set bounded.
    if (this.actors.size > 50_000) {
      const cutoff = Date.now() - 3_600_000;
      for (const [id, a] of this.actors) if (a.lastSeen < cutoff) this.actors.delete(id);
    }
  }

  countRequest(): void {
    const day = new Date().toISOString().slice(0, 10);
    this.db.prepare('INSERT INTO counters VALUES (?,1) ON CONFLICT(day) DO UPDATE SET requests = requests + 1').run(day);
  }

  insertEvent(e: EasyPotEvent): void {
    this.db.prepare('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(
      e.id, e.ts, e.actorId, e.ip, e.method, e.path.slice(0, 2048), e.ua.slice(0, 512), e.signal, e.severity,
      e.weight, e.score, e.action, e.actorClass, JSON.stringify(e.detail));
  }

  events(opts: { limit?: number; actorId?: string; signal?: string; since?: number; minSeverity?: string[] } = {}): EasyPotEvent[] {
    const where: string[] = [];
    const args: (string | number)[] = [];
    if (opts.actorId) { where.push('actor_id = ?'); args.push(opts.actorId); }
    if (opts.signal) { where.push('signal = ?'); args.push(opts.signal); }
    if (opts.since) { where.push('ts >= ?'); args.push(opts.since); }
    if (opts.minSeverity?.length) { where.push(`severity IN (${opts.minSeverity.map(() => '?').join(',')})`); args.push(...opts.minSeverity); }
    const sql = `SELECT * FROM events ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY ts DESC LIMIT ?`;
    args.push(Math.min(opts.limit ?? 100, 1000));
    return (this.db.prepare(sql).all(...args) as Row[]).map(rowToEvent);
  }

  upsertBlock(b: Block): void {
    this.db.prepare(`INSERT INTO blocks VALUES (?,?,?,?,?,?) ON CONFLICT(target) DO UPDATE SET
      reason=excluded.reason, expires=excluded.expires, source=excluded.source`)
      .run(b.target, b.kind, b.reason, b.created, b.expires, b.source);
  }

  deleteBlock(target: string): boolean {
    return Number(this.db.prepare('DELETE FROM blocks WHERE target = ?').run(target).changes) > 0;
  }

  activeBlocks(): Block[] {
    return (this.db.prepare('SELECT * FROM blocks WHERE expires IS NULL OR expires > ? ORDER BY created DESC').all(Date.now()) as Row[])
      .map(r => ({
        target: String(r.target), kind: r.kind as Block['kind'], reason: String(r.reason),
        created: Number(r.created), expires: r.expires == null ? null : Number(r.expires), source: r.source as Block['source'],
      }));
  }

  insertToken(token: string, actorId: string, kind: string, decoyPath: string): void {
    this.db.prepare('INSERT OR IGNORE INTO honeytokens VALUES (?,?,?,?,?)').run(token, actorId, kind, Date.now(), decoyPath);
  }

  allTokens(): { token: string; actorId: string; kind: string; issued: number; decoyPath: string }[] {
    return (this.db.prepare('SELECT * FROM honeytokens').all() as Row[]).map(r => ({
      token: String(r.token), actorId: String(r.actor_id), kind: String(r.kind), issued: Number(r.issued), decoyPath: String(r.decoy_path),
    }));
  }

  tokensFor(actorId: string) {
    return this.db.prepare('SELECT kind, issued, decoy_path FROM honeytokens WHERE actor_id = ?').all(actorId) as Row[];
  }

  prune(retentionDays: number): void {
    const cutoff = Date.now() - retentionDays * 86_400_000;
    this.db.prepare('DELETE FROM events WHERE ts < ?').run(cutoff);
    this.db.prepare('DELETE FROM blocks WHERE expires IS NOT NULL AND expires < ?').run(Date.now());
    this.db.prepare('DELETE FROM actors WHERE last_seen < ?').run(cutoff);
  }

  close(): void {
    clearInterval(this.flushTimer);
    this.flush();
    this.db.close();
  }
}

function rowToActor(r: Row): Actor {
  return {
    id: String(r.id), ip: String(r.ip), ua: String(r.ua ?? ''), firstSeen: Number(r.first_seen), lastSeen: Number(r.last_seen),
    score: Number(r.score), scoreTs: Number(r.score_ts), cls: r.cls as Actor['cls'], requests: Number(r.requests),
    signals: Number(r.signals), selfReport: r.self_report == null ? null : String(r.self_report),
    labyrinthDepth: Number(r.labyrinth_depth ?? 0),
  };
}

function rowToEvent(r: Row): EasyPotEvent {
  return {
    id: String(r.id), ts: Number(r.ts), actorId: String(r.actor_id), ip: String(r.ip), method: String(r.method),
    path: String(r.path), ua: String(r.ua), signal: String(r.signal), severity: r.severity as EasyPotEvent['severity'],
    weight: Number(r.weight), score: Number(r.score), action: r.action as EasyPotEvent['action'],
    actorClass: r.actor_class as EasyPotEvent['actorClass'], detail: JSON.parse(String(r.detail ?? '{}')),
  };
}
