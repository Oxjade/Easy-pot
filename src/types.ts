import type { IncomingHttpHeaders } from 'node:http';

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type Action = 'allow' | 'tarpit' | 'labyrinth' | 'block';
export type ActorClass = 'unknown' | 'human' | 'crawler' | 'bot' | 'scanner' | 'llm_agent';

export const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/** One piece of evidence about a visitor. */
export interface Signal {
  type: string;
  weight: number;
  severity: Severity;
  /** Conclusive signals block immediately when autoBlock is on (no benign path leads here). */
  conclusive?: boolean;
  classHint?: ActorClass;
  /** Signals with the same cooldownKey from the same actor are recorded once per cooldown window. */
  cooldownKey?: string;
  detail?: Record<string, unknown>;
}

export interface ReqCtx {
  id: string;
  ts: number;
  ip: string;
  method: string;
  url: string;
  path: string;
  query: URLSearchParams;
  headers: IncomingHttpHeaders;
  ua: string;
  body: Buffer;
  actorId: string;
  /** Attribution signature embedded in this actor's tripwires. */
  sig: string;
  acceptsHtml: boolean;
  isAsset: boolean;
}

export interface Actor {
  id: string;
  ip: string;
  ua: string;
  firstSeen: number;
  lastSeen: number;
  score: number;
  scoreTs: number;
  cls: ActorClass;
  requests: number;
  signals: number;
  selfReport: string | null;
  labyrinthDepth: number;
}

export interface EasyPotEvent {
  id: string;
  ts: number;
  actorId: string;
  ip: string;
  method: string;
  path: string;
  ua: string;
  signal: string;
  severity: Severity;
  weight: number;
  score: number;
  action: Action;
  actorClass: ActorClass;
  detail: Record<string, unknown>;
}

export interface Block {
  target: string;
  kind: 'ip' | 'actor';
  reason: string;
  created: number;
  expires: number | null;
  source: 'auto' | 'manual';
}
