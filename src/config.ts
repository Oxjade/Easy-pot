import { readFileSync, existsSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import type { Severity } from './types.js';

export interface SyslogConfig {
  enabled: boolean;
  host: string;
  port: number;
  protocol: 'udp' | 'tcp';
  format: 'json' | 'cef';
  minSeverity: Severity;
}

export interface WebhookConfig {
  url: string;
  type: 'generic' | 'slack';
  minSeverity: Severity;
}

export interface Config {
  listen: { host: string; port: number };
  upstream: string;
  preserveHost: boolean;
  /** Trust X-Forwarded-For / CF-Connecting-IP from the hop in front of EasyPot. */
  trustProxy: boolean;
  siteName: string;
  /** Stacks to tailor decoys for: generic, wordpress, laravel, nextjs, spring, php, node. */
  stack: string[];
  secret: string;
  dataDir: string;
  admin: { host: string; port: number; token: string; feedToken: string };
  decoys: { enabled: boolean; exclude: string[]; probeUpstream: boolean; cvePack: string | null };
  tripwires: { enabled: boolean; canaryPrefix: string; hiddenLinkPath: string; labyrinthPrefix: string };
  thresholds: { tarpit: number; labyrinth: number; block: number };
  autoBlock: boolean;
  halfLifeMinutes: number;
  blockTtlMinutes: number;
  blockMode: '403' | '404' | 'drop';
  tarpitMs: { min: number; max: number };
  maxBodyBytes: number;
  retentionDays: number;
  allowlist: { ips: string[]; cidrs: string[] };
  integrations: {
    syslog: SyslogConfig;
    fileLog: { enabled: boolean; path: string; minSeverity: Severity };
    webhooks: WebhookConfig[];
  };
}

const defaults: Config = {
  listen: { host: '0.0.0.0', port: 8080 },
  upstream: 'http://127.0.0.1:3000',
  preserveHost: true,
  trustProxy: false,
  siteName: 'Acme',
  stack: ['generic'],
  secret: '',
  dataDir: './data',
  admin: { host: '127.0.0.1', port: 8081, token: '', feedToken: '' },
  decoys: { enabled: true, exclude: [], probeUpstream: true, cvePack: null },
  tripwires: {
    enabled: true,
    canaryPrefix: '/.well-known/agent-registration',
    hiddenLinkPath: '/internal/ops/export',
    labyrinthPrefix: '/docs/archive',
  },
  thresholds: { tarpit: 30, labyrinth: 55, block: 80 },
  autoBlock: true,
  halfLifeMinutes: 30,
  blockTtlMinutes: 1440,
  blockMode: '403',
  tarpitMs: { min: 1500, max: 8000 },
  maxBodyBytes: 1024 * 1024,
  retentionDays: 30,
  allowlist: { ips: [], cidrs: [] },
  integrations: {
    syslog: { enabled: false, host: '127.0.0.1', port: 514, protocol: 'udp', format: 'json', minSeverity: 'low' },
    fileLog: { enabled: true, path: './data/events.jsonl', minSeverity: 'low' },
    webhooks: [],
  },
};

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function merge<T>(base: T, over: unknown): T {
  if (!isObj(over)) return base;
  const out: Record<string, unknown> = { ...(base as Record<string, unknown>) };
  for (const [k, v] of Object.entries(over)) {
    out[k] = isObj(v) && isObj(out[k]) ? merge(out[k], v) : v;
  }
  return out as T;
}

export function loadConfig(path = process.env.EASYPOT_CONFIG ?? './easypot.config.json'): Config {
  let fileCfg: unknown = {};
  if (existsSync(path)) fileCfg = JSON.parse(readFileSync(path, 'utf8'));
  const cfg = merge(defaults, fileCfg);

  const env = process.env;
  if (env.EASYPOT_UPSTREAM) cfg.upstream = env.EASYPOT_UPSTREAM;
  if (env.EASYPOT_PORT) cfg.listen.port = Number(env.EASYPOT_PORT);
  if (env.EASYPOT_ADMIN_PORT) cfg.admin.port = Number(env.EASYPOT_ADMIN_PORT);
  if (env.EASYPOT_ADMIN_HOST) cfg.admin.host = env.EASYPOT_ADMIN_HOST;
  if (env.EASYPOT_ADMIN_TOKEN) cfg.admin.token = env.EASYPOT_ADMIN_TOKEN;
  if (env.EASYPOT_FEED_TOKEN) cfg.admin.feedToken = env.EASYPOT_FEED_TOKEN;
  if (env.EASYPOT_SECRET) cfg.secret = env.EASYPOT_SECRET;
  if (env.EASYPOT_DATA_DIR) cfg.dataDir = env.EASYPOT_DATA_DIR;
  if (env.EASYPOT_TRUST_PROXY) cfg.trustProxy = env.EASYPOT_TRUST_PROXY === 'true';
  if (env.EASYPOT_SITE_NAME) cfg.siteName = env.EASYPOT_SITE_NAME;

  const generated: string[] = [];
  if (!cfg.secret) { cfg.secret = randomBytes(32).toString('hex'); generated.push('secret'); }
  if (!cfg.admin.token) { cfg.admin.token = randomBytes(18).toString('base64url'); generated.push('admin.token'); }
  if (!cfg.admin.feedToken) { cfg.admin.feedToken = randomBytes(18).toString('base64url'); generated.push('admin.feedToken'); }
  if (generated.length) {
    console.warn(`[easypot] generated ephemeral ${generated.join(', ')} — set them in config to keep them across restarts`);
    console.warn(`[easypot] admin token: ${cfg.admin.token}`);
  }
  new URL(cfg.upstream); // throws early on a bad upstream
  return cfg;
}
