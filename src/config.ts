import { readFileSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
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
  /**
   * How many proxies in front of EasyPot to trust for the client address: false or 0 for none,
   * true or 1 for one (a load balancer or Cloudflare), 2 for Cloudflare in front of a load balancer.
   */
  trustProxy: boolean | number;
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
  /**
   * Public attack range: visitors point their own AI agents at this instance and watch a live
   * report of what EasyPot caught. Only for a dedicated demo instance — never in front of a real site.
   */
  playground: {
    enabled: boolean;
    host: string;
    port: number;
    /** URL agents are told to attack (the public address of the proxy). Empty = http://localhost:<listen.port>. */
    targetUrl: string;
    /** Serve the built-in fake app as the upstream instead of `upstream`. */
    builtinTarget: boolean;
    /** Landing page files served at / alongside the playground at /try. */
    siteDir: string;
    runMinutes: number;
    maxRunsPerHourPerIp: number;
    maxConcurrentSimulations: number;
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
  // The CVE pack that ships with EasyPot is on by default; set cvePack to null to turn it off.
  decoys: { enabled: true, exclude: [], probeUpstream: true, cvePack: fileURLToPath(new URL('../rules/cve-pack.json', import.meta.url)) },
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
    // An empty path means <dataDir>/events.jsonl, so EASYPOT_DATA_DIR moves the event log too.
    fileLog: { enabled: true, path: '', minSeverity: 'low' },
    webhooks: [],
  },
  playground: {
    enabled: false, host: '0.0.0.0', port: 8082, targetUrl: '', builtinTarget: true,
    siteDir: fileURLToPath(new URL('../site', import.meta.url)),
    runMinutes: 20, maxRunsPerHourPerIp: 20, maxConcurrentSimulations: 3,
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
  if (existsSync(path)) {
    if (statSync(path).isDirectory()) {
      throw new ConfigError(`${path} is a directory, not a config file. Docker creates an empty directory when the file you mount doesn't exist: copy easypot.config.example.json to easypot.config.json first.`);
    }
    try { fileCfg = JSON.parse(readFileSync(path, 'utf8')); }
    catch (e) { throw new ConfigError(`${path} is not valid JSON: ${(e as Error).message}`); }
  }
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
  if (env.EASYPOT_TRUST_PROXY) cfg.trustProxy = /^\d+$/.test(env.EASYPOT_TRUST_PROXY) ? Number(env.EASYPOT_TRUST_PROXY) : env.EASYPOT_TRUST_PROXY === 'true';
  if (env.EASYPOT_SITE_NAME) cfg.siteName = env.EASYPOT_SITE_NAME;
  if (!cfg.integrations.fileLog.path) cfg.integrations.fileLog.path = join(cfg.dataDir, 'events.jsonl');
  if (env.EASYPOT_PLAYGROUND) cfg.playground.enabled = env.EASYPOT_PLAYGROUND === 'true';
  if (env.EASYPOT_PLAYGROUND_PORT) cfg.playground.port = Number(env.EASYPOT_PLAYGROUND_PORT);
  if (env.EASYPOT_PLAYGROUND_TARGET_URL) cfg.playground.targetUrl = env.EASYPOT_PLAYGROUND_TARGET_URL;
  if (!cfg.playground.targetUrl) cfg.playground.targetUrl = `http://localhost:${cfg.listen.port}`;

  // In production, ephemeral secrets would change on every restart: firewalls lose the feed,
  // dashboards are logged out and every honeytoken becomes unrecognisable. Refuse to start instead.
  if (env.NODE_ENV === 'production') {
    const weak = ([['secret', cfg.secret, 'EASYPOT_SECRET'], ['admin.token', cfg.admin.token, 'EASYPOT_ADMIN_TOKEN'], ['admin.feedToken', cfg.admin.feedToken, 'EASYPOT_FEED_TOKEN']] as const)
      .filter(([, v]) => !v || v.length < 16);
    if (weak.length) throw new ConfigError(`production needs ${weak.map(([k, , e]) => `${k} (or ${e})`).join(', ')} set to at least 16 random characters, e.g. \`openssl rand -hex 24\``);
  }

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

/** A problem with the configuration, reported without a stack trace. */
export class ConfigError extends Error {}
