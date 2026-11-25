import { readFileSync, existsSync } from 'node:fs';
import type { Honeytokens } from '../honeytokens.js';
import type { ReqCtx, Severity, Signal } from '../types.js';
import * as T from './templates.js';

export interface DecoyResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

export interface DecoyEnv {
  siteName: string;
  tokens: Honeytokens;
  canaryUrl: (ctx: ReqCtx) => string;
  labyrinthUrl: (ctx: ReqCtx) => string;
}

export interface Decoy {
  id: string;
  name: string;
  category: 'secrets' | 'source' | 'database' | 'admin' | 'api' | 'debug' | 'cve';
  stacks: string[];
  /** Exact paths (case-insensitive) — also used for the upstream collision probe. */
  paths?: string[];
  pattern?: RegExp;
  methods?: string[];
  signal: { type: string; weight: number; severity: Severity; conclusive?: boolean };
  handle: (ctx: ReqCtx, env: DecoyEnv) => DecoyResponse;
  enabled?: boolean;
}

const text = (body: string, type = 'text/plain; charset=utf-8', status = 200): DecoyResponse =>
  ({ status, headers: { 'content-type': type }, body });
const json = (obj: unknown, status = 200): DecoyResponse =>
  ({ status, headers: { 'content-type': 'application/json' }, body: JSON.stringify(obj, null, 2) });
const html = (body: string, status = 200): DecoyResponse =>
  ({ status, headers: { 'content-type': 'text/html; charset=utf-8' }, body });

const loginDecoy = (id: string, name: string, stacks: string[], paths: string[], render: (siteName: string, err: boolean) => string): Decoy => ({
  id, name, category: 'admin', stacks, paths,
  signal: { type: 'decoy_admin_panel', weight: 30, severity: 'medium' },
  handle: (ctx, env) => html(render(env.siteName, ctx.method === 'POST'), ctx.method === 'POST' ? 401 : 200),
});

export const BUILTIN_DECOYS: Decoy[] = [
  // ---- leaked secrets ----
  {
    id: 'env', name: 'Exposed .env file', category: 'secrets', stacks: ['generic', 'laravel', 'node', 'nextjs', 'php'],
    paths: ['/.env', '/.env.production', '/.env.local', '/.env.prod', '/.env.backup', '/.env.bak', '/api/.env', '/app/.env'],
    signal: { type: 'decoy_secret_file', weight: 45, severity: 'high' },
    handle: (ctx, env) => text(T.envFile(env.siteName, env.tokens.issue(ctx.actorId, ctx.path))),
  },
  {
    id: 'aws-credentials', name: 'AWS credentials file', category: 'secrets', stacks: ['generic'],
    paths: ['/.aws/credentials', '/.aws/config', '/aws.yml', '/.s3cfg'],
    signal: { type: 'decoy_secret_file', weight: 45, severity: 'high' },
    handle: (ctx, env) => text(T.awsCredentials(env.tokens.issue(ctx.actorId, ctx.path))),
  },
  {
    id: 'config-json', name: 'Config file', category: 'secrets', stacks: ['generic', 'node', 'nextjs'],
    paths: ['/config.json', '/appsettings.json', '/appsettings.Production.json', '/config/production.json', '/secrets.json', '/credentials.json'],
    signal: { type: 'decoy_secret_file', weight: 40, severity: 'high' },
    handle: (ctx, env) => json(T.configJson(env.siteName, env.tokens.issue(ctx.actorId, ctx.path))),
  },
  {
    id: 'wp-config', name: 'WordPress config backup', category: 'secrets', stacks: ['wordpress', 'php'],
    paths: ['/wp-config.php.bak', '/wp-config.php.old', '/wp-config.php~', '/wp-config.txt', '/wp-config.php.save'],
    signal: { type: 'decoy_secret_file', weight: 45, severity: 'high' },
    handle: (ctx, env) => text(T.wpConfig(env.tokens.issue(ctx.actorId, ctx.path))),
  },
  {
    id: 'spring-actuator', name: 'Spring Boot actuator env', category: 'debug', stacks: ['spring'],
    paths: ['/actuator/env', '/actuator/configprops', '/actuator/heapdump', '/env'],
    signal: { type: 'decoy_debug_endpoint', weight: 40, severity: 'high' },
    handle: (ctx, env) => json(T.actuatorEnv(env.siteName, env.tokens.issue(ctx.actorId, ctx.path))),
  },
  // ---- source control ----
  {
    id: 'git', name: 'Exposed .git directory', category: 'source', stacks: ['generic'],
    paths: ['/.git/config', '/.git/HEAD', '/.git/index', '/.git/logs/HEAD', '/.gitlab-ci.yml', '/.github/workflows/deploy.yml'],
    signal: { type: 'decoy_source_exposure', weight: 40, severity: 'high' },
    handle: (ctx, env) => {
      const p = ctx.path.toLowerCase();
      if (p.endsWith('/head') && !p.includes('logs')) return text('ref: refs/heads/main\n');
      if (p.endsWith('.yml')) return text(T.ciFile(env.siteName, env.tokens.issue(ctx.actorId, ctx.path)), 'text/yaml');
      if (p.endsWith('/index') || p.includes('logs')) return text(T.gitLog(env.siteName));
      return text(T.gitConfig(env.siteName, env.tokens.issue(ctx.actorId, ctx.path)));
    },
  },
  // ---- database dumps ----
  {
    id: 'sql-dump', name: 'Database backup', category: 'database', stacks: ['generic'],
    paths: ['/backup.sql', '/db.sql', '/dump.sql', '/database.sql', '/backup/db.sql', '/backups/latest.sql', '/data.sql', '/backup.zip', '/backup.tar.gz'],
    signal: { type: 'decoy_database_dump', weight: 45, severity: 'high' },
    handle: (ctx, env) => text(T.sqlDump(env.siteName, env.tokens.issue(ctx.actorId, ctx.path)), 'application/sql'),
  },
  // ---- admin panels ----
  loginDecoy('admin', 'Admin login', ['generic'], ['/admin', '/admin/', '/admin/login', '/administrator', '/administrator/', '/backend', '/cpanel', '/manage', '/console'], T.adminLogin),
  loginDecoy('wordpress', 'WordPress login', ['wordpress', 'generic'], ['/wp-login.php', '/wp-admin', '/wp-admin/'], T.wpLogin),
  loginDecoy('phpmyadmin', 'phpMyAdmin', ['php', 'generic'], ['/phpmyadmin', '/phpmyadmin/', '/pma', '/pma/', '/myadmin', '/dbadmin'], T.pmaLogin),
  // ---- internal APIs ----
  {
    id: 'openapi', name: 'Internal API docs', category: 'api', stacks: ['generic'],
    paths: ['/swagger.json', '/openapi.json', '/api-docs', '/v2/api-docs', '/v3/api-docs', '/api/swagger.json', '/swagger-ui.html', '/api/docs'],
    signal: { type: 'decoy_api_docs', weight: 25, severity: 'medium' },
    handle: (ctx, env) => json(T.openApi(env.siteName, env.canaryUrl(ctx))),
  },
  {
    id: 'internal-api', name: 'Internal admin API', category: 'api', stacks: ['generic'],
    paths: ['/api/internal/users', '/api/v1/admin/export', '/api/v1/keys', '/api/internal/config', '/api/admin/users', '/internal/api/users'],
    signal: { type: 'decoy_internal_api', weight: 45, severity: 'high' },
    handle: (ctx, env) => json(T.internalApi(ctx.path, env.siteName, env.tokens.issue(ctx.actorId, ctx.path))),
  },
  {
    id: 'graphql', name: 'GraphQL introspection', category: 'api', stacks: ['generic', 'node', 'nextjs'],
    paths: ['/graphql/schema', '/api/graphql/schema', '/graphiql'],
    signal: { type: 'decoy_api_docs', weight: 20, severity: 'medium' },
    handle: () => json(T.graphqlSchema()),
  },
  // ---- debug pages ----
  {
    id: 'debug', name: 'Debug / info pages', category: 'debug', stacks: ['generic', 'php'],
    paths: ['/phpinfo.php', '/info.php', '/server-status', '/server-info', '/debug', '/_debug', '/test.php', '/debug/vars', '/__debug__'],
    signal: { type: 'decoy_debug_endpoint', weight: 35, severity: 'medium' },
    handle: (ctx, env) => html(T.phpInfo(env.siteName, env.tokens.issue(ctx.actorId, ctx.path))),
  },
  {
    id: 'docker', name: 'Container / CI secrets', category: 'secrets', stacks: ['generic'],
    paths: ['/docker-compose.yml', '/docker-compose.prod.yml', '/.dockercfg', '/.docker/config.json', '/.npmrc', '/.pypirc'],
    signal: { type: 'decoy_secret_file', weight: 40, severity: 'high' },
    handle: (ctx, env) => text(T.dockerCompose(env.siteName, env.tokens.issue(ctx.actorId, ctx.path)), 'text/yaml'),
  },
];

interface CveRule {
  id: string; name: string; enabled?: boolean;
  match: { method?: string; path?: string; query?: string; body?: string; header?: string };
  response?: { status?: number; contentType?: string; body?: string };
  weight?: number; severity?: Severity;
}

/** CVE decoys are data-driven so new ones can ship the day a CVE drops, without a code release. */
export function loadCvePack(file: string | null): Decoy[] {
  if (!file || !existsSync(file)) return [];
  const rules = JSON.parse(readFileSync(file, 'utf8')) as CveRule[];
  return rules.filter(r => r.enabled !== false).map(r => {
    const re = {
      path: r.match.path ? new RegExp(r.match.path, 'i') : null,
      query: r.match.query ? new RegExp(r.match.query, 'i') : null,
      body: r.match.body ? new RegExp(r.match.body, 'i') : null,
      header: r.match.header ? new RegExp(r.match.header, 'i') : null,
    };
    const decoy: Decoy = {
      id: `cve:${r.id}`, name: `${r.id} — ${r.name}`, category: 'cve', stacks: ['generic'],
      methods: r.match.method ? [r.match.method.toUpperCase()] : undefined,
      pattern: re.path ?? /.*/,
      signal: { type: 'cve_exploit_attempt', weight: r.weight ?? 60, severity: r.severity ?? 'critical' },
      handle: () => text(r.response?.body ?? 'OK', r.response?.contentType ?? 'text/html; charset=utf-8', r.response?.status ?? 200),
    };
    (decoy as Decoy & { extra: (ctx: ReqCtx) => boolean }).extra = (ctx: ReqCtx) => {
      // Match against the raw URL so encoded traversal tricks are seen as the attacker sent them.
      if (re.path && !re.path.test(ctx.url)) return false;
      if (re.query && !re.query.test(ctx.url.split('?')[1] ?? '')) return false;
      if (re.body && !re.body.test(ctx.body.toString('utf8'))) return false;
      if (re.header && !re.header.test(Object.entries(ctx.headers).map(([k, v]) => `${k}: ${v}`).join('\n'))) return false;
      return true;
    };
    return decoy;
  });
}

export class DecoyRouter {
  private exact = new Map<string, Decoy>();
  private patterned: Decoy[] = [];
  readonly all: Decoy[];

  constructor(decoys: Decoy[], stacks: string[], exclude: string[]) {
    const wanted = new Set(stacks.length ? stacks : ['generic']);
    const excluded = new Set(exclude.map(p => p.toLowerCase()));
    this.all = decoys.filter(d => d.category === 'cve' || d.stacks.some(s => wanted.has(s)));
    for (const d of this.all) {
      d.enabled = true;
      for (const p of d.paths ?? []) if (!excluded.has(p.toLowerCase())) this.exact.set(p.toLowerCase(), d);
      if (d.pattern) this.patterned.push(d);
    }
  }

  /** Remove a path that turned out to be real on the upstream. */
  disablePath(path: string): void {
    this.exact.delete(path.toLowerCase());
  }

  probePaths(): string[] {
    return [...this.exact.keys()];
  }

  match(ctx: ReqCtx): Decoy | undefined {
    const d = this.exact.get(ctx.path.toLowerCase().replace(/\/{2,}/g, '/'));
    if (d && (!d.methods || d.methods.includes(ctx.method))) return d;
    for (const p of this.patterned) {
      if (p.methods && !p.methods.includes(ctx.method)) continue;
      const extra = (p as Decoy & { extra?: (c: ReqCtx) => boolean }).extra;
      if (extra ? extra(ctx) : p.pattern!.test(ctx.path)) return p;
    }
    return undefined;
  }

  respond(d: Decoy, ctx: ReqCtx, env: DecoyEnv): { res: DecoyResponse; signals: Signal[] } {
    const signals: Signal[] = [{
      type: d.signal.type, weight: d.signal.weight, severity: d.signal.severity, conclusive: d.signal.conclusive,
      classHint: d.category === 'cve' ? 'scanner' : undefined,
      cooldownKey: `decoy:${d.id}:${ctx.path.toLowerCase()}`,
      detail: { decoy: d.id, decoyName: d.name, category: d.category },
    }];
    if (d.category === 'admin' && ctx.method === 'POST') {
      const form = new URLSearchParams(ctx.body.toString('utf8'));
      const user = form.get('log') ?? form.get('pma_username') ?? form.get('username') ?? form.get('email') ?? form.get('user') ?? '';
      const pass = form.get('pwd') ?? form.get('pma_password') ?? form.get('password') ?? form.get('pass') ?? '';
      signals.push({
        type: 'decoy_login_attempt', weight: 40, severity: 'high', cooldownKey: `login:${d.id}:${user}`,
        // Never store the attempted password itself — only enough to spot spraying/stuffing patterns.
        detail: { decoy: d.id, username: user.slice(0, 80), passwordLength: pass.length, passwordHint: pass ? `${pass.slice(0, 2)}***` : '' },
      });
    }
    return { res: d.handle(ctx, env), signals };
  }
}
