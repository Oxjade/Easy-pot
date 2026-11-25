import { randomBytes } from 'node:crypto';
import type { Store } from './store.js';
import type { ReqCtx, Signal } from './types.js';
import { randStr } from './util.js';

export type TokenKind =
  | 'aws_access_key' | 'aws_secret' | 'stripe_key' | 'github_token' | 'db_password'
  | 'jwt' | 'api_key' | 'admin_password' | 'app_key';

export type TokenSet = Record<TokenKind, string>;

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function b64url(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

function makeSet(siteName: string): TokenSet {
  const now = Math.floor(Date.now() / 1000);
  const slug = siteName.toLowerCase().replace(/[^a-z0-9]+/g, '-');
  return {
    aws_access_key: 'AKIA' + randStr(16, B32),
    aws_secret: randStr(40, B64),
    stripe_key: 'sk_live_' + randStr(24),
    github_token: 'ghp_' + randStr(36),
    db_password: randStr(6) + '!' + randStr(9) + '#' + randStr(4),
    jwt: `${b64url({ alg: 'HS256', typ: 'JWT' })}.${b64url({ sub: 'svc-backup', role: 'admin', iss: slug, iat: now })}.${randomBytes(32).toString('base64url')}`,
    api_key: 'api_' + randomBytes(16).toString('hex'),
    admin_password: 'Adm1n-' + randStr(12),
    app_key: 'base64:' + randomBytes(32).toString('base64'),
  };
}

interface TokenOwner { actorId: string; kind: string; issued: number; decoyPath: string }

/**
 * Issues unique fake credentials per visitor and spots them when they come back.
 * A token can only be known by someone who fetched the decoy it was planted in,
 * so any replay is proof of an active attack — and tells you which visitor leaked it.
 */
export class Honeytokens {
  private byToken = new Map<string, TokenOwner>();
  private byActor = new Map<string, TokenSet>();

  constructor(private store: Store, private siteName: string) {
    for (const t of store.allTokens()) this.byToken.set(t.token, t);
  }

  /** The same visitor always sees the same credentials, across every decoy — like a real leak. */
  issue(actorId: string, decoyPath: string): TokenSet {
    let set = this.byActor.get(actorId);
    if (!set) {
      set = makeSet(this.siteName);
      this.byActor.set(actorId, set);
    }
    for (const [kind, token] of Object.entries(set)) {
      const known = this.byToken.get(token);
      if (known && known.decoyPath.split(',').includes(decoyPath)) continue;
      const owner: TokenOwner = known
        ? { ...known, decoyPath: `${known.decoyPath},${decoyPath}` }
        : { actorId, kind, issued: Date.now(), decoyPath };
      this.byToken.set(token, owner);
      if (!known) this.store.insertToken(token, actorId, kind, decoyPath);
    }
    return set;
  }

  /** How many fake secrets this visitor has been handed (0 if it never opened a decoy that plants them). */
  issuedCount(actorId: string): number {
    const set = this.byActor.get(actorId);
    return set ? Object.keys(set).length : 0;
  }

  /** Look for any issued token anywhere in the request: headers, URL, body, basic auth. */
  detectReplay(ctx: ReqCtx): Signal[] {
    if (!this.byToken.size) return [];
    const hay: string[] = [ctx.url];
    for (const [k, v] of Object.entries(ctx.headers)) {
      if (k === 'user-agent' || v == null) continue;
      const s = Array.isArray(v) ? v.join(' ') : v;
      hay.push(s);
      const basic = /^basic\s+([A-Za-z0-9+/=]+)$/i.exec(s);
      if (basic) hay.push(Buffer.from(basic[1]!, 'base64').toString('utf8'));
    }
    if (ctx.body.length && ctx.body.length <= 256 * 1024) {
      const text = ctx.body.toString('utf8');
      hay.push(text);
      try { hay.push(decodeURIComponent(text.replace(/\+/g, ' '))); } catch { /* not form-encoded */ }
    }

    const found = new Map<string, TokenOwner>();
    const check = (cand: string) => { const o = this.byToken.get(cand); if (o) found.set(cand, o); };
    const generic = /[A-Za-z0-9_\-.+/=!#:]{16,}/g;
    // Prefixed formats get pulled out of any surrounding syntax, e.g.
    // "AWS4-HMAC-SHA256 Credential=AKIA…/20261125/eu-west-1/s3/aws4_request".
    const prefixed = /AKIA[A-Z2-7]{16}|sk_live_[A-Za-z0-9]{24}|ghp_[A-Za-z0-9]{36}|api_[0-9a-f]{32}|Adm1n-[A-Za-z0-9]{12}|eyJ[\w-]+\.[\w-]+\.[\w-]+/g;
    for (const h of hay) {
      for (const m of h.matchAll(prefixed)) check(m[0]);
      for (const m of h.matchAll(generic)) {
        // Tokens can sit inside larger strings (e.g. "key:secret"); check whole match and its parts.
        check(m[0]);
        for (const part of m[0].split(/[:=]/)) check(part);
      }
    }
    return [...found.values()].map(owner => ({
      type: 'honeytoken_replay',
      weight: 100,
      severity: 'critical' as const,
      conclusive: true,
      cooldownKey: `replay:${owner.kind}`,
      detail: {
        kind: owner.kind,
        issuedTo: owner.actorId,
        issuedAt: owner.issued,
        plantedIn: owner.decoyPath,
        sameVisitor: owner.actorId === ctx.actorId,
      },
    }));
  }
}
