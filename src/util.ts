import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import { isIP, isIPv4 } from 'node:net';

export const uid = () => randomUUID();

export function hmac(secret: string, data: string, len = 16): string {
  return createHmac('sha256', secret).update(data).digest('hex').slice(0, len);
}

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
export function randStr(len: number, alphabet = ALNUM): string {
  const bytes = randomBytes(len);
  let s = '';
  for (let i = 0; i < len; i++) s += alphabet[bytes[i]! % alphabet.length];
  return s;
}

/** Deterministic PRNG (mulberry32) so labyrinth pages render the same for the same URL. */
export function seeded(seed: string): () => number {
  let h = 1779033703 ^ seed.length;
  for (let i = 0; i < seed.length; i++) {
    h = Math.imul(h ^ seed.charCodeAt(i), 3432918353);
    h = (h << 13) | (h >>> 19);
  }
  let a = h >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** The address of the hop that connected to us. */
export function peerIp(req: IncomingMessage): string {
  const ip = req.socket.remoteAddress ?? '0.0.0.0';
  return ip.startsWith('::ffff:') ? ip.slice(7) : ip;
}

/** How many proxies in front of EasyPot are trusted to append to X-Forwarded-For. */
export function trustedHops(trustProxy: boolean | number): number {
  if (trustProxy === true) return 1;
  if (typeof trustProxy === 'number' && Number.isFinite(trustProxy)) return Math.max(0, Math.floor(trustProxy));
  return 0;
}

/**
 * The client's real address. Each trusted proxy appends the address it received the request
 * from to X-Forwarded-For, so with N trusted proxies the client is the Nth entry from the right.
 * Everything further left was written by the client and is ignored: taking the leftmost entry
 * would let an attacker dodge blocks, or get any address of their choosing blocked and pushed
 * to every firewall reading the feed.
 */
export function clientIp(req: IncomingMessage, trustProxy: boolean | number): string {
  const peer = peerIp(req);
  const hops = trustedHops(trustProxy);
  if (!hops) return peer;
  const raw = req.headers['x-forwarded-for'];
  const xff = (Array.isArray(raw) ? raw.join(',') : raw ?? '').split(',').map(s => s.trim()).filter(Boolean);
  if (xff.length) {
    // Fewer entries than trusted hops means the request skipped a proxy; the leftmost is then the closest we have.
    const ip = xff[Math.max(0, xff.length - hops)]!;
    const norm = ip.startsWith('::ffff:') ? ip.slice(7) : ip;
    if (isIP(norm)) return norm;
  }
  // Proxies that set a single-address header instead (Cloudflare Tunnel, some nginx setups).
  for (const h of ['cf-connecting-ip', 'x-real-ip']) {
    const v = req.headers[h];
    if (typeof v === 'string' && isIP(v.trim())) return v.trim();
  }
  return peer;
}

function ipv4ToInt(ip: string): number {
  return ip.split('.').reduce((acc, o) => (acc << 8) + Number(o), 0) >>> 0;
}

export function ipInCidr(ip: string, cidr: string): boolean {
  const [range, bitsStr] = cidr.split('/');
  if (!range) return false;
  if (!isIPv4(ip) || !isIPv4(range)) return ip === range;
  const bits = bitsStr === undefined ? 32 : Number(bitsStr);
  if (bits === 0) return true;
  const mask = (~0 << (32 - bits)) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(range) & mask);
}

export function safeDecode(s: string): string {
  let out = s;
  for (let i = 0; i < 2; i++) {
    try {
      const d = decodeURIComponent(out.replace(/\+/g, ' '));
      if (d === out) break;
      out = d;
    } catch { break; }
  }
  return out;
}

export const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

const ASSET_RE = /\.(?:js|mjs|css|map|png|jpe?g|gif|webp|avif|svg|ico|woff2?|ttf|otf|eot|mp4|webm|mp3|wav|pdf)$/i;
export const isAssetPath = (p: string) => ASSET_RE.test(p);
