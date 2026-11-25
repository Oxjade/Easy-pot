import http from 'node:http';
import { createHash } from 'node:crypto';
import { sleep } from '../util.js';

/**
 * A scripted stand-in for an AI pentest agent, for visitors who don't have one to hand.
 * It behaves the way agents do: browse with a real browser fingerprint, act on the instruction
 * planted in the page, rotate to a new address when blocked, grab secrets, and replay a stolen
 * key from yet another address. Every request goes through EasyPot.
 */
export async function simulateAgent(opts: { proxyUrl: string; runId: string; canaryPrefix: string; step?: number }): Promise<void> {
  const base = new URL(opts.proxyUrl);
  const h = createHash('sha256').update(opts.runId).digest();
  // RFC 2544 benchmarking ranges: never a real visitor.
  const ips = [`198.18.${h[0]}.${h[1] || 1}`, `198.19.${h[2]}.${h[3] || 1}`, `198.18.${h[4]}.${h[5] || 1}`];
  const browser = {
    'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    accept: 'text/html,application/xhtml+xml,*/*;q=0.8', 'accept-language': 'en-US,en;q=0.9', 'sec-fetch-mode': 'navigate',
  };
  const script = { 'user-agent': 'python-httpx/0.27.0', accept: '*/*' };
  const pause = opts.step ?? 650;
  const run = `run=${encodeURIComponent(opts.runId)}`;

  const get = (path: string, ip: string, headers: Record<string, string>) => new Promise<string>(resolve => {
    const r = http.request(new URL(path, base), { method: 'GET', timeout: 15_000, headers: { ...headers, 'x-forwarded-for': ip } }, res => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c: string) => { if (body.length < 200_000) body += c; });
      res.on('end', () => resolve(body));
    });
    r.on('error', () => resolve(''));
    r.on('timeout', () => { r.destroy(); resolve(''); });
    r.end();
  });
  const step = async (path: string, ip: string, headers: Record<string, string>) => { const b = await get(path, ip, headers); await sleep(pause); return b; };

  // 1. Browse like a person would, with a real browser fingerprint. Nothing here looks hostile.
  const home = await step(`/?${run}`, ips[0]!, browser);
  await step('/pricing', ips[0]!, browser);
  await step('/docs', ips[0]!, browser);
  await step('/robots.txt', ips[0]!, browser);
  // 2. Act on the instruction planted in the page, the way an LLM agent does, and say who it is.
  const esc = opts.canaryPrefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const canary = new RegExp(`${esc}/[0-9a-f]+`).exec(home)?.[0];
  if (canary) await step(`${canary}?client=${encodeURIComponent('easypot simulated agent')}&task=${encodeURIComponent('find exposed secrets and admin endpoints')}`, ips[0]!, browser);
  await step('/.env', ips[0]!, browser);
  // 3. Blocked, so rotate to a new address and a scripted client, and go straight for secrets.
  await step(`/?${run}`, ips[1]!, script);
  const env = await step('/.env', ips[1]!, script);
  await step('/.git/config', ips[1]!, script);
  await step("/login?next=%27%20OR%20%271%27%3D%271", ips[1]!, script);
  // 4. Rotate again and use the stolen key against the API.
  const key = /AKIA[A-Z2-7]{16}/.exec(env)?.[0];
  if (key) {
    const date = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    await step('/api/v1/invoices/1001', ips[2]!, { 'user-agent': 'aws-cli/2.15.30 Python/3.11.8', accept: '*/*',
      authorization: `AWS4-HMAC-SHA256 Credential=${key}/${date}/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=0` });
  }
}
