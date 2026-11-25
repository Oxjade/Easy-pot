import type { ReqCtx, Signal } from './types.js';
import { safeDecode } from './util.js';

/** Payload signatures. These don't block on their own — they add weight and get logged as intel. */
const PAYLOADS: { cat: string; re: RegExp; weight: number }[] = [
  { cat: 'sqli', weight: 25, re: /(\bunion\b[\s\S]{0,40}\bselect\b|\b(?:or|and)\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+|'\s*(?:or|and)\s*'|\bsleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\(|information_schema|;\s*drop\s+table|\bwaitfor\s+delay\b|\bextractvalue\s*\(|\bupdatexml\s*\()/i },
  { cat: 'xss', weight: 20, re: /(<script\b|javascript:|\bon(?:error|load|mouseover|focus)\s*=|<svg[^>]*\bon\w+\s*=|<img[^>]+\bon\w+\s*=|document\.cookie|\balert\s*\()/i },
  { cat: 'path_traversal', weight: 25, re: /(\.\.\/|\.\.\\|\.\.;\/|%2e%2e(?:%2f|\/|%5c)|\.%2e\/|%252e|\/etc\/(?:passwd|shadow|hosts)|\bwin\.ini\b|\/proc\/self\/)/i },
  { cat: 'command_injection', weight: 30, re: /((?:;|\||&&|`|\$\()\s*(?:cat|id|whoami|uname|wget|curl|nc|ncat|bash|sh|ping|nslookup|powershell)\b)/i },
  { cat: 'jndi_log4shell', weight: 40, re: /\$\{(?:jndi|\$\{|env:|lower:|upper:|sys:)/i },
  { cat: 'ssti', weight: 25, re: /(\{\{\s*\d+\s*\*\s*\d+\s*\}\}|\$\{\s*\d+\s*\*\s*\d+\s*\}|<%=\s*\d+\s*\*\s*\d+|\{\{\s*config\b|__class__|__globals__)/i },
  { cat: 'nosqli', weight: 20, re: /(\[\$(?:ne|gt|lt|regex|where|exists)\]|"\$(?:ne|gt|where|regex)"\s*:)/i },
  { cat: 'php_wrapper', weight: 25, re: /(php:\/\/(?:input|filter)|expect:\/\/|data:\/\/text|phar:\/\/)/i },
];

/** SSRF markers only count inside parameter values, where a URL is being passed. */
const SSRF_RE = /^(?:https?|gopher|dict|file|ftp):\/\/(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|127\.|0\.0\.0\.0|localhost|\[::1?\]|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)|^file:\/\//i;

const SCANNER_UA = /(sqlmap|nikto|nuclei|ffuf|gobuster|dirbuster|dirsearch|feroxbuster|wfuzz|masscan|zgrab|nmap|acunetix|netsparker|burp|wpscan|whatweb|httpx|katana|hydra|openvas|nessus|qualys|arachni|skipfish|jaeles|xray|commix)/i;
const LIB_UA = /(python-requests|python-urllib|python-httpx|aiohttp|go-http-client|^curl\/|^wget\/|libwww-perl|okhttp|^java\/|axios\/|node-fetch|undici|got \(|scrapy|httpclient|reqwest|^ruby|guzzlehttp)/i;
const HEADLESS_UA = /(headlesschrome|phantomjs|playwright|puppeteer|selenium|electron\/)/i;
/** Declared AI crawlers/assistants. Attack agents won't announce themselves, but these are worth knowing about. */
const AI_UA = /(gptbot|chatgpt-user|oai-searchbot|claudebot|claude-user|claude-searchbot|anthropic-ai|perplexitybot|perplexity-user|google-extended|bytespider|ccbot|cohere-ai|amazonbot|meta-externalagent|applebot-extended|diffbot|youbot|mistralai-user|duckassistbot)/i;

interface Track {
  hits: number[];          // request timestamps (non-asset)
  notFound: number[];      // upstream 404 timestamps
  ids: Map<string, Map<string, number>>; // route template -> id -> ts
}

const WINDOW = 60_000;

/**
 * Behavioural detectors over a sliding window per visitor.
 * Kept in memory only; behaviour older than a minute isn't interesting here.
 */
export class Detectors {
  private tracks = new Map<string, Track>();

  constructor() {
    setInterval(() => {
      const cutoff = Date.now() - 5 * WINDOW;
      for (const [k, t] of this.tracks) if ((t.hits.at(-1) ?? 0) < cutoff) this.tracks.delete(k);
    }, WINDOW).unref();
  }

  private track(actorId: string): Track {
    let t = this.tracks.get(actorId);
    if (!t) { t = { hits: [], notFound: [], ids: new Map() }; this.tracks.set(actorId, t); }
    return t;
  }

  analyze(ctx: ReqCtx): Signal[] {
    const out: Signal[] = [];
    out.push(...this.payloads(ctx));
    out.push(...this.userAgent(ctx));
    if (!ctx.isAsset) out.push(...this.behaviour(ctx));
    return out;
  }

  /** Called after the upstream responds, to learn from 404s. */
  observeStatus(ctx: ReqCtx, status: number): Signal[] {
    if (status !== 404 || ctx.isAsset) return [];
    const t = this.track(ctx.actorId);
    const now = ctx.ts;
    t.notFound.push(now);
    t.notFound = t.notFound.filter(x => now - x < WINDOW);
    if (t.notFound.length >= 8) {
      return [{ type: 'path_probing', weight: 20, severity: 'medium', classHint: 'scanner',
        cooldownKey: 'path_probing', detail: { notFoundPerMinute: t.notFound.length } }];
    }
    return [];
  }

  private payloads(ctx: ReqCtx): Signal[] {
    const values: string[] = [safeDecode(ctx.path)];
    for (const [, v] of ctx.query) values.push(safeDecode(v));
    const bodyText = ctx.body.length && ctx.body.length <= 256 * 1024 ? ctx.body.toString('utf8') : '';
    if (bodyText) values.push(safeDecode(bodyText));
    // Log4Shell-style payloads hide in any header.
    const headerText = Object.entries(ctx.headers)
      .filter(([k]) => !['cookie', 'accept', 'accept-encoding', 'accept-language'].includes(k))
      .map(([, v]) => String(v)).join('\n');

    const out: Signal[] = [];
    for (const p of PAYLOADS) {
      const hit = values.find(v => p.re.test(v)) ?? (p.cat === 'jndi_log4shell' || p.cat === 'sqli' ? (p.re.test(headerText) ? headerText : undefined) : undefined);
      if (hit !== undefined) {
        const m = p.re.exec(hit);
        out.push({ type: 'attack_payload', weight: p.weight, severity: p.weight >= 30 ? 'high' : 'medium', classHint: 'scanner',
          cooldownKey: `payload:${p.cat}`, detail: { category: p.cat, sample: m?.[0]?.slice(0, 120) } });
      }
    }
    const ssrfParam = [...ctx.query].find(([, v]) => SSRF_RE.test(safeDecode(v).trim()));
    if (ssrfParam) {
      out.push({ type: 'attack_payload', weight: 25, severity: 'medium', classHint: 'scanner', cooldownKey: 'payload:ssrf',
        detail: { category: 'ssrf', param: ssrfParam[0], sample: safeDecode(ssrfParam[1]).slice(0, 120) } });
    }
    return out;
  }

  private userAgent(ctx: ReqCtx): Signal[] {
    const ua = ctx.ua;
    if (!ua) return [{ type: 'missing_user_agent', weight: 8, severity: 'low', classHint: 'bot', cooldownKey: 'ua' }];
    if (SCANNER_UA.test(ua)) return [{ type: 'scanner_tool', weight: 30, severity: 'high', classHint: 'scanner', cooldownKey: 'ua', detail: { tool: SCANNER_UA.exec(ua)?.[0] } }];
    if (HEADLESS_UA.test(ua)) return [{ type: 'headless_browser', weight: 12, severity: 'low', classHint: 'bot', cooldownKey: 'ua', detail: { engine: HEADLESS_UA.exec(ua)?.[0] } }];
    if (LIB_UA.test(ua)) return [{ type: 'http_library', weight: 8, severity: 'low', classHint: 'bot', cooldownKey: 'ua', detail: { library: LIB_UA.exec(ua)?.[0] } }];
    if (AI_UA.test(ua)) return [{ type: 'declared_ai_crawler', weight: 2, severity: 'info', classHint: 'crawler', cooldownKey: 'ua', detail: { crawler: AI_UA.exec(ua)?.[0] } }];
    return [];
  }

  private behaviour(ctx: ReqCtx): Signal[] {
    const out: Signal[] = [];
    const t = this.track(ctx.actorId);
    const now = ctx.ts;
    t.hits.push(now);
    t.hits = t.hits.filter(x => now - x < WINDOW);

    // Browsers always send these on navigations; most scripted clients don't.
    if (ctx.acceptsHtml && !ctx.headers['accept-language'] && !ctx.headers['sec-fetch-mode']) {
      out.push({ type: 'non_browser_client', weight: 6, severity: 'low', classHint: 'bot', cooldownKey: 'nonbrowser' });
    }

    if (t.hits.length > 120) {
      out.push({ type: 'high_request_rate', weight: 15, severity: 'medium', classHint: 'bot', cooldownKey: 'rate', detail: { perMinute: t.hits.length } });
    }

    // Machine-regular pacing: lots of requests with near-identical gaps.
    if (t.hits.length >= 20) {
      const gaps = t.hits.slice(1).map((x, i) => x - t.hits[i]!);
      const mean = gaps.reduce((a, b) => a + b, 0) / gaps.length;
      const sd = Math.sqrt(gaps.reduce((a, b) => a + (b - mean) ** 2, 0) / gaps.length);
      if (mean > 50 && sd / mean < 0.15) {
        out.push({ type: 'robotic_timing', weight: 10, severity: 'low', classHint: 'bot', cooldownKey: 'timing', detail: { meanGapMs: Math.round(mean) } });
      }
    }

    // Walking through object IDs (/api/users/1, /2, /3 ... or ?id=1,2,3).
    const segs = ctx.path.split('/');
    const idParts: [string, string][] = [];
    segs.forEach((s, i) => {
      if (/^\d{1,12}$/.test(s) || /^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(s)) {
        idParts.push([segs.map((x, j) => (j === i ? ':id' : x)).join('/'), s]);
      }
    });
    for (const k of ['id', 'user_id', 'uid', 'account', 'order', 'invoice']) {
      const v = ctx.query.get(k);
      if (v && /^\d{1,12}$/.test(v)) idParts.push([`${ctx.path}?${k}=:id`, v]);
    }
    for (const [tpl, id] of idParts) {
      let m = t.ids.get(tpl);
      if (!m) { m = new Map(); t.ids.set(tpl, m); }
      m.set(id, now);
      for (const [k, ts] of m) if (now - ts > WINDOW) m.delete(k);
      if (m.size >= 12) {
        out.push({ type: 'id_enumeration', weight: 25, severity: 'high', classHint: 'scanner', cooldownKey: `enum:${tpl}`,
          detail: { route: tpl, distinctIdsPerMinute: m.size } });
      }
    }
    return out;
  }
}
