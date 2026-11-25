import dgram from 'node:dgram';
import type { EventEmitter } from 'node:events';
import net from 'node:net';
import os from 'node:os';
import { appendFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { Config, SyslogConfig, WebhookConfig } from '../config.js';
import type { Block, EasyPotEvent, Severity } from '../types.js';
import { SEVERITY_RANK } from '../types.js';

const atLeast = (s: Severity, min: Severity) => SEVERITY_RANK[s] >= SEVERITY_RANK[min];

/** MITRE ATT&CK technique per signal — lets SIEMs group EasyPot alerts with the rest of their detections. */
export const MITRE: Record<string, { id: string; tactic: string }> = {
  decoy_secret_file: { id: 'T1552.001', tactic: 'Credential Access' },
  decoy_source_exposure: { id: 'T1213', tactic: 'Collection' },
  decoy_database_dump: { id: 'T1005', tactic: 'Collection' },
  decoy_admin_panel: { id: 'T1595.003', tactic: 'Reconnaissance' },
  decoy_login_attempt: { id: 'T1110', tactic: 'Credential Access' },
  decoy_api_docs: { id: 'T1595.003', tactic: 'Reconnaissance' },
  decoy_internal_api: { id: 'T1190', tactic: 'Initial Access' },
  decoy_debug_endpoint: { id: 'T1592', tactic: 'Reconnaissance' },
  cve_exploit_attempt: { id: 'T1190', tactic: 'Initial Access' },
  honeytoken_replay: { id: 'T1078', tactic: 'Defense Evasion' },
  agent_instruction_followed: { id: 'T1595', tactic: 'Reconnaissance' },
  tripwire_link_followed: { id: 'T1595.003', tactic: 'Reconnaissance' },
  labyrinth_depth: { id: 'T1595', tactic: 'Reconnaissance' },
  path_probing: { id: 'T1595.003', tactic: 'Reconnaissance' },
  attack_payload: { id: 'T1190', tactic: 'Initial Access' },
  id_enumeration: { id: 'T1087', tactic: 'Discovery' },
  scanner_tool: { id: 'T1595.002', tactic: 'Reconnaissance' },
};

/** Flat JSON record. `srcip` is named so Wazuh's JSON decoder maps it natively (needed for active response). */
export function toRecord(e: EasyPotEvent) {
  return {
    product: 'easypot', version: 1, timestamp: new Date(e.ts).toISOString(), id: e.id,
    srcip: e.ip, actor: e.actorId, actor_class: e.actorClass, signal: e.signal, severity: e.severity,
    score: e.score, action: e.action, method: e.method, url: e.path, user_agent: e.ua,
    mitre_id: MITRE[e.signal]?.id, mitre_tactic: MITRE[e.signal]?.tactic, detail: e.detail,
  };
}

const CEF_SEV: Record<Severity, number> = { info: 1, low: 3, medium: 5, high: 8, critical: 10 };
const cefEsc = (s: string) => s.replace(/\\/g, '\\\\').replace(/=/g, '\\=').replace(/\r?\n/g, ' ');
const cefHdr = (s: string) => s.replace(/\\/g, '\\\\').replace(/\|/g, '\\|');

export function toCef(e: EasyPotEvent): string {
  return `CEF:0|Syntrei|EasyPot|0.1|${cefHdr(e.signal)}|${cefHdr(e.signal.replace(/_/g, ' '))}|${CEF_SEV[e.severity]}|` +
    `rt=${e.ts} src=${cefEsc(e.ip)} requestMethod=${cefEsc(e.method)} request=${cefEsc(e.path.slice(0, 1000))} ` +
    `requestClientApplication=${cefEsc(e.ua.slice(0, 300))} act=${e.action} ` +
    `cs1Label=actor cs1=${e.actorId} cs2Label=actorClass cs2=${e.actorClass} cn1Label=score cn1=${e.score} ` +
    `cs3Label=mitre cs3=${MITRE[e.signal]?.id ?? ''} cs4Label=detail cs4=${cefEsc(JSON.stringify(e.detail).slice(0, 1000))}`;
}

class Syslog {
  private udp?: dgram.Socket;
  private tcp?: net.Socket;
  private connecting = false;
  private host = os.hostname();
  constructor(private c: SyslogConfig) {
    if (c.protocol === 'udp') { this.udp = dgram.createSocket('udp4'); this.udp.unref(); }
  }
  private ensureTcp(): net.Socket | undefined {
    if (this.tcp && !this.tcp.destroyed) return this.tcp;
    if (this.connecting) return undefined;
    this.connecting = true;
    const s = net.connect({ host: this.c.host, port: this.c.port }, () => { this.connecting = false; });
    s.on('error', err => { console.error('[easypot] syslog tcp:', err.message); this.connecting = false; s.destroy(); });
    s.unref();
    this.tcp = s;
    return s;
  }
  send(e: EasyPotEvent): void {
    if (!atLeast(e.severity, this.c.minSeverity)) return;
    const sev = { info: 6, low: 5, medium: 4, high: 3, critical: 2 }[e.severity];
    const msg = this.c.format === 'cef' ? toCef(e) : JSON.stringify(toRecord(e));
    const line = `<${16 * 8 + sev}>1 ${new Date(e.ts).toISOString()} ${this.host} easypot - ${e.signal} - ${msg}`;
    if (this.udp) this.udp.send(Buffer.from(line), this.c.port, this.c.host, err => err && console.error('[easypot] syslog udp:', err.message));
    else this.ensureTcp()?.write(line + '\n'); // newline framing (octet-counting optional on most receivers)
  }
}

class Webhooks {
  private last = new Map<string, number>();
  constructor(private hooks: WebhookConfig[], private siteName: string) {}
  async send(e: EasyPotEvent): Promise<void> {
    for (const h of this.hooks) {
      if (!atLeast(e.severity, h.minSeverity)) continue;
      // One alert per visitor per signal per 10 minutes.
      const key = `${h.url}|${e.actorId}|${e.signal}`;
      if (Date.now() - (this.last.get(key) ?? 0) < 600_000) continue;
      this.last.set(key, Date.now());
      const body = h.type === 'slack' ? this.slack(e) : toRecord(e);
      fetch(h.url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(5000) })
        .catch(err => console.error('[easypot] webhook:', err.message));
    }
  }
  private slack(e: EasyPotEvent) {
    const icon = { info: '⚪', low: '🔵', medium: '🟡', high: '🟠', critical: '🔴' }[e.severity];
    const d = e.detail as Record<string, unknown>;
    const extra = d.selfReportedClient ? `\n*Self-reported agent:* ${d.selfReportedClient} — ${d.selfReportedTask ?? ''}` :
      d.kind ? `\n*Stolen credential used:* ${d.kind} (planted in ${d.plantedIn})` :
      d.category ? `\n*Category:* ${d.category}` : '';
    return {
      text: `${icon} EasyPot [${this.siteName}] ${e.signal} from ${e.ip}`,
      blocks: [{ type: 'section', text: { type: 'mrkdwn', text:
        `${icon} *${e.signal.replace(/_/g, ' ')}* on *${this.siteName}*\n*Source:* \`${e.ip}\` (${e.actorClass}, score ${e.score})\n` +
        `*Request:* \`${e.method} ${e.path.slice(0, 200)}\`\n*Action:* ${e.action}${extra}` } }],
    };
  }
}

class FileLog {
  private ready: Promise<unknown>;
  private queue: Promise<unknown> = Promise.resolve();
  constructor(private path: string, private min: Severity) { this.ready = mkdir(dirname(path), { recursive: true }); }
  send(e: EasyPotEvent): void {
    if (!atLeast(e.severity, this.min)) return;
    const line = JSON.stringify(toRecord(e)) + '\n';
    this.queue = this.queue.then(() => this.ready).then(() => appendFile(this.path, line)).catch(err => console.error('[easypot] file log:', err.message));
  }
  block(b: Block): void {
    const line = JSON.stringify({ product: 'easypot', version: 1, timestamp: new Date().toISOString(), signal: 'block_added',
      severity: 'high', srcip: b.kind === 'ip' ? b.target : undefined, actor: b.kind === 'actor' ? b.target : undefined,
      reason: b.reason, source: b.source, expires: b.expires ? new Date(b.expires).toISOString() : null }) + '\n';
    if (b.kind !== 'ip') return;
    this.queue = this.queue.then(() => this.ready).then(() => appendFile(this.path, line)).catch(() => {});
  }
}

export function wireOutputs(cfg: Config, bus: EventEmitter): void {
  const i = cfg.integrations;
  if (i.syslog.enabled) {
    const s = new Syslog(i.syslog);
    bus.on('event', (e: EasyPotEvent) => s.send(e));
    console.log(`[easypot] syslog → ${i.syslog.protocol}://${i.syslog.host}:${i.syslog.port} (${i.syslog.format})`);
  }
  if (i.fileLog.enabled) {
    const f = new FileLog(i.fileLog.path, i.fileLog.minSeverity);
    bus.on('event', (e: EasyPotEvent) => f.send(e));
    bus.on('block', (b: Block) => f.block(b));
    console.log(`[easypot] event log → ${i.fileLog.path}`);
  }
  if (i.webhooks.length) {
    const w = new Webhooks(i.webhooks, cfg.siteName);
    bus.on('event', (e: EasyPotEvent) => void w.send(e));
    console.log(`[easypot] ${i.webhooks.length} webhook(s) configured`);
  }
}
