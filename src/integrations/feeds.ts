import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import type { Block } from '../types.js';

/** Plain list, one IP per line — the format Palo Alto EDL, FortiGate threat feeds, pfSense/OPNsense aliases and ipset all read. */
export function blocklistTxt(blocks: Block[]): string {
  const ips = [...new Set(blocks.filter(b => b.kind === 'ip' && isIP(b.target)).map(b => b.target))];
  return ips.join('\n') + (ips.length ? '\n' : '');
}

export function blocklistJson(blocks: Block[]) {
  return {
    generated: new Date().toISOString(),
    count: blocks.filter(b => b.kind === 'ip').length,
    entries: blocks.filter(b => b.kind === 'ip').map(b => ({
      ip: b.target, reason: b.reason, source: b.source,
      added: new Date(b.created).toISOString(), expires: b.expires ? new Date(b.expires).toISOString() : null,
    })),
  };
}

const stixId = (type: string, seed: string) => {
  const h = createHash('sha256').update(seed).digest('hex');
  return `${type}--${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`;
};

/** STIX 2.1 bundle of IP indicators, for MISP / OpenCTI / TAXII consumers. */
export function stixBundle(blocks: Block[], siteName: string) {
  const identity = {
    type: 'identity', spec_version: '2.1', id: stixId('identity', 'easypot:' + siteName),
    created: '2026-01-01T00:00:00.000Z', modified: '2026-01-01T00:00:00.000Z', name: `EasyPot (${siteName})`, identity_class: 'system',
  };
  const indicators = blocks.filter(b => b.kind === 'ip' && isIP(b.target)).map(b => {
    const ts = new Date(b.created).toISOString();
    const v6 = isIP(b.target) === 6;
    return {
      type: 'indicator', spec_version: '2.1', id: stixId('indicator', `${b.target}|${b.created}`),
      created_by_ref: identity.id, created: ts, modified: ts,
      name: `EasyPot: ${b.reason}`,
      description: `Source caught by EasyPot deception layer (${b.reason}).`,
      indicator_types: ['malicious-activity'],
      pattern: `[${v6 ? 'ipv6-addr' : 'ipv4-addr'}:value = '${b.target}']`, pattern_type: 'stix',
      valid_from: ts, ...(b.expires ? { valid_until: new Date(b.expires).toISOString() } : {}),
      labels: ['easypot', b.reason.split(' ')[0]],
    };
  });
  return { type: 'bundle', id: stixId('bundle', `${siteName}|${Date.now()}`), objects: [identity, ...indicators] };
}
