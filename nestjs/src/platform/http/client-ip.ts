import { BlockList, isIP } from 'node:net';
import type { Request } from 'express';

// Pure helpers (unit tested): which IP a request comes from, and how the rate limiter keys it.

/** RFC 5952 form via the WHATWG URL serializer (compressed, lowercase). */
const canonicalIpv6 = (v: string): string | null => {
  try {
    return new URL(`http://[${v}]/`).hostname.slice(1, -1);
  } catch {
    return null;
  }
};

/**
 * Parsed IP in canonical form, or null if the value is not an IP. IPv6 is canonicalised (`2001:DB8:0::1` →
 * `2001:db8::1`, zone ids dropped) and IPv4-mapped IPv6 (`::ffff:1.2.3.4`) becomes `1.2.3.4`.
 */
export function normalizeIp(value: string | undefined | null): string | null {
  if (!value) return null;
  const v = value.trim().split('%')[0];
  const kind = isIP(v);
  if (kind === 4) return v;
  if (kind !== 6) return null;
  const canonical = canonicalIpv6(v);
  if (!canonical) return null;
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(canonical);
  if (mapped) {
    const hi = parseInt(mapped[1], 16);
    const lo = parseInt(mapped[2], 16);
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  return canonical;
}

/** TRUSTED_PROXY_CIDRS → BlockList. Throws with the offending entry on anything that is not `ip/prefix`. */
export function parseCidrs(list: string[]): BlockList {
  const blocks = new BlockList();
  for (const entry of list) {
    const [addr, prefix, extra] = entry.split('/');
    const ip = normalizeIp(addr);
    const family = ip ? isIP(ip) : 0;
    const bits = Number(prefix);
    if (!ip || extra !== undefined || !/^\d{1,3}$/.test(prefix ?? '') || bits > (family === 4 ? 32 : 128)) {
      throw new Error(`invalid CIDR: ${entry}`);
    }
    blocks.addSubnet(ip, bits, family === 4 ? 'ipv4' : 'ipv6');
  }
  return blocks;
}

export interface ProxyTrust {
  hops: number;
  cidrs: BlockList | null;
}

/** From TRUSTED_PROXY_HOPS / TRUSTED_PROXY_CIDRS (already validated at startup). */
export const proxyTrust = (hops: number, cidrs: string[]): ProxyTrust => ({ hops, cidrs: cidrs.length ? parseCidrs(cidrs) : null });

/**
 * SPEC 2: hops 0 → the socket peer, X-Forwarded-For ignored. hops N → only when the peer is inside
 * TRUSTED_PROXY_CIDRS, the N-th entry from the RIGHT (each proxy appends one; everything to the left is
 * client-written). A missing or non-IP entry, or an untrusted peer, means the socket peer. Null if not even
 * the peer parses (never a placeholder string).
 */
export function resolveClientIp(xff: string | string[] | undefined, socketPeer: string | undefined, trust: ProxyTrust): string | null {
  const peer = normalizeIp(socketPeer);
  if (trust.hops <= 0 || xff === undefined || !peer || !trust.cidrs) return peer;
  if (!trust.cidrs.check(peer, isIP(peer) === 4 ? 'ipv4' : 'ipv6')) return peer;
  // Entry by entry: one odd (e.g. non-ASCII) entry never discards the rest.
  const entries = (Array.isArray(xff) ? xff.join(',') : xff).split(',').map((e) => e.trim());
  return normalizeIp(entries[entries.length - trust.hops]) ?? peer;
}

export const clientIp = (req: Request, trust: ProxyTrust): string | null =>
  resolveClientIp(req.headers['x-forwarded-for'], req.socket.remoteAddress, trust);

/** Expands a canonical IPv6 address to its 8 hextets (handles `::` and an embedded IPv4 tail). */
function ipv6Hextets(ip: string): string[] {
  let addr = ip;
  const v4 = /(\d{1,3}(?:\.\d{1,3}){3})$/.exec(addr);
  if (v4) {
    const [a, b, c, d] = v4[1].split('.').map(Number);
    addr = addr.slice(0, -v4[1].length) + `${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const [head, tail] = addr.split('::');
  const h = head ? head.split(':') : [];
  const t = tail !== undefined && tail !== '' ? tail.split(':') : [];
  const fill = tail !== undefined ? Array<string>(8 - h.length - t.length).fill('0') : [];
  return [...h, ...fill, ...t].map((x) => x.padStart(4, '0'));
}

/** Rate-limit key: IPv4 as-is, IPv6 by its /64 (one client usually owns a whole /64). */
export function rateLimitKey(ip: string | null): string {
  if (!ip) return 'unknown-peer';
  if (isIP(ip) !== 6) return ip;
  return `${ipv6Hextets(ip).slice(0, 4).join(':')}::/64`;
}
