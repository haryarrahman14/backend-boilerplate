import { normalizeIp, parseCidrs, proxyTrust, rateLimitKey, resolveClientIp } from './client-ip.js';

const behindProxy = (hops = 1) => proxyTrust(hops, ['10.0.0.0/8', '::1/128']);

describe('resolveClientIp', () => {
  it('ignores X-Forwarded-For with 0 hops', () => {
    expect(resolveClientIp('6.6.6.6', '10.0.0.1', proxyTrust(0, []))).toBe('10.0.0.1');
  });

  it('takes the N-th entry from the right, never the client-written left side', () => {
    expect(resolveClientIp('6.6.6.6, 203.0.113.9', '10.0.0.1', behindProxy())).toBe('203.0.113.9');
    expect(resolveClientIp('6.6.6.6, 203.0.113.9, 10.0.0.2', '10.0.0.1', behindProxy(2))).toBe('203.0.113.9');
    expect(resolveClientIp(['6.6.6.6', '203.0.113.9'], '10.0.0.1', behindProxy())).toBe('203.0.113.9');
  });

  it('ignores X-Forwarded-For from a peer outside TRUSTED_PROXY_CIDRS', () => {
    expect(resolveClientIp('203.0.113.9', '198.51.100.7', behindProxy())).toBe('198.51.100.7');
    expect(resolveClientIp('203.0.113.9', '::ffff:198.51.100.7', behindProxy())).toBe('198.51.100.7');
    expect(resolveClientIp('203.0.113.9', '::1', behindProxy())).toBe('203.0.113.9');
  });

  it('falls back to the socket peer when the entry is missing or not an IP', () => {
    expect(resolveClientIp('not-an-ip', '10.0.0.1', behindProxy())).toBe('10.0.0.1');
    expect(resolveClientIp('203.0.113.9:443', '10.0.0.1', behindProxy())).toBe('10.0.0.1');
    expect(resolveClientIp('203.0.113.9', '10.0.0.1', behindProxy(2))).toBe('10.0.0.1');
    expect(resolveClientIp(undefined, '10.0.0.1', behindProxy())).toBe('10.0.0.1');
  });

  it('parses entry by entry, so a non-ASCII entry does not discard the rest', () => {
    expect(resolveClientIp('café, 203.0.113.9', '10.0.0.1', behindProxy())).toBe('203.0.113.9');
  });

  it('returns null, never a placeholder, when the peer itself is unknown', () => {
    expect(resolveClientIp(undefined, undefined, proxyTrust(0, []))).toBeNull();
  });
});

describe('normalizeIp', () => {
  it('shows IPv4-mapped IPv6 as IPv4 and canonicalises IPv6', () => {
    expect(normalizeIp('::ffff:127.0.0.1')).toBe('127.0.0.1');
    expect(normalizeIp('::FFFF:7f00:1')).toBe('127.0.0.1');
    expect(normalizeIp('2001:DB8:0:0:0::1')).toBe('2001:db8::1');
    expect(normalizeIp('2001:0db8:0000:0000:0001:0000:0000:0001')).toBe('2001:db8::1:0:0:1');
    expect(normalizeIp('fe80::1%eth0')).toBe('fe80::1');
    expect(normalizeIp('garbage')).toBeNull();
    expect(normalizeIp(undefined)).toBeNull();
  });
});

describe('parseCidrs', () => {
  it('accepts IPv4 and IPv6 CIDRs and rejects anything else', () => {
    const b = parseCidrs(['127.0.0.1/32', '2001:db8::/32']);
    expect(b.check('127.0.0.1', 'ipv4')).toBe(true);
    expect(b.check('2001:db8::5', 'ipv6')).toBe(true);
    expect(b.check('127.0.0.2', 'ipv4')).toBe(false);
    for (const bad of ['127.0.0.1', '127.0.0.1/33', '::1/129', 'nope/8', '10.0.0.0/8/1', '10.0.0.0/x']) {
      expect(() => parseCidrs([bad])).toThrow(/invalid CIDR/);
    }
  });
});

describe('rateLimitKey', () => {
  it('keys IPv4 by address and IPv6 by /64', () => {
    expect(rateLimitKey('203.0.113.9')).toBe('203.0.113.9');
    expect(rateLimitKey('2001:db8:1:2:aaaa::1')).toBe('2001:0db8:0001:0002::/64');
    expect(rateLimitKey('2001:db8:1:2:ffff:ffff:ffff:ffff')).toBe(rateLimitKey('2001:db8:1:2::'));
    expect(rateLimitKey('2001:db8:1:3::1')).not.toBe(rateLimitKey('2001:db8:1:2::1'));
    expect(rateLimitKey('::1')).toBe('0000:0000:0000:0000::/64');
    expect(rateLimitKey('64:ff9b::192.0.2.1')).toBe('0064:ff9b:0000:0000::/64');
  });
});
