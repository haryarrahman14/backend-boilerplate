import { createHash } from 'node:crypto';
import { formatRefreshToken, generateSecret, hashesEqual, isReplayOfRotatedToken, parseRefreshToken, sha256Hex } from './tokens.js';

const SID = '3f2b8c1e-9a4d-4e6f-8b7a-1c2d3e4f5a6b';

describe('tokens', () => {
  it('generates 32-byte base64url secrets without padding', () => {
    const a = generateSecret();
    const b = generateSecret();
    expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(Buffer.from(a, 'base64url')).toHaveLength(32);
    expect(a).not.toEqual(b);
  });

  it('hashes with sha256 hex', () => {
    expect(sha256Hex('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  it('hashes the base64url string as transmitted, not the decoded bytes (SPEC 4)', () => {
    const secret = generateSecret();
    expect(sha256Hex(secret)).toBe(createHash('sha256').update(secret).digest('hex'));
    expect(sha256Hex(secret)).not.toBe(createHash('sha256').update(Buffer.from(secret, 'base64url')).digest('hex'));
  });

  it('compares hashes in constant time and handles length mismatch', () => {
    const h = sha256Hex('x');
    expect(hashesEqual(h, sha256Hex('x'))).toBe(true);
    expect(hashesEqual(h, sha256Hex('y'))).toBe(false);
    expect(hashesEqual(h, h.slice(1))).toBe(false);
  });

  it('round-trips a refresh token', () => {
    const secret = generateSecret();
    expect(parseRefreshToken(formatRefreshToken(SID, secret))).toEqual({ sessionId: SID, secret });
  });

  it.each([
    ['not a string', 42],
    ['no dot', 'nope'],
    ['too many parts', `${SID}.${'A'.repeat(43)}.x`],
    ['not a uuid', `not-a-uuid.${'A'.repeat(43)}`],
    ['uppercase uuid', `${SID.toUpperCase()}.${'A'.repeat(43)}`],
    ['dash-less uuid', `${SID.replaceAll('-', '')}.${'A'.repeat(43)}`],
    ['short secret', `${SID}.${'A'.repeat(42)}`],
    ['long secret', `${SID}.${'A'.repeat(44)}`],
    ['bad alphabet', `${SID}.${'+'.repeat(43)}`],
    ['empty', ''],
  ])('rejects a malformed refresh token (%s)', (_, token) => {
    expect(parseRefreshToken(token)).toBeNull();
  });

  describe('reuse detection decision', () => {
    const now = new Date('2026-11-19T12:00:00Z');
    const prev = sha256Hex('previous-secret');
    const live = { previousRefreshTokenHash: prev, revokedAt: null, expiresAt: new Date('2026-12-01T00:00:00Z') };

    it('revokes on a replay of exactly the rotated-away secret', () => {
      expect(isReplayOfRotatedToken(live, prev, now)).toBe(true);
    });

    it('does not revoke for a never-issued secret (the session id is public)', () => {
      expect(isReplayOfRotatedToken(live, sha256Hex('A'.repeat(43)), now)).toBe(false);
    });

    it('does not revoke before the first rotation, or on a dead session', () => {
      expect(isReplayOfRotatedToken({ ...live, previousRefreshTokenHash: null }, prev, now)).toBe(false);
      expect(isReplayOfRotatedToken({ ...live, revokedAt: now }, prev, now)).toBe(false);
      expect(isReplayOfRotatedToken({ ...live, expiresAt: now }, prev, now)).toBe(false);
      expect(isReplayOfRotatedToken(null, prev, now)).toBe(false);
    });
  });
});
