import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

// Pure helpers for the opaque tokens of SPEC 4. No framework imports, so they are unit tested directly.

// Lowercase canonical only: `ABC…` or dash-less variants are malformed and never reach reuse detection.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SECRET = /^[A-Za-z0-9_-]{43}$/; // 32 bytes, base64url without padding

/** 32 random bytes from the CSPRNG, base64url without padding (43 chars). */
export const generateSecret = (): string => randomBytes(32).toString('base64url');

/** Only this sha256 hex is ever stored. */
export const sha256Hex = (value: string): string => createHash('sha256').update(value, 'utf8').digest('hex');

/** Constant-time comparison of two hex digests. */
export const hashesEqual = (a: string, b: string): boolean => {
  const x = Buffer.from(a, 'utf8');
  const y = Buffer.from(b, 'utf8');
  return x.length === y.length && timingSafeEqual(x, y);
};

/**
 * Reuse-detection decision (SPEC 4): revoke only if the presented hash is exactly the one the last rotation
 * replaced on a live session. A never-issued secret (the session id is public) must revoke nothing.
 */
export function isReplayOfRotatedToken(
  session: { previousRefreshTokenHash: string | null; revokedAt: Date | null; expiresAt: Date } | null,
  presentedHash: string,
  now = new Date(),
): boolean {
  if (!session || session.revokedAt || session.expiresAt <= now || !session.previousRefreshTokenHash) return false;
  return hashesEqual(session.previousRefreshTokenHash, presentedHash);
}

/** Refresh token = `<session_id>.<secret>`. */
export const formatRefreshToken = (sessionId: string, secret: string): string => `${sessionId}.${secret}`;

/** Returns null for anything that is not exactly `<lowercase canonical uuid>.<43-char base64url secret>`. */
export function parseRefreshToken(token: unknown): { sessionId: string; secret: string } | null {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [sessionId, secret] = parts;
  if (!UUID.test(sessionId) || !SECRET.test(secret)) return null;
  return { sessionId, secret };
}
