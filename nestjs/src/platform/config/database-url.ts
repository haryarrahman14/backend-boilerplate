import type { ConnectionOptions } from 'node:tls';

// Pure helpers (unit tested, also imported by prisma.config.ts): we read `sslmode` ourselves instead of trusting
// node-postgres / pg-connection-string, which connect in plaintext when it is absent and announce that their
// reading of `require` will loosen. SPEC 2: honour disable, require, verify-ca and verify-full.

export const SSL_MODES = ['disable', 'require', 'verify-ca', 'verify-full'] as const;
export type SslMode = (typeof SSL_MODES)[number];

/** `sslmode` from a postgres URL; undefined when absent; throws on a value we do not support. */
export function sslModeOf(databaseUrl: string): SslMode | undefined {
  const mode = new URL(databaseUrl).searchParams.get('sslmode');
  if (mode === null) return undefined;
  if (!(SSL_MODES as readonly string[]).includes(mode)) {
    throw new Error(`sslmode=${mode} is not supported; use one of ${SSL_MODES.join(', ')}`);
  }
  return mode as SslMode;
}

/**
 * The `ssl` option for node-postgres:
 * - absent / disable → false (plaintext; production refuses an absent sslmode at startup)
 * - require          → encrypted, certificate not checked
 * - verify-ca        → encrypted, chain verified against the system trust store, host name not checked
 * - verify-full      → encrypted, chain and host name verified
 */
export function pgSslOption(mode: SslMode | undefined): false | ConnectionOptions {
  switch (mode) {
    case undefined:
    case 'disable':
      return false;
    case 'require':
      return { rejectUnauthorized: false };
    case 'verify-ca':
      return { rejectUnauthorized: true, checkServerIdentity: () => undefined };
    case 'verify-full':
      return { rejectUnauthorized: true };
  }
}

/** The URL without the TLS query params, so the driver cannot apply its own reading on top of our `ssl` option. */
export function withoutSslParams(databaseUrl: string): string {
  const url = new URL(databaseUrl);
  for (const key of ['sslmode', 'ssl', 'sslcert', 'sslkey', 'sslrootcert', 'uselibpqcompat']) url.searchParams.delete(key);
  return url.toString();
}

/**
 * The Prisma CLI (`make migrate`) talks to Postgres through its own schema engine, which understands
 * `sslmode=disable|prefer|require` plus `sslaccept=strict|accept_invalid_certs`. Map our modes onto that,
 * never looser: verify-ca and verify-full both become strict verification.
 */
export function prismaCliUrl(databaseUrl: string): string {
  const mode = sslModeOf(databaseUrl);
  const url = new URL(withoutSslParams(databaseUrl));
  url.searchParams.delete('sslaccept');
  if (mode === 'disable') url.searchParams.set('sslmode', 'disable');
  if (mode === 'require') {
    url.searchParams.set('sslmode', 'require');
    url.searchParams.set('sslaccept', 'accept_invalid_certs');
  }
  if (mode === 'verify-ca' || mode === 'verify-full') {
    url.searchParams.set('sslmode', 'require');
    url.searchParams.set('sslaccept', 'strict');
  }
  return url.toString();
}
