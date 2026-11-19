import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { ConnectionOptions } from 'node:tls';

// Pure helpers (unit tested, also imported by prisma.config.ts): we read `sslmode` and `sslrootcert` ourselves
// instead of trusting node-postgres / pg-connection-string, which connect in plaintext when sslmode is absent,
// announce that their reading of `require` will loosen, and silently replace an `ssl` object we pass when the URL
// carries TLS params. SPEC 2: honour disable, require, verify-ca and verify-full.

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
 * libpq's `sslrootcert`: a CA file to verify the server against instead of the system trust store, as an absolute
 * path (relative paths resolve against the working directory, like libpq). `system`, libpq's spelling for "the
 * system store", and an absent value both mean undefined.
 */
export function sslRootCertOf(databaseUrl: string): string | undefined {
  const value = new URL(databaseUrl).searchParams.get('sslrootcert');
  if (!value || value === 'system') return undefined;
  return resolve(value);
}

/** Reads the sslrootcert file; throws a clear message when it is missing or unreadable (startup refuses then). */
export function readRootCert(path: string, read: (p: string) => string = (p) => readFileSync(p, 'utf8')): string {
  let pem: string;
  try {
    pem = read(path);
  } catch (err) {
    throw new Error(`sslrootcert ${path} is not readable (${(err as NodeJS.ErrnoException).code ?? (err as Error).message})`);
  }
  if (!pem.includes('-----BEGIN CERTIFICATE-----')) throw new Error(`sslrootcert ${path} does not contain a PEM certificate`);
  return pem;
}

/**
 * The `ssl` option for node-postgres:
 * - absent / disable → false (plaintext; production refuses an absent sslmode at startup)
 * - require          → encrypted, certificate not checked; with a root cert, checked like verify-ca (as libpq does)
 * - verify-ca        → encrypted, chain verified against `ca` (or the system store), host name not checked
 * - verify-full      → encrypted, chain and host name verified
 */
export function pgSslOption(mode: SslMode | undefined, ca?: string): false | ConnectionOptions {
  const anyHost = { checkServerIdentity: () => undefined };
  switch (mode) {
    case undefined:
    case 'disable':
      return false;
    case 'require':
      return ca ? { rejectUnauthorized: true, ca, ...anyHost } : { rejectUnauthorized: false };
    case 'verify-ca':
      return { rejectUnauthorized: true, ...(ca ? { ca } : {}), ...anyHost };
    case 'verify-full':
      return { rejectUnauthorized: true, ...(ca ? { ca } : {}) };
  }
}

/** The adapter's `ssl` option straight from DATABASE_URL (reads the sslrootcert file if there is one). */
export function pgSslFromUrl(databaseUrl: string): false | ConnectionOptions {
  const mode = sslModeOf(databaseUrl);
  const rootCert = sslRootCertOf(databaseUrl);
  if (mode === undefined || mode === 'disable') return false;
  return pgSslOption(mode, rootCert ? readRootCert(rootCert) : undefined);
}

/** The URL without the TLS query params, so the driver cannot apply its own reading on top of our `ssl` option. */
export function withoutSslParams(databaseUrl: string): string {
  const url = new URL(databaseUrl);
  for (const key of ['sslmode', 'ssl', 'sslcert', 'sslkey', 'sslrootcert', 'uselibpqcompat']) url.searchParams.delete(key);
  return url.toString();
}

/**
 * The Prisma CLI (`make migrate`) talks to Postgres through its own schema engine, which understands
 * `sslmode=disable|prefer|require`, `sslaccept=strict|accept_invalid_certs` and `sslcert=<root CA file>` (the
 * server's root certificate; relative paths would resolve against the prisma folder, so we pass it absolute).
 * Map our modes onto that, never looser: verify-ca and verify-full both become strict verification, against
 * sslrootcert when given, else the system store. Known ceiling: the engine has no CA-only mode, so verify-ca
 * against an address that is not in the certificate is refused by the CLI even though the app accepts it.
 */
export function prismaCliUrl(databaseUrl: string): string {
  const mode = sslModeOf(databaseUrl);
  const rootCert = sslRootCertOf(databaseUrl);
  const url = new URL(withoutSslParams(databaseUrl));
  url.searchParams.delete('sslaccept');
  if (mode === 'disable') url.searchParams.set('sslmode', 'disable');
  if (mode === 'require' && !rootCert) {
    url.searchParams.set('sslmode', 'require');
    url.searchParams.set('sslaccept', 'accept_invalid_certs');
  }
  if (mode === 'verify-ca' || mode === 'verify-full' || (mode === 'require' && rootCert)) {
    url.searchParams.set('sslmode', 'require');
    url.searchParams.set('sslaccept', 'strict');
    if (rootCert) url.searchParams.set('sslcert', rootCert);
  }
  return url.toString();
}
