import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pgSslFromUrl, pgSslOption, prismaCliUrl, readRootCert, sslModeOf, sslRootCertOf, withoutSslParams } from './database-url.js';

const url = (q = '') => `postgres://u:p@db.example.com:5432/app${q}`;
const PEM = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n';

describe('database-url', () => {
  let dir: string;
  let ca: string;
  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'dburl-'));
    ca = join(dir, 'ca.crt');
    writeFileSync(ca, PEM);
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it('reads sslmode and rejects modes we do not support', () => {
    expect(sslModeOf(url())).toBeUndefined();
    expect(sslModeOf(url('?sslmode=verify-full'))).toBe('verify-full');
    expect(() => sslModeOf(url('?sslmode=prefer'))).toThrow(/not supported/);
  });

  it('reads sslrootcert as an absolute path; `system` means the system store', () => {
    expect(sslRootCertOf(url(`?sslrootcert=${ca}`))).toBe(ca);
    expect(sslRootCertOf(url('?sslrootcert=certs/ca.pem'))).toBe(resolve('certs/ca.pem'));
    expect(sslRootCertOf(url('?sslrootcert=system'))).toBeUndefined();
    expect(sslRootCertOf(url())).toBeUndefined();
  });

  it('refuses an unreadable or non-PEM sslrootcert with a clear message', () => {
    expect(() => readRootCert(join(dir, 'missing.crt'))).toThrow(/sslrootcert .*missing\.crt is not readable \(ENOENT\)/);
    const junk = join(dir, 'junk.txt');
    writeFileSync(junk, 'hello');
    expect(() => readRootCert(junk)).toThrow(/does not contain a PEM certificate/);
    expect(readRootCert(ca)).toBe(PEM);
  });

  it('maps sslmode (+ CA) onto the node-postgres ssl option, never looser', () => {
    expect(pgSslOption(undefined)).toBe(false);
    expect(pgSslOption('disable')).toBe(false);
    expect(pgSslOption('require')).toEqual({ rejectUnauthorized: false });
    const requireWithCa = pgSslOption('require', PEM);
    expect(requireWithCa).toMatchObject({ rejectUnauthorized: true, ca: PEM }); // libpq: like verify-ca
    const verifyCa = pgSslOption('verify-ca', PEM);
    expect(verifyCa).toMatchObject({ rejectUnauthorized: true, ca: PEM });
    expect(verifyCa && verifyCa.checkServerIdentity?.('other.host', {} as never)).toBeUndefined(); // CA only, any host
    expect(pgSslOption('verify-ca')).not.toHaveProperty('ca'); // system store
    expect(pgSslOption('verify-full', PEM)).toEqual({ rejectUnauthorized: true, ca: PEM }); // default host-name check
    expect(pgSslOption('verify-full')).toEqual({ rejectUnauthorized: true });
  });

  it('builds the ssl option straight from the URL, reading the CA file', () => {
    expect(pgSslFromUrl(url(`?sslmode=verify-full&sslrootcert=${ca}`))).toEqual({ rejectUnauthorized: true, ca: PEM });
    expect(pgSslFromUrl(url(`?sslmode=disable&sslrootcert=${join(dir, 'missing.crt')}`))).toBe(false);
    expect(() => pgSslFromUrl(url(`?sslmode=verify-full&sslrootcert=${join(dir, 'missing.crt')}`))).toThrow(/not readable/);
  });

  it('strips TLS params so the driver cannot apply its own reading', () => {
    expect(withoutSslParams(url('?sslmode=require&sslrootcert=/x.pem&application_name=api'))).toBe(url('?application_name=api'));
  });

  it('translates for the Prisma CLI schema engine (sslaccept + sslcert = root CA)', () => {
    const q = (s: string) => new URL(prismaCliUrl(url(s))).searchParams;
    expect(prismaCliUrl(url('?sslmode=disable'))).toBe(url('?sslmode=disable'));
    expect(Object.fromEntries(q('?sslmode=require'))).toEqual({ sslmode: 'require', sslaccept: 'accept_invalid_certs' });
    expect(Object.fromEntries(q('?sslmode=verify-full'))).toEqual({ sslmode: 'require', sslaccept: 'strict' });
    expect(Object.fromEntries(q(`?sslmode=verify-full&sslrootcert=${ca}`))).toEqual({ sslmode: 'require', sslaccept: 'strict', sslcert: ca });
    expect(Object.fromEntries(q(`?sslmode=verify-ca&sslrootcert=${ca}&sslaccept=accept_invalid_certs`))).toEqual({ sslmode: 'require', sslaccept: 'strict', sslcert: ca });
    expect(Object.fromEntries(q(`?sslmode=require&sslrootcert=${ca}`))).toEqual({ sslmode: 'require', sslaccept: 'strict', sslcert: ca });
    expect(prismaCliUrl(url())).toBe(url());
  });
});
