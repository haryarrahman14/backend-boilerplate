import { pgSslOption, prismaCliUrl, sslModeOf, withoutSslParams } from './database-url.js';

const url = (q = '') => `postgres://u:p@db.example.com:5432/app${q}`;

describe('database-url', () => {
  it('reads sslmode and rejects modes we do not support', () => {
    expect(sslModeOf(url())).toBeUndefined();
    expect(sslModeOf(url('?sslmode=verify-full'))).toBe('verify-full');
    expect(() => sslModeOf(url('?sslmode=prefer'))).toThrow(/not supported/);
  });

  it('maps sslmode onto the node-postgres ssl option, never looser', () => {
    expect(pgSslOption(undefined)).toBe(false);
    expect(pgSslOption('disable')).toBe(false);
    expect(pgSslOption('require')).toEqual({ rejectUnauthorized: false });
    const ca = pgSslOption('verify-ca');
    expect(ca).toMatchObject({ rejectUnauthorized: true });
    expect(ca && ca.checkServerIdentity?.('other.host', {} as never)).toBeUndefined(); // CA only, any host name
    const full = pgSslOption('verify-full');
    expect(full).toEqual({ rejectUnauthorized: true }); // default checkServerIdentity: host name verified
  });

  it('strips TLS params so the driver cannot apply its own reading', () => {
    const stripped = withoutSslParams(url('?sslmode=require&sslrootcert=/x.pem&application_name=api'));
    expect(stripped).toBe(url('?application_name=api'));
  });

  it('translates for the Prisma CLI schema engine', () => {
    expect(prismaCliUrl(url('?sslmode=disable'))).toBe(url('?sslmode=disable'));
    expect(prismaCliUrl(url('?sslmode=require'))).toBe(url('?sslmode=require&sslaccept=accept_invalid_certs'));
    expect(prismaCliUrl(url('?sslmode=verify-full'))).toBe(url('?sslmode=require&sslaccept=strict'));
    expect(prismaCliUrl(url('?sslmode=verify-ca&sslaccept=accept_invalid_certs'))).toBe(url('?sslmode=require&sslaccept=strict'));
    expect(prismaCliUrl(url())).toBe(url());
  });
});
