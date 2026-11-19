import { inspect } from 'node:util';
import { validate } from './env.validation.js';

const base = {
  DATABASE_URL: 'postgres://u:p@localhost:5432/db',
  JWT_SECRET: 'x'.repeat(32),
  S3_ENDPOINT: 'http://localhost:9000',
  S3_ACCESS_KEY_ID: 'k',
  S3_SECRET_ACCESS_KEY: 's',
  S3_BUCKET: 'b',
};

describe('env validation', () => {
  it('applies the spec defaults', () => {
    const env = validate({ ...base, SMTP_HOST: '' });
    expect(env).toMatchObject({
      PORT: 8080,
      ACCESS_TOKEN_TTL_SECONDS: 900,
      AUTH_REQUIRE_VERIFIED_EMAIL: false,
      RATE_LIMIT_AUTH_PER_MINUTE: 10,
      TRUSTED_PROXY_HOPS: 0,
      EMAIL_TOKEN_COOLDOWN_SECONDS: 60,
      S3_REGION: 'auto',
      SMTP_HOST: '',
      CORS_ORIGINS: ['http://localhost:3000'],
      UPLOAD_ALLOWED_TYPES: ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'],
    });
  });

  it('refuses a JWT_SECRET shorter than 32 characters', () => {
    expect(() => validate({ ...base, JWT_SECRET: 'x'.repeat(31) })).toThrow(/JWT_SECRET must be at least 32 characters/);
  });

  it('refuses missing required vars and bad values', () => {
    expect(() => validate({})).toThrow(/DATABASE_URL/);
    expect(() => validate({ ...base, PORT: 'abc' })).toThrow(/PORT/);
    expect(() => validate({ ...base, AUTH_REQUIRE_VERIFIED_EMAIL: 'yes' })).toThrow(/AUTH_REQUIRE_VERIFIED_EMAIL/);
    expect(() => validate({ ...base, TRUSTED_PROXY_HOPS: '-1' })).toThrow(/TRUSTED_PROXY_HOPS/);
    expect(() => validate({ ...base, CORS_ORIGINS: '*' })).toThrow(/CORS_ORIGINS/);
  });

  const production = {
    ...base,
    APP_ENV: 'production',
    APP_URL: 'https://app.example.com',
    DATABASE_URL: 'postgres://u:p@db.example.com:5432/app?sslmode=verify-full',
    S3_ENDPOINT: 'https://acct.r2.cloudflarestorage.com',
    SMTP_HOST: 'smtp.example.com',
  };

  it('accepts a complete production config', () => {
    expect(validate(production).APP_ENV).toBe('production');
    expect(validate({ ...production, DATABASE_URL: 'postgres://u:p@db/app?sslmode=disable' }).APP_ENV).toBe('production');
  });

  it('requires SMTP_HOST in production', () => {
    expect(() => validate({ ...production, SMTP_HOST: '' })).toThrow(/SMTP_HOST is required when APP_ENV=production/);
  });

  it('requires an explicit sslmode in production, and a supported one everywhere', () => {
    expect(() => validate({ ...production, DATABASE_URL: 'postgres://u:p@db/app' })).toThrow(/explicit sslmode/);
    expect(validate({ ...base, DATABASE_URL: 'postgres://u:p@db/app' }).APP_ENV).toBe('development');
    expect(() => validate({ ...base, DATABASE_URL: 'postgres://u:p@db/app?sslmode=prefer' })).toThrow(/sslmode=prefer is not supported/);
    expect(() => validate({ ...base, DATABASE_URL: 'postgres://u:p@db/app?sslmode=no-verify' })).toThrow(/not supported/);
  });

  it('refuses to start when the sslrootcert file cannot be read', () => {
    expect(() => validate({ ...base, DATABASE_URL: 'postgres://u:p@db/app?sslmode=verify-full&sslrootcert=/nonexistent/ca.crt' })).toThrow(
      /sslrootcert \/nonexistent\/ca\.crt is not readable/,
    );
  });

  it('requires https APP_URL and S3_ENDPOINT in production', () => {
    expect(() => validate({ ...production, APP_URL: 'http://app.example.com' })).toThrow(/APP_URL must be https/);
    expect(() => validate({ ...production, S3_ENDPOINT: 'http://minio:9000' })).toThrow(/S3_ENDPOINT must be https/);
  });

  it('requires valid TRUSTED_PROXY_CIDRS when TRUSTED_PROXY_HOPS > 0', () => {
    expect(() => validate({ ...base, TRUSTED_PROXY_HOPS: '1' })).toThrow(/TRUSTED_PROXY_CIDRS is required/);
    expect(() => validate({ ...base, TRUSTED_PROXY_HOPS: '1', TRUSTED_PROXY_CIDRS: '10.0.0.0/33' })).toThrow(/invalid CIDR/);
    expect(() => validate({ ...base, TRUSTED_PROXY_HOPS: '33', TRUSTED_PROXY_CIDRS: '10.0.0.0/8' })).toThrow(/TRUSTED_PROXY_HOPS/);
    const env = validate({ ...base, TRUSTED_PROXY_HOPS: '1', TRUSTED_PROXY_CIDRS: '127.0.0.1/32, ::1/128' });
    expect(env.TRUSTED_PROXY_CIDRS).toEqual(['127.0.0.1/32', '::1/128']);
  });

  it('refuses the placeholder JWT_SECRET in production, keeps the secret byte for byte', () => {
    expect(() => validate({ ...production, JWT_SECRET: 'change-me-change-me-change-me-change-me' })).toThrow(/change-me/);
    expect(validate({ ...base, JWT_SECRET: ` ${'x'.repeat(32)} ` }).JWT_SECRET).toBe(` ${'x'.repeat(32)} `);
  });

  it('never prints secrets', () => {
    const env = validate({ ...base, JWT_SECRET: 's3cret-'.repeat(6) });
    expect(JSON.stringify(env)).not.toContain('s3cret');
    expect(inspect(env)).not.toContain('s3cret');
    expect(inspect(env)).not.toContain('postgres://u:p');
  });

  it('parses booleans and lists strictly', () => {
    const env = validate({ ...base, AUTH_REQUIRE_VERIFIED_EMAIL: 'true', CORS_ORIGINS: 'http://a.test, http://b.test' });
    expect(env.AUTH_REQUIRE_VERIFIED_EMAIL).toBe(true);
    expect(env.CORS_ORIGINS).toEqual(['http://a.test', 'http://b.test']);
  });
});
