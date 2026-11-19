import { inspect } from 'node:util';
import { parseCidrs } from '../http/client-ip.js';
import { sslModeOf } from './database-url.js';
import { plainToInstance, Transform, Type } from 'class-transformer';
import {
  ArrayNotEmpty,
  IsBoolean,
  IsIn,
  IsInt,
  IsNotEmpty,
  IsString,
  IsUrl,
  Max,
  Min,
  MinLength,
  validateSync,
  type ValidationError,
} from 'class-validator';

// Env vars from SPEC.md section 2. Defaults live on the class; `validate` runs once at startup.
const toBool = ({ obj, key }: { obj: Record<string, unknown>; key: string }): unknown => {
  const raw = obj[key];
  if (raw === 'true' || raw === true) return true;
  if (raw === 'false' || raw === false) return false;
  return raw;
};
const toList = ({ value }: { value: unknown }): unknown =>
  typeof value === 'string'
    ? value
        .split(',')
        .map((v) => v.trim())
        .filter(Boolean)
    : value;

export class Env {
  @Type(() => Number) @IsInt() @Min(1) @Max(65535)
  PORT = 8080;

  @IsIn(['development', 'production'])
  APP_ENV: 'development' | 'production' = 'development';

  @IsUrl({ require_tld: false, require_protocol: true })
  APP_URL = 'http://localhost:3000';

  @IsString() @IsNotEmpty()
  DATABASE_URL: string;

  @IsString() @MinLength(32, { message: 'JWT_SECRET must be at least 32 characters' })
  JWT_SECRET: string;

  @Type(() => Number) @IsInt() @Min(1)
  ACCESS_TOKEN_TTL_SECONDS = 900;

  @Type(() => Number) @IsInt() @Min(1)
  REFRESH_TOKEN_TTL_SECONDS = 2592000;

  @Transform(toBool) @IsBoolean()
  AUTH_REQUIRE_VERIFIED_EMAIL = false;

  @Type(() => Number) @IsInt() @Min(1)
  RATE_LIMIT_AUTH_PER_MINUTE = 10;

  /** Reverse proxies in front of the app; the client IP is the N-th X-Forwarded-For entry from the right. */
  @Type(() => Number) @IsInt() @Min(0) @Max(32)
  TRUSTED_PROXY_HOPS = 0;

  /** CIDRs of those proxies; X-Forwarded-For is honoured only from a peer inside them. Required when HOPS > 0. */
  @Transform(toList) @IsString({ each: true })
  TRUSTED_PROXY_CIDRS: string[] = [];

  @Type(() => Number) @IsInt() @Min(0)
  EMAIL_TOKEN_COOLDOWN_SECONDS = 60;

  @Transform(toList) @ArrayNotEmpty()
  @IsUrl({ require_tld: false, require_protocol: true }, { each: true, message: 'CORS_ORIGINS must be a comma separated list of origins (no *)' })
  CORS_ORIGINS: string[] = ['http://localhost:3000'];

  @IsString()
  SMTP_HOST = '';

  @Type(() => Number) @IsInt() @Min(1) @Max(65535)
  SMTP_PORT = 1025;

  @IsString()
  SMTP_USER = '';

  @IsString()
  SMTP_PASS = '';

  @IsString() @IsNotEmpty()
  MAIL_FROM = 'no-reply@example.com';

  @IsUrl({ require_tld: false, require_protocol: true })
  S3_ENDPOINT: string;

  @IsString() @IsNotEmpty()
  S3_REGION = 'auto';

  @IsString() @IsNotEmpty()
  S3_ACCESS_KEY_ID: string;

  @IsString() @IsNotEmpty()
  S3_SECRET_ACCESS_KEY: string;

  @IsString() @IsNotEmpty()
  S3_BUCKET: string;

  @Type(() => Number) @IsInt() @Min(1)
  UPLOAD_MAX_BYTES = 10485760;

  @Transform(toList) @ArrayNotEmpty() @IsString({ each: true })
  UPLOAD_ALLOWED_TYPES: string[] = ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];
}

const SECRET_KEYS = new Set(['DATABASE_URL', 'JWT_SECRET', 'SMTP_PASS', 'S3_SECRET_ACCESS_KEY']);

/** SPEC 4: the config is never printable with its secrets (console.log / util.inspect / JSON.stringify). */
function redactWhenPrinted(env: Env): Env {
  const redacted = () => Object.fromEntries(Object.entries(env).map(([k, v]) => [k, SECRET_KEYS.has(k) && v ? '[redacted]' : v]));
  // Non-enumerable, so they do not show up as config keys.
  Object.defineProperty(env, 'toJSON', { value: redacted });
  Object.defineProperty(env, inspect.custom, { value: redacted });
  return env;
}

const KEYS = Object.keys(new Env()).concat(['DATABASE_URL', 'JWT_SECRET', 'S3_ENDPOINT', 'S3_ACCESS_KEY_ID', 'S3_SECRET_ACCESS_KEY', 'S3_BUCKET']);

// One message per variable.
const describe = (errors: ValidationError[]): string[] =>
  errors.map((e) => {
    if (e.value === undefined) return `${e.property} is required`;
    const m = Object.values(e.constraints ?? {}).at(-1) ?? 'is invalid';
    return m.startsWith(e.property) ? m : `${e.property}: ${m}`;
  });

/** Rules spanning several variables, or that the decorators cannot express (SPEC 2). */
function crossFieldProblems(env: Env): string[] {
  const problems: string[] = [];
  const production = env.APP_ENV === 'production';
  if (typeof env.DATABASE_URL === 'string' && env.DATABASE_URL) {
    try {
      const mode = sslModeOf(env.DATABASE_URL);
      if (production && mode === undefined) {
        problems.push('DATABASE_URL must carry an explicit sslmode in production (verify-full recommended, disable to opt out)');
      }
    } catch (err) {
      problems.push(`DATABASE_URL: ${(err as Error).message.replace(/^Invalid URL.*/, 'not a valid URL')}`);
    }
  }
  if (production) {
    if (typeof env.APP_URL === 'string' && !env.APP_URL.startsWith('https://')) problems.push('APP_URL must be https:// in production');
    if (typeof env.S3_ENDPOINT === 'string' && !env.S3_ENDPOINT.startsWith('https://')) problems.push('S3_ENDPOINT must be https:// in production');
  }
  if (Array.isArray(env.TRUSTED_PROXY_CIDRS)) {
    try {
      parseCidrs(env.TRUSTED_PROXY_CIDRS);
    } catch (err) {
      problems.push(`TRUSTED_PROXY_CIDRS: ${(err as Error).message}`);
    }
    if (env.TRUSTED_PROXY_HOPS > 0 && env.TRUSTED_PROXY_CIDRS.length === 0) {
      problems.push('TRUSTED_PROXY_CIDRS is required when TRUSTED_PROXY_HOPS > 0');
    }
  }
  return problems;
}

/** Passed to ConfigModule.forRoot({ validate }). Throws (and the app refuses to start) on any bad value. */
export function validate(raw: Record<string, unknown>): Env {
  // Only our own vars, and an empty value means "use the default" (common in .env files).
  const picked = Object.fromEntries(KEYS.filter((k) => raw[k] !== undefined && raw[k] !== '').map((k) => [k, raw[k]]));
  const env = plainToInstance(Env, picked);
  const problems = describe(validateSync(env, { skipMissingProperties: false }));
  // SPEC 2: the "log the email" fallback would put one-time tokens in production logs.
  if (env.APP_ENV === 'production' && !env.SMTP_HOST) problems.push('SMTP_HOST is required when APP_ENV=production');
  if (env.APP_ENV === 'production' && env.JWT_SECRET?.includes('change-me')) {
    problems.push('JWT_SECRET still contains the .env.example placeholder ("change-me")');
  }
  problems.push(...crossFieldProblems(env));
  if (problems.length > 0) {
    throw new Error(`Invalid configuration:\n  - ${problems.join('\n  - ')}`);
  }
  return redactWhenPrinted(env);
}
