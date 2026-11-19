import { randomUUID } from 'node:crypto';
import { Injectable, type OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Prisma } from '../../generated/prisma/client.js';
import type { AuthContext } from '../../platform/auth/auth.decorator.js';
import type { Env } from '../../platform/config/env.validation.js';
import { ApiError } from '../../platform/errors/api-error.js';
import { MailerService } from '../../platform/mailer/mailer.service.js';
import { PrismaService } from '../../platform/prisma/prisma.service.js';
import { EMAIL_REGEX } from '../../platform/validation/validation.decorator.js';
import { UserDto } from '../users/dto/user.dto.js';
import type { SessionDto, TokensDto } from './dto/auth-response.dto.js';
import { getDummyHash, hashPassword, verifyPassword } from './password.js';
import { formatRefreshToken, generateSecret, isReplayOfRotatedToken, parseRefreshToken, sha256Hex } from './tokens.js';

type TokenType = 'email_verification' | 'password_reset';
type Tx = Prisma.TransactionClient;

const VERIFY_TTL_SECONDS = 24 * 3600;
const RESET_TTL_SECONDS = 3600;
const UA_MAX = 255;

export interface ClientInfo {
  userAgent: string | null;
  ip: string | null; // parsed canonical IP, or null when even the socket peer does not parse
}

@Injectable()
export class AuthService implements OnModuleInit {
  private readonly accessTtl: number;
  private readonly refreshTtl: number;
  private readonly requireVerified: boolean;
  private readonly appUrl: string;
  private readonly tokenCooldown: number;

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly mailer: MailerService,
    config: ConfigService<Env, true>,
  ) {
    this.accessTtl = config.get('ACCESS_TOKEN_TTL_SECONDS', { infer: true });
    this.refreshTtl = config.get('REFRESH_TOKEN_TTL_SECONDS', { infer: true });
    this.requireVerified = config.get('AUTH_REQUIRE_VERIFIED_EMAIL', { infer: true });
    this.appUrl = config.get('APP_URL', { infer: true }).replace(/\/+$/, '');
    this.tokenCooldown = config.get('EMAIL_TOKEN_COOLDOWN_SECONDS', { infer: true });
  }

  async onModuleInit() {
    await getDummyHash(); // warm it so the first unknown-email login costs the same as the rest
  }

  // ---------- register / login / refresh ----------

  async register(email: string, password: string, name: string): Promise<UserDto> {
    const passwordHash = await hashPassword(password);
    let user;
    try {
      user = await this.prisma.user.create({ data: { email, passwordHash, name }, omit: { passwordHash: true } });
    } catch (err) {
      if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002') throw ApiError.emailTaken();
      throw err;
    }
    const userId = user.id;
    this.mailer.sendInBackground('email verification', async () => this.verificationMail(userId, email));
    return UserDto.from(user);
  }

  async login(email: string, password: string, client: ClientInfo): Promise<TokensDto> {
    // Presence-only validation (SPEC 4). An address that fails the strict syntax can't belong to any account,
    // so skip the lookup (that also keeps NULs away from Postgres) and fall through to the dummy verify.
    const user = EMAIL_REGEX.test(email) ? await this.prisma.user.findUnique({ where: { email } }) : null;
    if (!user) {
      await verifyPassword(await getDummyHash(), password); // same cost as a real check: no enumeration by timing
      throw ApiError.invalidCredentials();
    }
    if (!(await verifyPassword(user.passwordHash, password))) throw ApiError.invalidCredentials();
    // Only after the password matched, so this 403 never reveals anything to someone without the password.
    if (this.requireVerified && !user.emailVerifiedAt) throw ApiError.emailNotVerified();

    const sessionId = randomUUID();
    const secret = generateSecret();
    const userAgent = client.userAgent ? [...client.userAgent].slice(0, UA_MAX).join('') : null;
    // SPEC 4: the session is bound to the password that was verified. argon2 ran outside any transaction, so a
    // reset/change may have landed meanwhile; then this inserts 0 rows and the login fails like any other miss.
    // FOR SHARE makes it wait for an in-flight (uncommitted) password write and re-check the hash after it commits;
    // without it the SELECT reads the old hash and inserts a session the reset never revokes.
    const inserted = await this.prisma.$executeRaw`
      INSERT INTO auth.sessions (id, user_id, refresh_token_hash, user_agent, ip, expires_at)
      SELECT ${sessionId}::uuid, u.id, ${sha256Hex(secret)}, ${userAgent}, ${client.ip},
             now() + ${this.refreshTtl}::int * interval '1 second'
      FROM auth.users u WHERE u.id = ${user.id}::uuid AND u.password_hash = ${user.passwordHash}
      FOR SHARE`;
    if (inserted === 0) throw ApiError.invalidCredentials();
    return this.tokens(UserDto.from(user), sessionId, secret);
  }

  async refresh(refreshToken: string): Promise<TokensDto> {
    const parsed = parseRefreshToken(refreshToken);
    if (!parsed) throw ApiError.unauthorized();
    const { sessionId, secret } = parsed;
    const oldHash = sha256Hex(secret);
    const newSecret = generateSecret();

    // SPEC 4: rotation is one atomic statement (sliding expiry).
    const rotated = await this.prisma.$queryRaw<{ user_id: string }[]>`
      UPDATE auth.sessions
      SET refresh_token_hash = ${sha256Hex(newSecret)}, previous_refresh_token_hash = ${oldHash}, last_used_at = now(),
          expires_at = now() + ${this.refreshTtl}::int * interval '1 second'
      WHERE id = ${sessionId}::uuid AND refresh_token_hash = ${oldHash} AND revoked_at IS NULL AND expires_at > now()
      RETURNING user_id`;

    if (rotated.length === 0) {
      // Reuse detection (SPEC 4): revoke only when the presented secret is exactly the one the last rotation
      // replaced, which proves it was issued and then replayed. The session id is public, so a merely wrong or
      // invented secret must revoke nothing. The UPDATE re-checks the same condition, so this stays atomic.
      const session = await this.prisma.session.findUnique({
        where: { id: sessionId },
        select: { previousRefreshTokenHash: true, revokedAt: true, expiresAt: true },
      });
      if (isReplayOfRotatedToken(session, oldHash)) {
        await this.prisma.$executeRaw`
          UPDATE auth.sessions SET revoked_at = now()
          WHERE id = ${sessionId}::uuid AND previous_refresh_token_hash = ${oldHash} AND revoked_at IS NULL AND expires_at > now()`;
      }
      throw ApiError.unauthorized();
    }

    const user = await this.prisma.user.findUnique({ where: { id: rotated[0].user_id }, omit: { passwordHash: true } });
    if (!user) throw ApiError.unauthorized();
    return this.tokens(UserDto.from(user), sessionId, newSecret);
  }

  private async tokens(user: UserDto, sessionId: string, secret: string): Promise<TokensDto> {
    // Algorithm (HS256) and expiry come from JwtModule's signOptions; iat is added by jsonwebtoken.
    const accessToken = await this.jwt.signAsync({ sub: user.id, sid: sessionId });
    return {
      access_token: accessToken,
      refresh_token: formatRefreshToken(sessionId, secret),
      token_type: 'Bearer',
      expires_in: this.accessTtl,
      user,
    };
  }

  // ---------- logout / sessions ----------

  async logout(auth: AuthContext): Promise<void> {
    await this.prisma.session.updateMany({ where: { id: auth.sessionId, revokedAt: null }, data: { revokedAt: new Date() } });
  }

  async logoutAll(auth: AuthContext): Promise<void> {
    await this.prisma.session.updateMany({ where: { userId: auth.user.id, revokedAt: null }, data: { revokedAt: new Date() } });
  }

  async listSessions(auth: AuthContext): Promise<SessionDto[]> {
    const sessions = await this.prisma.session.findMany({
      where: { userId: auth.user.id, revokedAt: null, expiresAt: { gt: new Date() } },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
    });
    return sessions.map((s) => ({
      id: s.id,
      user_agent: s.userAgent,
      ip: s.ip,
      created_at: s.createdAt,
      last_used_at: s.lastUsedAt,
      current: s.id === auth.sessionId,
    }));
  }

  /** Own, active sessions only; anything else (someone else's, already revoked, unknown) is a 404. */
  async revokeSession(auth: AuthContext, sessionId: string): Promise<void> {
    const { count } = await this.prisma.session.updateMany({
      where: { id: sessionId, userId: auth.user.id, revokedAt: null, expiresAt: { gt: new Date() } },
      data: { revokedAt: new Date() },
    });
    if (count === 0) throw ApiError.notFound('Session not found');
  }

  // ---------- email verification ----------

  async verifyEmail(token: string): Promise<void> {
    await this.prisma.$transaction(async (tx) => {
      const userId = await this.consumeToken(tx, token, 'email_verification');
      await this.burnOtherTokens(tx, userId, 'email_verification');
      await tx.$executeRaw`
        UPDATE auth.users SET email_verified_at = now(), updated_at = now()
        WHERE id = ${userId}::uuid AND email_verified_at IS NULL`;
    });
  }

  /** Always resolves; the lookup and the mail happen in the background so timing reveals nothing. */
  resendVerification(email: string): void {
    this.mailer.sendInBackground('email verification', async () => {
      const user = await this.prisma.user.findUnique({ where: { email }, select: { id: true, email: true, emailVerifiedAt: true } });
      if (!user || user.emailVerifiedAt) return null;
      return this.verificationMail(user.id, user.email);
    });
  }

  private async verificationMail(userId: string, email: string) {
    const token = await this.issueToken(userId, 'email_verification', VERIFY_TTL_SECONDS);
    if (!token) return null; // cooldown: nothing issued, nothing sent
    return {
      to: email,
      subject: 'Verify your email address',
      text: `Confirm your email address by opening this link (valid for 24 hours):\n\n${this.appUrl}/verify-email?token=${token}\n\nIf you did not create this account, ignore this email and do not use the link.\n`,
    };
  }

  // ---------- password reset / change ----------

  /** Always resolves; same reasoning as resendVerification. */
  forgotPassword(email: string): void {
    this.mailer.sendInBackground('password reset', async () => {
      const user = await this.prisma.user.findUnique({ where: { email }, select: { id: true, email: true } });
      if (!user) return null;
      const token = await this.issueToken(user.id, 'password_reset', RESET_TTL_SECONDS);
      if (!token) return null; // cooldown: nothing issued, nothing sent
      return {
        to: user.email,
        subject: 'Reset your password',
        text: `Choose a new password by opening this link (valid for 1 hour):\n\n${this.appUrl}/reset-password?token=${token}\n\nIf you did not ask for this, ignore this email and do not use the link.\n`,
      };
    });
  }

  /** Password was validated by the DTO before we get here, so a weak password never burns the token. */
  async resetPassword(token: string, password: string): Promise<void> {
    const passwordHash = await hashPassword(password);
    await this.prisma.$transaction(async (tx) => {
      // Lock order (SPEC 4): user_tokens → users → sessions, the same as changePassword, so the two never deadlock.
      const userId = await this.consumeToken(tx, token, 'password_reset');
      // Any other live reset link (e.g. from a parallel forgot-password) dies with this one.
      await this.burnOtherTokens(tx, userId, 'password_reset');
      // The link proved ownership of the inbox, so the email counts as verified.
      await tx.$executeRaw`
        UPDATE auth.users SET password_hash = ${passwordHash}, email_verified_at = COALESCE(email_verified_at, now()), updated_at = now()
        WHERE id = ${userId}::uuid`;
      await tx.session.updateMany({ where: { userId, revokedAt: null }, data: { revokedAt: new Date() } });
    });
  }

  async changePassword(auth: AuthContext, currentPassword: string, newPassword: string): Promise<void> {
    const user = await this.prisma.user.findUnique({ where: { id: auth.user.id }, select: { id: true, passwordHash: true } });
    if (!user || !(await verifyPassword(user.passwordHash, currentPassword))) throw ApiError.invalidCredentials();
    const verifiedHash = user.passwordHash;
    const passwordHash = await hashPassword(newPassword); // argon2 runs before the transaction opens

    await this.prisma.$transaction(async (tx) => {
      // Lock order (SPEC 4): users → sessions here (no user_tokens). Reset links are deliberately left alone:
      // the mailbox owner must always be able to recover, whoever knows the password.
      // Compare-and-swap: only if the password is still the one we verified and this session is still live.
      // A reset (or revocation) that landed in between wins; we roll back and answer 401.
      const swapped = await tx.$executeRaw`
        UPDATE auth.users SET password_hash = ${passwordHash}, updated_at = now()
        WHERE id = ${user.id}::uuid AND password_hash = ${verifiedHash}
          AND EXISTS (SELECT 1 FROM auth.sessions WHERE id = ${auth.sessionId}::uuid AND revoked_at IS NULL AND expires_at > now())`;
      if (swapped === 0) throw ApiError.invalidCredentials();
      await tx.$executeRaw`
        UPDATE auth.sessions SET revoked_at = now()
        WHERE user_id = ${user.id}::uuid AND id <> ${auth.sessionId}::uuid AND revoked_at IS NULL`;
    });
  }

  // ---------- one-time tokens ----------

  /**
   * New token of a type, or null during the cooldown (then nothing is issued or sent). Serialised per user and
   * type by an advisory lock, so concurrent requests cannot race the cooldown check (SPEC 4).
   */
  private async issueToken(userId: string, type: TokenType, ttlSeconds: number): Promise<string | null> {
    const token = generateSecret();
    const issued = await this.prisma.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`${userId}:${type}`}))`;
      if (this.tokenCooldown > 0) {
        const recent = await tx.$queryRaw<{ one: number }[]>`
          SELECT 1 AS one FROM auth.user_tokens
          WHERE user_id = ${userId}::uuid AND type = ${type}
            AND created_at > now() - ${this.tokenCooldown}::int * interval '1 second'
          LIMIT 1`;
        if (recent.length > 0) return false;
      }
      // Older tokens stay valid (SPEC 4: issuing is anonymous, so invalidate-on-issue would let anyone kill the link
      // a user is about to click). Consuming one burns the rest instead.
      await tx.$executeRaw`
        INSERT INTO auth.user_tokens (user_id, type, token_hash, expires_at)
        VALUES (${userId}::uuid, ${type}, ${sha256Hex(token)}, now() + ${ttlSeconds}::int * interval '1 second')`;
      return true;
    });
    return issued ? token : null;
  }

  /** After a consume, in the same transaction: the user's other unused tokens of that type die too. */
  private async burnOtherTokens(tx: Tx, userId: string, type: TokenType): Promise<void> {
    await tx.$executeRaw`
      UPDATE auth.user_tokens SET used_at = now() WHERE user_id = ${userId}::uuid AND type = ${type} AND used_at IS NULL`;
  }

  /** Atomic single use (SPEC 4). Throws 400 invalid_token when unknown, used, expired or of another type. */
  private async consumeToken(tx: Tx, token: string, type: TokenType): Promise<string> {
    const rows = await tx.$queryRaw<{ user_id: string }[]>`
      UPDATE auth.user_tokens SET used_at = now()
      WHERE token_hash = ${sha256Hex(token)} AND type = ${type} AND used_at IS NULL AND expires_at > now()
      RETURNING user_id`;
    if (rows.length === 0) throw ApiError.invalidToken();
    return rows[0].user_id;
  }
}
