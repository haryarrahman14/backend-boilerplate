import { type CanActivate, type ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { ApiError } from '../errors/api-error.js';
import { requestContext } from '../logging/request-context.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { type AuthContext, type AuthenticatedRequest, IS_PUBLIC_KEY, type Role } from './auth.decorator.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const BEARER = /^Bearer ([A-Za-z0-9_\-.]+)$/i; // SPEC 4: scheme matched case-insensitively

interface SessionUserRow {
  id: string;
  email: string;
  name: string;
  role: Role;
  email_verified_at: Date | null;
  created_at: Date;
}

/**
 * Global guard (APP_GUARD): every route needs a valid access token unless marked @Public().
 * SPEC 4: HS256 pinned, `exp` required (`iat` is informational, not validated), then session + user loaded in ONE query so revocation is immediate
 * and the role always comes from the DB.
 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly jwt: JwtService,
    private readonly prisma: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [context.getHandler(), context.getClass()]);
    if (isPublic) return true;

    const req = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const token = BEARER.exec(req.headers.authorization ?? '')?.[1];
    if (!token) throw ApiError.unauthorized();

    let claims: { sub?: unknown; sid?: unknown; exp?: unknown };
    try {
      claims = await this.jwt.verifyAsync(token, { algorithms: ['HS256'] });
    } catch {
      throw ApiError.unauthorized();
    }
    const { sub, sid, exp } = claims;
    if (typeof exp !== 'number' || typeof sub !== 'string' || typeof sid !== 'string' || !UUID.test(sub) || !UUID.test(sid)) {
      throw ApiError.unauthorized();
    }

    const rows = await this.prisma.$queryRaw<SessionUserRow[]>`
      SELECT u.id, u.email, u.name, u.role, u.email_verified_at, u.created_at
      FROM auth.sessions s JOIN auth.users u ON u.id = s.user_id
      WHERE s.id = ${sid}::uuid AND s.user_id = ${sub}::uuid AND s.revoked_at IS NULL AND s.expires_at > now()
        AND u.disabled_at IS NULL`;
    const row = rows[0];
    if (!row) throw ApiError.unauthorized();

    const auth: AuthContext = {
      sessionId: sid,
      user: { id: row.id, email: row.email, name: row.name, role: row.role, emailVerifiedAt: row.email_verified_at, disabledAt: null, createdAt: row.created_at },
    };
    req.auth = auth;
    const ctx = requestContext.getStore();
    if (ctx) ctx.userId = row.id;
    return true;
  }
}
