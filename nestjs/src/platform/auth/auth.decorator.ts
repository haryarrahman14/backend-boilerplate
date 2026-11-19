import { createParamDecorator, type ExecutionContext, SetMetadata } from '@nestjs/common';
import type { Request } from 'express';

export type Role = 'user' | 'admin';

/** What JwtAuthGuard attaches to the request: the user and session, freshly loaded from the DB. */
export interface AuthContext {
  sessionId: string;
  user: {
    id: string;
    email: string;
    name: string;
    role: Role;
    emailVerifiedAt: Date | null;
    createdAt: Date;
  };
}

export type AuthenticatedRequest = Request & { auth?: AuthContext };

export const IS_PUBLIC_KEY = 'isPublic';
/** Opt a route out of the global JwtAuthGuard. */
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);

export const ROLES_KEY = 'roles';
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);

/** `@CurrentAuth() auth: AuthContext` in a 🔒 handler. */
export const CurrentAuth = createParamDecorator((_: unknown, ctx: ExecutionContext): AuthContext => {
  const auth = ctx.switchToHttp().getRequest<AuthenticatedRequest>().auth;
  if (!auth) throw new Error('CurrentAuth used on a route without JwtAuthGuard');
  return auth;
});
