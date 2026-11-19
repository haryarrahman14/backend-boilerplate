import { type CanActivate, type ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ApiError } from '../errors/api-error.js';
import { type AuthenticatedRequest, type Role, ROLES_KEY } from './auth.decorator.js';

/** Global guard registered after JwtAuthGuard: enforces @Roles(...) against the role loaded from the DB. */
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const roles = this.reflector.getAllAndOverride<Role[] | undefined>(ROLES_KEY, [context.getHandler(), context.getClass()]);
    if (!roles?.length) return true;
    const role = context.switchToHttp().getRequest<AuthenticatedRequest>().auth?.user.role;
    if (!role) throw ApiError.unauthorized();
    if (!roles.includes(role)) throw ApiError.forbidden();
    return true;
  }
}
