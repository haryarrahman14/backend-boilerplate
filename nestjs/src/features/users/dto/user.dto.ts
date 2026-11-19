import type { Role } from '../../../platform/auth/auth.decorator.js';

interface UserRow {
  id: string;
  email: string;
  name: string;
  role: string;
  emailVerifiedAt: Date | null;
  createdAt: Date;
}

/** The `user` object of SPEC 5, the only shape a user ever leaves the API in (never the hash). */
export class UserDto {
  id: string;
  email: string;
  name: string;
  /** @example user */
  role: Role;
  email_verified: boolean;
  created_at: Date;

  static from(u: UserRow): UserDto {
    return {
      id: u.id,
      email: u.email,
      name: u.name,
      role: u.role as Role, // DB CHECK constraint guarantees 'user' | 'admin'
      email_verified: u.emailVerifiedAt !== null,
      created_at: u.createdAt,
    };
  }
}

/** `{ "user": {...} }` response body. */
export class UserEnvelopeDto {
  user: UserDto;
}
