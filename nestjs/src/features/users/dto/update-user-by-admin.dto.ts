import { IsBoolean, IsIn, IsOptional } from 'class-validator';

/** Body of PATCH /admin/users/{id}. Both optional; absent or null → that field does not change. */
export class UpdateUserByAdminDto {
  /** @example admin */
  @IsOptional() @IsIn(['user', 'admin'], { message: 'role must be one of: user, admin' })
  role?: 'user' | 'admin' | null;

  /** true disables the account and revokes every session; false re-enables it. */
  @IsOptional() @IsBoolean()
  disabled?: boolean | null;
}
