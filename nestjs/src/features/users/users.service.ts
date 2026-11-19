import { Injectable } from '@nestjs/common';
import type { AuthContext } from '../../platform/auth/auth.decorator.js';
import { ApiError } from '../../platform/errors/api-error.js';
import { pageMeta, type PaginationQueryDto } from '../../platform/http/pagination.dto.js';
import { PrismaService } from '../../platform/prisma/prisma.service.js';
import { StorageService } from '../../platform/storage/storage.service.js';
import { verifyPassword } from '../auth/password.js';
import { refuseSelfChange } from './admin-rules.js';
import type { UpdateUserByAdminDto } from './dto/update-user-by-admin.dto.js';
import type { UserListDto } from './dto/user-list.dto.js';
import { UserDto } from './dto/user.dto.js';

const FILE_PAGE = 1000; // = the S3 DeleteObjects limit

@Injectable()
export class UsersService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly storage: StorageService,
  ) {}

  async updateName(userId: string, name: string | undefined): Promise<UserDto> {
    const user =
      name === undefined
        ? await this.prisma.user.findUnique({ where: { id: userId }, omit: { passwordHash: true } })
        : await this.prisma.user.update({ where: { id: userId }, data: { name, updatedAt: new Date() }, omit: { passwordHash: true } });
    if (!user) throw ApiError.unauthorized(); // deleted between the guard and here
    return UserDto.from(user);
  }

  async list(q: PaginationQueryDto): Promise<UserListDto> {
    const [users, total] = await this.prisma.$transaction([
      this.prisma.user.findMany({ omit: { passwordHash: true }, orderBy: [{ createdAt: 'desc' }, { id: 'desc' }], skip: q.skip, take: q.per_page }),
      this.prisma.user.count(),
    ]);
    return { data: users.map((u) => UserDto.from(u)), meta: pageMeta(q, total) };
  }

  // ---------- account deletion ----------

  /** DELETE /users/me: the password is checked like a login (argon2 queue, never more than 128 code points). */
  async deleteOwnAccount(auth: AuthContext, password: string): Promise<void> {
    const user = await this.prisma.user.findUnique({ where: { id: auth.user.id }, select: { passwordHash: true } });
    if (!user || !(await verifyPassword(user.passwordHash, password))) throw ApiError.invalidCredentials();
    await this.deleteAccount(auth.user.id);
  }

  /** DELETE /admin/users/{id}. */
  async deleteByAdmin(actor: AuthContext['user'], id: string): Promise<void> {
    const refusal = refuseSelfChange(actor, id, 'delete');
    if (refusal) throw ApiError.forbidden(refusal);
    const exists = await this.prisma.user.findUnique({ where: { id }, select: { id: true } });
    if (!exists) throw ApiError.notFound('User not found');
    await this.deleteAccount(id);
  }

  /**
   * SPEC 5 "Deleting a user", in this order: (1) revoke every session, committed on its own so access stops even if
   * a later step fails; (2) delete every bucket object of the user's files, page by page, and let a bucket error
   * surface as a 500 with the user row still there, so the call can simply be repeated; (3) delete the users row,
   * which cascades to sessions, tokens and file rows.
   * Accepted ceiling: an upload URL issued before the deletion can still create an orphan object for up to 15
   * minutes; a bucket lifecycle rule on `users/` cleans those up.
   */
  private async deleteAccount(userId: string): Promise<void> {
    await this.prisma.$executeRaw`
      UPDATE auth.sessions SET revoked_at = now() WHERE user_id = ${userId}::uuid AND revoked_at IS NULL`;

    let cursor: string | undefined;
    for (;;) {
      const page = await this.prisma.file.findMany({
        where: { userId },
        select: { id: true, key: true },
        orderBy: { id: 'asc' },
        take: FILE_PAGE,
        ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
      });
      await this.storage.deleteMany(page.map((f) => f.key));
      if (page.length < FILE_PAGE) break;
      cursor = page[page.length - 1].id;
    }

    await this.prisma.user.deleteMany({ where: { id: userId } });
  }

  // ---------- admin changes ----------

  /** PATCH /admin/users/{id}: role and/or disabled; none → 200 unchanged. */
  async updateByAdmin(actor: AuthContext['user'], id: string, change: UpdateUserByAdminDto): Promise<UserDto> {
    const refusal = refuseSelfChange(actor, id, change);
    if (refusal) throw ApiError.forbidden(refusal);

    const user = await this.prisma.$transaction(async (tx) => {
      // Lock order users → sessions (SPEC 4). The row lock serialises concurrent admin edits of one user.
      const locked = await tx.$queryRaw<{ id: string }[]>`SELECT id FROM auth.users WHERE id = ${id}::uuid FOR UPDATE`;
      if (locked.length === 0) throw ApiError.notFound('User not found');
      if (change.role != null) {
        await tx.$executeRaw`UPDATE auth.users SET role = ${change.role}, updated_at = now() WHERE id = ${id}::uuid`;
      }
      if (change.disabled === true) {
        // Disabling and revoking every session happen in this one transaction (SPEC 5).
        await tx.$executeRaw`
          UPDATE auth.users SET disabled_at = COALESCE(disabled_at, now()), updated_at = now() WHERE id = ${id}::uuid`;
        await tx.$executeRaw`
          UPDATE auth.sessions SET revoked_at = now() WHERE user_id = ${id}::uuid AND revoked_at IS NULL`;
      } else if (change.disabled === false) {
        await tx.$executeRaw`UPDATE auth.users SET disabled_at = NULL, updated_at = now() WHERE id = ${id}::uuid`;
      }
      return tx.user.findUniqueOrThrow({ where: { id }, omit: { passwordHash: true } });
    });
    return UserDto.from(user);
  }
}
