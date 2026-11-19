import { Injectable } from '@nestjs/common';
import { ApiError } from '../../platform/errors/api-error.js';
import { pageMeta, type PaginationQueryDto } from '../../platform/http/pagination.dto.js';
import { PrismaService } from '../../platform/prisma/prisma.service.js';
import type { UserListDto } from './dto/user-list.dto.js';
import { UserDto } from './dto/user.dto.js';

@Injectable()
export class UsersService {
  constructor(private readonly prisma: PrismaService) {}

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
}
