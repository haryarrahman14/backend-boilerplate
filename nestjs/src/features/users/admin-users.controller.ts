import { Body, Controller, Delete, Get, HttpCode, HttpStatus, Param, Patch, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { type AuthContext, CurrentAuth, Roles } from '../../platform/auth/auth.decorator.js';
import { PaginationQueryDto } from '../../platform/http/pagination.dto.js';
import { ParseUuidPipe } from '../../platform/http/parse-uuid.pipe.js';
import { UpdateUserByAdminDto } from './dto/update-user-by-admin.dto.js';
import { UserListDto } from './dto/user-list.dto.js';
import { UserEnvelopeDto } from './dto/user.dto.js';
import { UsersService } from './users.service.js';

/**
 * Admin only. RolesGuard (a global guard) runs before every pipe, so a non-admin gets 403 before the id or the body
 * is even looked at; nobody but an admin ever sees a 404 or 422 here.
 */
@ApiTags('admin')
@ApiBearerAuth()
@Roles('admin')
@Controller('admin/users')
export class AdminUsersController {
  constructor(private readonly users: UsersService) {}

  /** Paginated list of every user, newest first. */
  @Get()
  list(@Query() query: PaginationQueryDto): Promise<UserListDto> {
    return this.users.list(query);
  }

  /** Change role and/or disable / re-enable. An admin cannot change their own role or disable themselves (403). */
  @Patch(':id')
  async update(
    @CurrentAuth() auth: AuthContext,
    @Param('id', ParseUuidPipe) id: string,
    @Body() dto: UpdateUserByAdminDto,
  ): Promise<UserEnvelopeDto> {
    return { user: await this.users.updateByAdmin(auth.user, id, dto) };
  }

  /** Delete the account, its sessions, tokens, files and bucket objects. Own id → 403 (use DELETE /users/me). */
  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  remove(@CurrentAuth() auth: AuthContext, @Param('id', ParseUuidPipe) id: string): Promise<void> {
    return this.users.deleteByAdmin(auth.user, id);
  }
}
