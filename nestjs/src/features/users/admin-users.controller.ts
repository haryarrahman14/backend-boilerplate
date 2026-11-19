import { Controller, Get, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { Roles } from '../../platform/auth/auth.decorator.js';
import { PaginationQueryDto } from '../../platform/http/pagination.dto.js';
import { UserListDto } from './dto/user-list.dto.js';
import { UsersService } from './users.service.js';

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
}
