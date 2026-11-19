import { Body, Controller, Get, Patch } from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { type AuthContext, CurrentAuth } from '../../platform/auth/auth.decorator.js';
import { UpdateUserDto } from './dto/update-user.dto.js';
import { UserDto, UserEnvelopeDto } from './dto/user.dto.js';
import { UsersService } from './users.service.js';

@ApiTags('users')
@ApiBearerAuth()
@Controller('users')
export class UsersController {
  constructor(private readonly users: UsersService) {}

  @Get('me')
  me(@CurrentAuth() auth: AuthContext): UserEnvelopeDto {
    return { user: UserDto.from(auth.user) };
  }

  @Patch('me')
  async update(@CurrentAuth() auth: AuthContext, @Body() dto: UpdateUserDto): Promise<UserEnvelopeDto> {
    return { user: await this.users.updateName(auth.user.id, dto.name) };
  }
}
