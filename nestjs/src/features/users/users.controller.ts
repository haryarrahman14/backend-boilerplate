import { Body, Controller, Delete, Get, HttpCode, HttpStatus, Patch } from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { type AuthContext, CurrentAuth } from '../../platform/auth/auth.decorator.js';
import { DeleteAccountDto } from './dto/delete-account.dto.js';
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

  /** Delete your own account (password required): sessions, tokens, files and bucket objects go with it. */
  @Delete('me')
  @HttpCode(HttpStatus.NO_CONTENT)
  remove(@CurrentAuth() auth: AuthContext, @Body() dto: DeleteAccountDto): Promise<void> {
    return this.users.deleteOwnAccount(auth, dto.password);
  }
}
