import { Body, Controller, Delete, Get, HttpCode, HttpStatus, Param, Post, Req } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import type { Request } from 'express';
import { type AuthContext, CurrentAuth, Public } from '../../platform/auth/auth.decorator.js';
import type { Env } from '../../platform/config/env.validation.js';
import { ParseUuidPipe } from '../../platform/http/parse-uuid.pipe.js';
import { clientIp, type ProxyTrust, proxyTrust } from '../../platform/http/client-ip.js';
import { AuthService } from './auth.service.js';
import { UserEnvelopeDto } from '../users/dto/user.dto.js';
import { MessageDto, SessionListDto, TokensDto } from './dto/auth-response.dto.js';
import { ChangePasswordDto } from './dto/change-password.dto.js';
import { EmailDto } from './dto/email.dto.js';
import { LoginDto } from './dto/login.dto.js';
import { RefreshDto } from './dto/refresh.dto.js';
import { RegisterDto } from './dto/register.dto.js';
import { ResetPasswordDto } from './dto/reset-password.dto.js';
import { VerifyEmailDto } from './dto/verify-email.dto.js';

const ACCEPTED: MessageDto = { message: 'If an account matches, an email is on its way.' };

/** Every route here is rate limited per client IP by rateLimitMiddleware, mounted in main.ts ahead of body parsing. */
@ApiTags('auth')
@Controller('auth')
export class AuthController {
  private readonly trust: ProxyTrust;

  constructor(
    private readonly auth: AuthService,
    config: ConfigService<Env, true>,
  ) {
    this.trust = proxyTrust(config.get('TRUSTED_PROXY_HOPS', { infer: true }), config.get('TRUSTED_PROXY_CIDRS', { infer: true }));
  }

  @Public()
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() dto: RegisterDto): Promise<UserEnvelopeDto> {
    return { user: await this.auth.register(dto.email, dto.password, dto.name) };
  }

  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  login(@Body() dto: LoginDto, @Req() req: Request): Promise<TokensDto> {
    return this.auth.login(dto.email, dto.password, { userAgent: req.get('user-agent') ?? null, ip: clientIp(req, this.trust) });
  }

  @Public()
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  refresh(@Body() dto: RefreshDto): Promise<TokensDto> {
    return this.auth.refresh(dto.refresh_token);
  }

  @ApiBearerAuth()
  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  logout(@CurrentAuth() auth: AuthContext): Promise<void> {
    return this.auth.logout(auth);
  }

  @ApiBearerAuth()
  @Post('logout-all')
  @HttpCode(HttpStatus.NO_CONTENT)
  logoutAll(@CurrentAuth() auth: AuthContext): Promise<void> {
    return this.auth.logoutAll(auth);
  }

  @Public()
  @Post('verify-email')
  @HttpCode(HttpStatus.NO_CONTENT)
  verifyEmail(@Body() dto: VerifyEmailDto): Promise<void> {
    return this.auth.verifyEmail(dto.token);
  }

  @Public()
  @Post('resend-verification')
  @HttpCode(HttpStatus.ACCEPTED)
  resendVerification(@Body() dto: EmailDto): MessageDto {
    this.auth.resendVerification(dto.email);
    return ACCEPTED;
  }

  @Public()
  @Post('forgot-password')
  @HttpCode(HttpStatus.ACCEPTED)
  forgotPassword(@Body() dto: EmailDto): MessageDto {
    this.auth.forgotPassword(dto.email);
    return ACCEPTED;
  }

  @Public()
  @Post('reset-password')
  @HttpCode(HttpStatus.NO_CONTENT)
  resetPassword(@Body() dto: ResetPasswordDto): Promise<void> {
    return this.auth.resetPassword(dto.token, dto.password);
  }

  @ApiBearerAuth()
  @Post('change-password')
  @HttpCode(HttpStatus.NO_CONTENT)
  changePassword(@CurrentAuth() auth: AuthContext, @Body() dto: ChangePasswordDto): Promise<void> {
    return this.auth.changePassword(auth, dto.current_password, dto.new_password);
  }

  @ApiBearerAuth()
  @Get('sessions')
  async listSessions(@CurrentAuth() auth: AuthContext): Promise<SessionListDto> {
    return { data: await this.auth.listSessions(auth) };
  }

  @ApiBearerAuth()
  @Delete('sessions/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  revokeSession(
    @CurrentAuth() auth: AuthContext,
    @Param('id', ParseUuidPipe) id: string,
  ): Promise<void> {
    return this.auth.revokeSession(auth, id);
  }
}
