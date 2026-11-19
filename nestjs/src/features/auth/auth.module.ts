import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller.js';
import { AuthService } from './auth.service.js';

// Rate limiting for every /auth/* path is mounted in main.ts (platform/rate-limit), before body parsing.
@Module({
  controllers: [AuthController],
  providers: [AuthService],
})
export class AuthModule {}
