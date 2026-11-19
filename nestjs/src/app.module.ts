import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_FILTER, APP_GUARD } from '@nestjs/core';
import { JwtModule } from '@nestjs/jwt';
import { AuthModule } from './features/auth/auth.module.js';
import { FilesModule } from './features/files/files.module.js';
import { HealthModule } from './features/health/health.module.js';
import { UsersModule } from './features/users/users.module.js';
import { JwtAuthGuard } from './platform/auth/jwt-auth.guard.js';
import { RolesGuard } from './platform/auth/roles.guard.js';
import { type Env, validate } from './platform/config/env.validation.js';
import { AllExceptionsFilter } from './platform/filters/all-exceptions.filter.js';
import { MailerModule } from './platform/mailer/mailer.module.js';
import { PrismaModule } from './platform/prisma/prisma.module.js';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, cache: true, ignoreEnvFile: true, validate }), // .env loaded in main.ts
    JwtModule.registerAsync({
      global: true,
      inject: [ConfigService],
      useFactory: (config: ConfigService<Env, true>) => ({
        secret: config.get('JWT_SECRET', { infer: true }),
        // SPEC 4: HS256 only, both ways (a token with alg=none or RS256 fails verification).
        signOptions: { algorithm: 'HS256', expiresIn: config.get('ACCESS_TOKEN_TTL_SECONDS', { infer: true }) },
        verifyOptions: { algorithms: ['HS256'] },
      }),
    }),
    PrismaModule,
    MailerModule,
    HealthModule,
    AuthModule,
    UsersModule,
    FilesModule,
  ],
  providers: [
    { provide: APP_FILTER, useClass: AllExceptionsFilter },
    // Order matters: authenticate first, then check roles.
    { provide: APP_GUARD, useClass: JwtAuthGuard },
    { provide: APP_GUARD, useClass: RolesGuard },
  ],
})
export class AppModule {}
