import { Controller, Get, HttpStatus, Logger, Res } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import type { Response } from 'express';
import { Public } from '../../platform/auth/auth.decorator.js';
import { safeError } from '../../platform/logging/safe-error.js';
import { PrismaService } from '../../platform/prisma/prisma.service.js';

/** Served outside /api/v1 (excluded from the global prefix in main.ts). */
@ApiTags('health')
@Public()
@Controller('health')
export class HealthController {
  private readonly logger = new Logger(HealthController.name);

  constructor(private readonly prisma: PrismaService) {}

  /** Liveness: the process is up. No DB. */
  @Get()
  live(): { status: string } {
    return { status: 'ok' };
  }

  /** Readiness: 200 when `SELECT 1` works, else 503. */
  @Get('ready')
  async ready(@Res({ passthrough: true }) res: Response): Promise<{ status: string }> {
    try {
      await this.prisma.$queryRaw`SELECT 1`;
      return { status: 'ok' };
    } catch (err) {
      const detail = safeError(err);
      this.logger.warn({ msg: 'readiness check failed', error: detail instanceof Error ? detail.message : detail });
      res.status(HttpStatus.SERVICE_UNAVAILABLE);
      return { status: 'unavailable' };
    }
  }
}
