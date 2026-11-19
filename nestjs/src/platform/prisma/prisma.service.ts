import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '../../generated/prisma/client.js';
import { pgSslFromUrl, withoutSslParams } from '../config/database-url.js';
import type { Env } from '../config/env.validation.js';

// $disconnect is called from main.ts on shutdown, after the HTTP server has drained (Nest runs
// onModuleDestroy *before* closing the server, which would cut in-flight requests off the pool).
@Injectable()
export class PrismaService extends PrismaClient {
  constructor(config: ConfigService<Env, true>) {
    const url = config.get('DATABASE_URL', { infer: true });
    super({
      adapter: new PrismaPg({
        // TLS from our own reading of sslmode (platform/config/database-url.ts), never the driver's.
        connectionString: withoutSslParams(url),
        ssl: pgSslFromUrl(url), // sslmode + sslrootcert (CA file) read by us
        connectionTimeoutMillis: 5_000, // pg waits forever by default; readiness must fail fast instead
      }),
    });
  }
}
