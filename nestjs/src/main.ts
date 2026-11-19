import 'reflect-metadata';
import { Logger, ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import type { ValidationError } from 'class-validator';
import type { NextFunction, Request, Response } from 'express';
import { type Env, validate } from './platform/config/env.validation.js';
import { ApiError } from './platform/errors/api-error.js';
import { JsonLogger } from './platform/logging/json.logger.js';
import { requestMiddleware } from './platform/http/request.middleware.js';
import { MailerService } from './platform/mailer/mailer.service.js';
import { PrismaService } from './platform/prisma/prisma.service.js';
import { argon2Queue, threadpoolSize } from './features/auth/password.js';
import { rateLimitMiddleware } from './platform/rate-limit/rate-limit.middleware.js';
import { proxyTrust } from './platform/http/client-ip.js';

const API_PREFIX = 'api/v1';

const toDetails = (errors: ValidationError[], parent = '') =>
  errors.flatMap((e): { field: string; message: string }[] => {
    const field = parent ? `${parent}.${e.property}` : e.property || 'body';
    const own = Object.values(e.constraints ?? {}).slice(0, 1).map((message) => ({ field, message }));
    return own.concat(e.children?.length ? toDetails(e.children, field) : []);
  });

/** SPEC 1: JSON only. A request that carries a body in another content type is a 400, not a silent empty body. */
function jsonOnly(req: Request, res: Response, next: NextFunction) {
  const hasBody = req.headers['transfer-encoding'] !== undefined || Number(req.headers['content-length'] ?? 0) > 0;
  if (hasBody && !req.is('application/json')) {
    res.status(400).json(ApiError.badRequest('Content-Type must be application/json').toBody());
    return;
  }
  next();
}

/** Path of the first string (key or value) that is not well-formed Unicode, e.g. a lone surrogate. */
function malformedString(value: unknown, path: string): string | null {
  if (typeof value === 'string') return value.isWellFormed() ? null : path;
  if (value === null || typeof value !== 'object') return null;
  for (const [k, v] of Object.entries(value)) {
    const child = path ? `${path}.${k}` : k;
    if (!k.isWellFormed()) return child;
    const hit = malformedString(v, child);
    if (hit) return hit;
  }
  return null;
}

/**
 * SPEC 1: valid JSON that is not an object (`[1,2]`, `null`, `"x"`) is a 422, like any other wrong shape; so is
 * any string that is not well-formed Unicode (it would crash validators or be stored as U+FFFD).
 */
function objectBodyOnly(req: Request, res: Response, next: NextFunction) {
  const hasBody = req.headers['transfer-encoding'] !== undefined || req.headers['content-length'] !== undefined;
  const parsed = hasBody && req.is('application/json');
  const body: unknown = req.body;
  if (parsed && (body === null || typeof body !== 'object' || Array.isArray(body))) {
    res.status(422).json(ApiError.validation([{ field: 'body', message: 'body must be a JSON object' }]).toBody());
    return;
  }
  const bad = parsed ? malformedString(body, '') : null;
  if (bad) {
    res.status(422).json(ApiError.validation([{ field: bad, message: `${bad} is not well-formed Unicode` }]).toBody());
    return;
  }
  next();
}

async function bootstrap() {
  // Load .env (real env vars win) and validate up front, so a bad config stops the process with a clear
  // message before anything else starts. ConfigModule then validates the same process.env again.
  try {
    process.loadEnvFile();
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
  }
  validate(process.env);
  // Imported only now: evaluating app.module.ts kicks off ConfigModule.forRoot's (async) validation.
  const { AppModule } = await import('./app.module.js');
  const logger = new Logger('Bootstrap');
  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    logger: new JsonLogger(),
    bodyParser: false, // registered below with the spec's 1 MB limit and JSON only
    abortOnError: false,
  });
  const config = app.get<ConfigService<Env, true>>(ConfigService);
  const production = config.get('APP_ENV', { infer: true }) === 'production';

  app.disable('x-powered-by');
  app.use(requestMiddleware({ production, logger: new Logger('HTTP') }));
  // Before the rate limiter: preflights are answered here and not counted, and 429s still carry CORS headers.
  app.enableCors({
    origin: config.get('CORS_ORIGINS', { infer: true }),
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-Id'],
    exposedHeaders: ['X-Request-Id', 'Retry-After'],
    maxAge: 600,
  });
  app.use(
    `/${API_PREFIX}/auth`,
    rateLimitMiddleware({
      perMinute: config.get('RATE_LIMIT_AUTH_PER_MINUTE', { infer: true }),
      trust: proxyTrust(config.get('TRUSTED_PROXY_HOPS', { infer: true }), config.get('TRUSTED_PROXY_CIDRS', { infer: true })),
    }),
  );
  app.use(`/${API_PREFIX}`, jsonOnly);
  // strict: false so `null`/`5`/`"x"` parse and get the 422 below instead of a 400 "malformed JSON".
  app.useBodyParser('json', { limit: '1mb', strict: false });
  app.use(`/${API_PREFIX}`, objectBodyOnly);
  app.setGlobalPrefix(API_PREFIX, { exclude: ['health', 'health/ready'] });
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // unknown fields are ignored (and never mass-assigned)
      transform: true,
      exceptionFactory: (errors) => ApiError.validation(toDetails(errors)),
    }),
  );

  // SPEC 5: /docs, /openapi.json and /openapi.yaml exist only outside production (404 there). Swagger UI is
  // served from the bundled swagger-ui-dist package, no CDN.
  if (!production) {
    const document = SwaggerModule.createDocument(
      app,
      new DocumentBuilder()
        .setTitle('Backend boilerplate (NestJS)')
        .setDescription('Shared contract: see SPEC.md')
        .setVersion('1.0')
        .addBearerAuth()
        .build(),
    );
    SwaggerModule.setup('docs', app, () => document, { jsonDocumentUrl: 'openapi.json', yamlDocumentUrl: 'openapi.yaml' });
  }

  const server = app.getHttpServer();
  server.requestTimeout = 30_000; // whole request, slowloris guard
  server.headersTimeout = 15_000;
  server.keepAliveTimeout = 5_000;

  await app.init();
  // Nest's own not-found handler only covers the /api/v1 prefix; everything else (including /docs in
  // production) gets the same envelope here, registered after all routes.
  app.use((_req: Request, res: Response) => {
    res.status(404).json(ApiError.notFound().toBody());
  });
  await app.listen(config.get('PORT', { infer: true }));
  logger.log({ msg: 'listening', port: config.get('PORT', { infer: true }), env: config.get('APP_ENV', { infer: true }) });
  logger.log({ msg: 'argon2 concurrency', slots: argon2Queue.slots, max_waiting: argon2Queue.maxWaiting, threadpool: threadpoolSize() });

  // Graceful shutdown, in this order: stop accepting + drain HTTP, flush background mail, close the DB pool.
  const mailer = app.get(MailerService);
  const prisma = app.get(PrismaService);
  let closing = false;
  const shutdown = async (signal: string) => {
    if (closing) return;
    closing = true;
    logger.log({ msg: 'shutting down', signal });
    const force = setTimeout(() => process.exit(1), 30_000).unref();
    try {
      await app.close();
      await mailer.drain();
      await prisma.$disconnect();
      clearTimeout(force);
      process.exit(0);
    } catch (err) {
      logger.error(err);
      process.exit(1);
    }
  };
  process.once('SIGTERM', () => void shutdown('SIGTERM'));
  process.once('SIGINT', () => void shutdown('SIGINT'));
}

bootstrap().catch((err: unknown) => {
  // e.g. invalid configuration: print the clear message and refuse to start
  process.stderr.write(`Startup failed: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
