import { randomUUID } from 'node:crypto';
import type { Logger } from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';
import { requestContext } from '../logging/request-context.js';

const REQUEST_ID = /^[A-Za-z0-9_-]{1,64}$/;

/**
 * Plain Express middleware mounted in main.ts ahead of Nest's router, so it also covers 404s and /docs:
 * request id, security headers, one structured log line per request.
 */
export function requestMiddleware(opts: { production: boolean; logger: Logger }) {
  return (req: Request, res: Response, next: NextFunction) => {
    const incoming = req.headers['x-request-id'];
    const requestId = typeof incoming === 'string' && REQUEST_ID.test(incoming) ? incoming : randomUUID();
    const started = process.hrtime.bigint();
    const aborted = new AbortController();
    const ctx = { requestId, userId: undefined as string | undefined, signal: aborted.signal };
    res.on('close', () => {
      if (!res.writableFinished) aborted.abort();
    });

    res.setHeader('X-Request-Id', requestId);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    if (opts.production) res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains'); // 2 years, as the other three

    res.on('finish', () => {
      requestContext.run(ctx, () =>
        opts.logger.log({
          msg: 'request',
          method: req.method,
          path: req.path, // no query string: never risk logging secrets passed there
          status: res.statusCode,
          duration_ms: Number((process.hrtime.bigint() - started) / 1000n) / 1000,
        }),
      );
    });

    requestContext.run(ctx, next);
  };
}
