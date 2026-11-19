import type { NextFunction, Request, Response } from 'express';
import { ApiError } from '../errors/api-error.js';
import { clientIp, type ProxyTrust, rateLimitKey } from '../http/client-ip.js';
import { FixedWindowLimiter } from './fixed-window-limiter.js';

/**
 * Express middleware mounted in main.ts on /api/v1/auth, ahead of body parsing and Nest's router, so one
 * counter per client (IPv6 by /64) covers every /auth/* request: 401s, 404s, malformed or oversized bodies too.
 */
export function rateLimitMiddleware(opts: { perMinute: number; trust: ProxyTrust }) {
  const limiter = new FixedWindowLimiter(opts.perMinute);
  return (req: Request, res: Response, next: NextFunction) => {
    const { allowed, retryAfterSeconds } = limiter.hit(rateLimitKey(clientIp(req, opts.trust)));
    if (allowed) return next();
    res.setHeader('Retry-After', String(retryAfterSeconds));
    res.status(429).json(ApiError.rateLimited().toBody());
  };
}
