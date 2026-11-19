import type { LoggerService, LogLevel } from '@nestjs/common';
import { requestContext } from './request-context.js';

/**
 * One JSON object per line on stdout. Nest passes the context name as the last string param.
 * Callers must never pass passwords, tokens, hashes or Authorization headers in here.
 */
export class JsonLogger implements LoggerService {
  log(message: unknown, ...params: unknown[]) {
    this.write('info', message, params);
  }
  error(message: unknown, ...params: unknown[]) {
    this.write('error', message, params);
  }
  warn(message: unknown, ...params: unknown[]) {
    this.write('warn', message, params);
  }
  debug(message: unknown, ...params: unknown[]) {
    this.write('debug', message, params);
  }
  verbose(message: unknown, ...params: unknown[]) {
    this.write('verbose', message, params);
  }
  fatal(message: unknown, ...params: unknown[]) {
    this.write('fatal', message, params);
  }

  private write(level: LogLevel | 'info', message: unknown, params: unknown[]) {
    const rest = [...params];
    const context = typeof rest.at(-1) === 'string' ? (rest.pop() as string) : undefined;
    const ctx = requestContext.getStore();
    const line: Record<string, unknown> = { time: new Date().toISOString(), level };
    if (context) line.context = context;
    if (ctx) {
      line.request_id = ctx.requestId;
      if (ctx.userId) line.user_id = ctx.userId;
    }
    if (message instanceof Error) {
      line.msg = message.message;
      line.stack = message.stack;
    } else if (message && typeof message === 'object') {
      Object.assign(line, message);
    } else {
      line.msg = String(message);
    }
    // Nest's error(message, stack, context) convention
    if (level === 'error' && typeof rest[0] === 'string') line.stack = rest[0];
    else if (rest[0] instanceof Error) line.stack = rest[0].stack;
    process.stdout.write(`${JSON.stringify(line)}\n`);
  }
}
