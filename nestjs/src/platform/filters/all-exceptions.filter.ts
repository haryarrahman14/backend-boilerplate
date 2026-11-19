import { type ArgumentsHost, Catch, type ExceptionFilter, HttpException, Logger } from '@nestjs/common';
import { HttpAdapterHost } from '@nestjs/core';
import type { Response } from 'express';
import { ApiError } from '../errors/api-error.js';
import { BusyError } from '../errors/busy.error.js';
import { safeError } from '../logging/safe-error.js';

const CODE_BY_STATUS: Record<number, () => ApiError> = {
  400: () => ApiError.badRequest(),
  401: () => ApiError.unauthorized(),
  403: () => ApiError.forbidden(),
  404: () => ApiError.notFound(),
  429: () => ApiError.rateLimited(),
};

/** Every error leaves the API in the spec's envelope; anything unexpected is logged and becomes a generic 500. */
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger('AllExceptionsFilter');

  constructor(private readonly adapterHost: HttpAdapterHost) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const res = host.switchToHttp().getResponse<Response>();
    if (exception instanceof BusyError) res.setHeader('Retry-After', '1'); // SPEC 4: argon2 queue full
    const error = exception instanceof BusyError ? ApiError.rateLimited() : this.toApiError(exception);
    const { httpAdapter } = this.adapterHost;
    httpAdapter.reply(res, error.toBody(), error.getStatus());
  }

  private toApiError(exception: unknown): ApiError {
    if (exception instanceof ApiError) return exception;
    const status = exception instanceof HttpException ? exception.getStatus() : 500;
    // The Express adapter wraps body-parser errors (malformed JSON, body over 1 MB) in an HttpException.
    const cause = exception instanceof HttpException ? exception.cause : undefined;
    const parserType = (cause as { type?: unknown } | undefined)?.type;
    if (parserType === 'entity.parse.failed') return ApiError.badRequest('Malformed JSON body');
    if (parserType === 'entity.too.large' || status === 413) return ApiError.payloadTooLarge();
    if (status === 415) return ApiError.badRequest('Content-Type must be application/json');
    const mapped = CODE_BY_STATUS[status];
    if (mapped && status < 500) return mapped();
    this.logger.error(safeError(exception));
    return ApiError.internal();
  }
}
