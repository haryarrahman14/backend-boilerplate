import { HttpException, HttpStatus } from '@nestjs/common';

export interface FieldError {
  field: string;
  message: string;
}

export interface ErrorEnvelope {
  error: { code: string; message: string; details?: FieldError[] };
}

/** The only exception type features throw: carries the spec's error `code` (SPEC.md section 1). */
export class ApiError extends HttpException {
  constructor(
    status: number,
    readonly code: string,
    message: string,
    readonly details?: FieldError[],
  ) {
    super(message, status);
  }

  toBody(): ErrorEnvelope {
    return { error: { code: this.code, message: this.message, ...(this.details ? { details: this.details } : {}) } };
  }

  static badRequest = (message = 'Malformed request') => new ApiError(HttpStatus.BAD_REQUEST, 'bad_request', message);
  static invalidToken = () => new ApiError(HttpStatus.BAD_REQUEST, 'invalid_token', 'Token is invalid or has expired');
  static invalidCredentials = () => new ApiError(HttpStatus.UNAUTHORIZED, 'invalid_credentials', 'Invalid email or password');
  static unauthorized = () => new ApiError(HttpStatus.UNAUTHORIZED, 'unauthorized', 'Authentication required');
  static emailNotVerified = () => new ApiError(HttpStatus.FORBIDDEN, 'email_not_verified', 'Email address is not verified');
  static accountDisabled = () => new ApiError(HttpStatus.FORBIDDEN, 'account_disabled', 'This account has been disabled');
  static forbidden = (message = 'You are not allowed to do this') => new ApiError(HttpStatus.FORBIDDEN, 'forbidden', message);
  static notFound = (message = 'Not found') => new ApiError(HttpStatus.NOT_FOUND, 'not_found', message);
  static emailTaken = () => new ApiError(HttpStatus.CONFLICT, 'email_taken', 'Email is already registered');
  static uploadIncomplete = () => new ApiError(HttpStatus.CONFLICT, 'upload_incomplete', 'The object has not been uploaded yet');
  static payloadTooLarge = () => new ApiError(HttpStatus.PAYLOAD_TOO_LARGE, 'payload_too_large', 'Request body is larger than 1 MB');
  static validation = (details: FieldError[]) =>
    new ApiError(HttpStatus.UNPROCESSABLE_ENTITY, 'validation_error', 'Request validation failed', details);
  static rateLimited = () => new ApiError(HttpStatus.TOO_MANY_REQUESTS, 'rate_limited', 'Too many requests, slow down');
  static internal = () => new ApiError(HttpStatus.INTERNAL_SERVER_ERROR, 'internal_error', 'Something went wrong');
}
