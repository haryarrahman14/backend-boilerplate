/**
 * Framework-free "try again in a second" signal (e.g. the argon2 queue is full, or a wait for it was cancelled).
 * AllExceptionsFilter answers it with 429 rate_limited and Retry-After: 1.
 */
export class BusyError extends Error {
  constructor(reason: string) {
    super(`busy: ${reason}`);
    this.name = 'BusyError';
  }
}
