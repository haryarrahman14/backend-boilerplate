import { AsyncLocalStorage } from 'node:async_hooks';

export interface RequestContext {
  requestId: string;
  userId?: string;
  /** Aborted when the client goes away before the response is finished (e.g. stops argon2 queue waits). */
  signal?: AbortSignal;
}

/** Per-request store so every log line of a request carries its request_id (and user_id once known). */
export const requestContext = new AsyncLocalStorage<RequestContext>();
