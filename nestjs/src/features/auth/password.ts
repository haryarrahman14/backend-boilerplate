import { availableParallelism } from 'node:os';
import argon2 from 'argon2';
import { BusyError } from '../../platform/errors/busy.error.js';
import { requestContext } from '../../platform/logging/request-context.js';

// SPEC 4: argon2id, m=19456 KiB, t=2, p=1, PHC string.
const OPTIONS = { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 } as const;
export const MAX_PASSWORD_CHARS = 128;

/**
 * Size of the libuv threadpool that argon2 (and dns.lookup, fs, zlib, crypto) actually run on. It is fixed when
 * the pool first starts, which in an ESM entry happens while the loader reads the files, before any of our code
 * runs, so UV_THREADPOOL_SIZE only counts when it was in the environment at process start (Dockerfile, Makefile).
 * Measured: set inside the entry module, the pool stays at 4. We never set it in-process, so the env is the truth.
 */
export function threadpoolSize(env: NodeJS.ProcessEnv = process.env): number {
  const n = Number(env.UV_THREADPOOL_SIZE);
  return Number.isInteger(n) && n >= 1 ? Math.min(n, 1024) : 4;
}

/**
 * Concurrent hashes: roughly the CPU count (SPEC 4), but always at least one pool thread fewer than the pool, so
 * DNS lookups (mail), fs and the rest of the threadpool work never queue behind argon2. With the default pool of
 * 4 that is 3 slots.
 */
export function argon2Slots(pool = threadpoolSize(), cpus = availableParallelism()): number {
  return Math.max(1, Math.min(cpus, pool - 1));
}

interface Waiter {
  grant: () => void;
}

/**
 * Bounded argon2 work (SPEC 4): at most `slots` hashes run at once (19 MiB each, see argon2Slots) and at most
 * 4× that wait.
 * A slot is held for the whole hash, even if the request goes away meanwhile; a finished hash hands its slot
 * straight to the next waiter, so the running count never exceeds the cap. Waiting stops when the request is
 * aborted or after `maxWaitMs`. Exported as a class for unit tests; the app uses the shared instance below.
 */
export class Argon2Queue {
  private running = 0;
  private readonly waiting: Waiter[] = [];

  constructor(
    readonly slots = argon2Slots(),
    readonly maxWaiting = 4 * slots,
    private readonly maxWaitMs = 10_000,
  ) {}

  get stats() {
    return { running: this.running, waiting: this.waiting.length };
  }

  async run<T>(job: () => Promise<T>, signal?: AbortSignal): Promise<T> {
    await this.acquire(signal);
    try {
      return await job();
    } finally {
      this.release();
    }
  }

  private acquire(signal?: AbortSignal): Promise<void> {
    if (signal?.aborted) return Promise.reject(new BusyError('request aborted'));
    if (this.running < this.slots) {
      this.running++;
      return Promise.resolve();
    }
    if (this.waiting.length >= this.maxWaiting) return Promise.reject(new BusyError('queue full'));
    return new Promise<void>((resolve, reject) => {
      const leave = (reason: string) => {
        const i = this.waiting.indexOf(waiter);
        if (i !== -1) this.waiting.splice(i, 1);
        cleanup();
        reject(new BusyError(reason));
      };
      const onAbort = () => leave('request aborted');
      const timer = setTimeout(() => leave('waited too long'), this.maxWaitMs);
      timer.unref();
      const cleanup = () => {
        clearTimeout(timer);
        signal?.removeEventListener('abort', onAbort);
      };
      const waiter: Waiter = {
        grant: () => {
          cleanup();
          resolve();
        },
      };
      signal?.addEventListener('abort', onAbort, { once: true });
      this.waiting.push(waiter);
    });
  }

  private release() {
    const next = this.waiting.shift();
    if (next) next.grant(); // hand-off: the slot passes on, `running` is unchanged
    else this.running--;
  }
}

export const argon2Queue = new Argon2Queue();
const queue = argon2Queue;
const currentSignal = () => requestContext.getStore()?.signal;

export const hashPassword = (password: string): Promise<string> => queue.run(() => argon2.hash(password, OPTIONS), currentSignal());

/**
 * False on mismatch and on a malformed hash. Never runs argon2 on more than 128 code points: such a
 * password can't be right, so it costs one dummy verify (same timing) and returns false.
 * Throws BusyError (→ 429, Retry-After: 1) only when the queue refuses the work.
 */
export async function verifyPassword(hash: string, password: string): Promise<boolean> {
  const tooLong = [...password].length > MAX_PASSWORD_CHARS;
  const [h, p] = tooLong ? [await getDummyHash(), 'x'] : [hash, password];
  let ok: boolean;
  try {
    ok = await queue.run(() => argon2.verify(h, p), currentSignal());
  } catch (err) {
    if (err instanceof BusyError) throw err;
    return false;
  }
  return ok && !tooLong;
}

/**
 * Login with an unknown email still pays for one verify against this hash (same parameters as real ones),
 * so response time does not reveal whether the account exists. Computed once, lazily.
 */
let dummyHash: Promise<string> | undefined;
export const getDummyHash = (): Promise<string> =>
  (dummyHash ??= queue.run(() => argon2.hash('dummy password, never matches anything', OPTIONS)));
