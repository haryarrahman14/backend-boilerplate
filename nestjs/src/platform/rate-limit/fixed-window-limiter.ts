export interface RateLimitResult {
  allowed: boolean;
  /** Seconds until the caller may retry (for Retry-After); 0 when allowed. */
  retryAfterSeconds: number;
}

export const MAX_KEYS = 100_000;

/**
 * Fixed-window counter per key. SINGLE-INSTANCE ONLY: state lives in this process's memory,
 * so swap it for Redis (INCR + EXPIRE) once the API runs on more than one instance.
 * Memory is bounded: expired windows are swept at most once per window, and at MAX_KEYS a new key is allowed but
 * not tracked (SPEC 4: refusing new keys would let someone with 100 000 addresses lock everyone else out, while
 * they already have 100 000 budgets either way). Known keys stay limited.
 */
export class FixedWindowLimiter {
  private readonly windows = new Map<string, { start: number; count: number }>();
  private lastSweep: number | undefined;

  constructor(
    private readonly limit: number,
    private readonly windowMs = 60_000,
    private readonly maxKeys = MAX_KEYS,
  ) {}

  hit(key: string, now = Date.now()): RateLimitResult {
    this.sweep(now);
    let w = this.windows.get(key);
    if (w && now - w.start >= this.windowMs) {
      w.start = now;
      w.count = 0;
    }
    if (!w) {
      if (this.windows.size >= this.maxKeys) return { allowed: true, retryAfterSeconds: 0 }; // full: allow, don't track
      w = { start: now, count: 0 };
      this.windows.set(key, w);
    }
    w.count++;
    if (w.count <= this.limit) return { allowed: true, retryAfterSeconds: 0 };
    return { allowed: false, retryAfterSeconds: this.secondsUntil(w.start + this.windowMs, now) };
  }

  get size(): number {
    return this.windows.size;
  }

  private secondsUntil(at: number, now: number): number {
    return Math.max(1, Math.ceil((at - now) / 1000));
  }

  // O(1) check per request; the O(n) sweep itself runs at most once per window.
  private sweep(now: number) {
    if (this.lastSweep === undefined) {
      this.lastSweep = now;
      return;
    }
    if (now - this.lastSweep < this.windowMs) return;
    this.lastSweep = now;
    for (const [key, w] of this.windows) if (now - w.start >= this.windowMs) this.windows.delete(key);
  }
}
