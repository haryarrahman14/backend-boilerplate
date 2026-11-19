import { FixedWindowLimiter } from './fixed-window-limiter.js';

describe('FixedWindowLimiter', () => {
  const t0 = 1_000_000;

  it('allows up to the limit within a window, then blocks with Retry-After', () => {
    const rl = new FixedWindowLimiter(3);
    expect(rl.hit('ip', t0).allowed).toBe(true);
    expect(rl.hit('ip', t0 + 1).allowed).toBe(true);
    expect(rl.hit('ip', t0 + 2).allowed).toBe(true);
    expect(rl.hit('ip', t0 + 10_000)).toEqual({ allowed: false, retryAfterSeconds: 50 });
    expect(rl.hit('ip', t0 + 59_001)).toEqual({ allowed: false, retryAfterSeconds: 1 });
  });

  it('starts a fresh window once the old one has passed (fixed, not sliding)', () => {
    const rl = new FixedWindowLimiter(1);
    expect(rl.hit('ip', t0).allowed).toBe(true);
    expect(rl.hit('ip', t0 + 59_999).allowed).toBe(false);
    expect(rl.hit('ip', t0 + 60_000).allowed).toBe(true);
    expect(rl.hit('ip', t0 + 60_001).allowed).toBe(false);
  });

  it('counts each key separately', () => {
    const rl = new FixedWindowLimiter(1);
    expect(rl.hit('a', t0).allowed).toBe(true);
    expect(rl.hit('b', t0).allowed).toBe(true);
    expect(rl.hit('a', t0).allowed).toBe(false);
  });

  it('never reports Retry-After below 1 second', () => {
    const rl = new FixedWindowLimiter(0);
    expect(rl.hit('ip', t0 + 59_999 - 59_999).retryAfterSeconds).toBe(60);
    expect(new FixedWindowLimiter(0, 500).hit('ip', t0).retryAfterSeconds).toBe(1);
  });

  it('caps the number of keys: a new key while full is allowed and not tracked, known keys stay limited', () => {
    const rl = new FixedWindowLimiter(1, 60_000, 2);
    expect(rl.hit('a', t0).allowed).toBe(true);
    expect(rl.hit('b', t0).allowed).toBe(true);
    for (let i = 0; i < 5; i++) expect(rl.hit('c', t0 + 1000).allowed).toBe(true);
    expect(rl.size).toBe(2);
    expect(rl.hit('a', t0 + 1000)).toEqual({ allowed: false, retryAfterSeconds: 59 });
    // after a full window the sweep frees expired keys
    expect(rl.hit('c', t0 + 60_000).allowed).toBe(true);
    expect(rl.size).toBe(1);
  });
});
