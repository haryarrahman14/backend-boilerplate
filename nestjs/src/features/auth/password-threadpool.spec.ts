import { lookup } from 'node:dns/promises';
import argon2 from 'argon2';
import { Argon2Queue, argon2Slots, threadpoolSize } from './password.js';

const OPTIONS = { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 } as const;
// Measured on the dev machine under this load: with slots below the pool a lookup takes 0-2 ms; with the old
// sizing (10 slots on the default 4 threads) it took 8-36 ms, queued behind hashes. Timers are never affected
// (argon2 runs off the event loop), but are checked so a blocking regression would show too.
const DNS_BOUND_MS = 10;
const TIMER_BOUND_MS = 50;

const elapsed = async (f: () => Promise<unknown>) => {
  const start = performance.now();
  await f();
  return performance.now() - start;
};

describe('argon2 vs the libuv threadpool', () => {
  it('sizes slots one below the real pool, capped by the CPU count', () => {
    expect(threadpoolSize({})).toBe(4);
    expect(threadpoolSize({ UV_THREADPOOL_SIZE: '16' })).toBe(16);
    expect(threadpoolSize({ UV_THREADPOOL_SIZE: 'lots' })).toBe(4);
    expect(argon2Slots(4, 10)).toBe(3);
    expect(argon2Slots(16, 10)).toBe(10);
    expect(argon2Slots(1, 10)).toBe(1);
  });

  // Regression: with more slots than pool threads, getaddrinfo (nodemailer, fetch, pg) queued behind the hashes.
  it(`a DNS lookup (< ${DNS_BOUND_MS} ms) and a timer (< ${TIMER_BOUND_MS} ms late) are not delayed while the argon2 queue is saturated`, async () => {
    const queue = new Argon2Queue(argon2Slots());
    await lookup('localhost'); // warm the resolver
    // Sustained load: every slot busy and the wait list full for the whole measurement, like a login flood.
    let stop = false;
    const jobs = Array.from({ length: queue.slots + queue.maxWaiting }, async (_, i) => {
      while (!stop) await queue.run(() => argon2.hash(`pw ${i}`, OPTIONS));
    });
    await new Promise((r) => setTimeout(r, 30)); // let the hashes occupy their threads
    expect(queue.stats.running).toBe(queue.slots);

    const dnsMs: number[] = [];
    const timerLateMs: number[] = [];
    for (let i = 0; i < 10; i++) {
      dnsMs.push(await elapsed(() => lookup('localhost')));
      const due = performance.now() + 10;
      await new Promise((r) => setTimeout(r, 10));
      timerLateMs.push(performance.now() - due);
    }
    stop = true;
    await Promise.all(jobs);
    expect(Math.max(...dnsMs)).toBeLessThan(DNS_BOUND_MS);
    expect(Math.max(...timerLateMs)).toBeLessThan(TIMER_BOUND_MS);
  }, 30_000);
});
