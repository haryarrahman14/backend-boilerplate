import { lookup } from 'node:dns/promises';
import argon2 from 'argon2';
import { Argon2Queue, argon2Slots, threadpoolSize } from './password.js';

const OPTIONS = { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 } as const;
describe('argon2 vs the libuv threadpool', () => {
  it('sizes slots one below the real pool, capped by the CPU count', () => {
    expect(threadpoolSize({})).toBe(4);
    expect(threadpoolSize({ UV_THREADPOOL_SIZE: '16' })).toBe(16);
    expect(threadpoolSize({ UV_THREADPOOL_SIZE: 'lots' })).toBe(4);
    expect(argon2Slots(4, 10)).toBe(3);
    expect(argon2Slots(16, 10)).toBe(10);
    expect(argon2Slots(1, 10)).toBe(1);
  });

  // Regression: with more slots than pool threads, getaddrinfo (nodemailer, fetch, pg) queued behind the hashes and
  // mail was lost. Asserted on the count, not on timings: a latency bound fails on a busy machine.
  it('never runs hashes on every pool thread, even with the queue saturated', async () => {
    const pool = threadpoolSize();
    const queue = new Argon2Queue(argon2Slots());
    let stop = false;
    let peak = 0;
    const jobs = Array.from({ length: queue.slots + queue.maxWaiting }, async (_, i) => {
      while (!stop) {
        await queue.run(async () => {
          peak = Math.max(peak, queue.stats.running);
          await argon2.hash(`pw ${i}`, OPTIONS);
        });
      }
    });
    await new Promise((r) => setTimeout(r, 300)); // several rounds of hand-offs between waiters
    stop = true;
    await Promise.all(jobs);
    expect(peak).toBe(queue.slots);
    expect(peak).toBeLessThan(pool); // one thread always stays free for DNS and file work
    await expect(lookup('localhost')).resolves.toBeDefined();
  }, 30_000);
});
