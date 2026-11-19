import { BusyError } from '../../platform/errors/busy.error.js';
import { Argon2Queue } from './password.js';

const deferred = () => {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => (resolve = r));
  return { promise, resolve };
};

describe('Argon2Queue', () => {
  it('runs at most `slots` jobs at once and hands a finished slot to the next waiter', async () => {
    const q = new Argon2Queue(2, 8);
    let peak = 0;
    let active = 0;
    const gates = Array.from({ length: 5 }, deferred);
    const jobs = gates.map((g) =>
      q.run(async () => {
        active++;
        peak = Math.max(peak, active);
        await g.promise;
        active--;
      }),
    );
    await Promise.resolve();
    expect(q.stats).toEqual({ running: 2, waiting: 3 });
    gates.forEach((g) => g.resolve());
    await Promise.all(jobs);
    expect(peak).toBe(2);
    expect(q.stats).toEqual({ running: 0, waiting: 0 });
  });

  it('refuses with BusyError beyond 4× the slots waiting', async () => {
    const q = new Argon2Queue(1);
    expect(q.maxWaiting).toBe(4);
    const gate = deferred();
    const running = q.run(() => gate.promise);
    const waiters = Array.from({ length: 4 }, () => q.run(() => Promise.resolve(undefined)));
    await expect(q.run(() => Promise.resolve(undefined))).rejects.toBeInstanceOf(BusyError);
    gate.resolve();
    await Promise.all([running, ...waiters]);
  });

  it('drops a waiter whose request is aborted, without freeing the running slot', async () => {
    const q = new Argon2Queue(1, 4);
    const gate = deferred();
    const running = q.run(() => gate.promise);
    const ac = new AbortController();
    const waiting = q.run(() => Promise.resolve('never'), ac.signal);
    ac.abort();
    await expect(waiting).rejects.toBeInstanceOf(BusyError);
    expect(q.stats).toEqual({ running: 1, waiting: 0 });
    gate.resolve();
    await running;
    expect(q.stats).toEqual({ running: 0, waiting: 0 });
  });

  it('refuses an already aborted request and gives up after the deadline', async () => {
    const ac = new AbortController();
    ac.abort();
    await expect(new Argon2Queue(1).run(() => Promise.resolve(1), ac.signal)).rejects.toBeInstanceOf(BusyError);

    const q = new Argon2Queue(1, 4, 20);
    const gate = deferred();
    const running = q.run(() => gate.promise);
    await expect(q.run(() => Promise.resolve(1))).rejects.toThrow(/waited too long/);
    gate.resolve();
    await running;
  });
});
