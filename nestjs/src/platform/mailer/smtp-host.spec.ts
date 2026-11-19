import type { LookupAddress } from 'node:dns';
import { resolveSmtpHost } from './smtp-host.js';

const fake =
  (addresses: LookupAddress[], delayMs = 0) =>
  (_host: string, cb: (err: NodeJS.ErrnoException | null, a: LookupAddress[]) => void) =>
    setTimeout(() => cb(null, addresses), delayMs);

describe('resolveSmtpHost', () => {
  it('uses an IP as is', async () => {
    expect(await resolveSmtpHost('127.0.0.1', 100, () => { throw new Error('no lookup for an IP'); })).toEqual(['127.0.0.1']);
    expect(await resolveSmtpHost('::1', 100)).toEqual(['::1']);
  });

  it('orders IPv4 before IPv6 and dedupes', async () => {
    const addrs = [{ address: '::1', family: 6 }, { address: '127.0.0.1', family: 4 }, { address: '127.0.0.1', family: 4 }];
    expect(await resolveSmtpHost('localhost', 100, fake(addrs))).toEqual(['127.0.0.1', '::1']);
  });

  it('times out instead of hanging', async () => {
    await expect(resolveSmtpHost('slow.example', 20, fake([{ address: '10.0.0.1', family: 4 }], 200))).rejects.toThrow(/timed out/);
  });

  it('resolves localhost through the system resolver quickly (no c-ares DNS round trip)', async () => {
    const start = performance.now();
    expect((await resolveSmtpHost('localhost', 2000)).length).toBeGreaterThan(0);
    expect(performance.now() - start).toBeLessThan(500);
  });
});
