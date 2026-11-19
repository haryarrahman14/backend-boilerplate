import { lookup as systemLookup, type LookupAddress } from 'node:dns';
import { isIP } from 'node:net';

type Lookup = (host: string, cb: (err: NodeJS.ErrnoException | null, addresses: LookupAddress[]) => void) => void;
const defaultLookup: Lookup = (host, cb) => systemLookup(host, { all: true }, cb);

/**
 * Addresses to try for SMTP_HOST, IPv4 first, via the system resolver (getaddrinfo: /etc/hosts, then DNS), as the
 * other three implementations do. nodemailer's own resolver asks the DNS servers directly with c-ares and only
 * falls back to the system one afterwards: measured on the dev machine, `localhost` took 5-10 s that way and hit
 * the 10 s connection timeout ("DNS lookup for localhost timed out") with no load at all. An IP is used as is.
 */
export function resolveSmtpHost(host: string, timeoutMs: number, lookup: Lookup = defaultLookup): Promise<string[]> {
  if (isIP(host)) return Promise.resolve([host]);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(Object.assign(new Error(`DNS lookup for ${host} timed out`), { code: 'ETIMEOUT' })), timeoutMs);
    lookup(host, (err, addresses) => {
      clearTimeout(timer);
      if (err) return reject(err);
      const ordered = [...addresses].sort((a, b) => a.family - b.family).map((a) => a.address);
      if (ordered.length === 0) return reject(Object.assign(new Error(`no address for ${host}`), { code: 'ENOTFOUND' }));
      resolve([...new Set(ordered)]);
    });
  });
}
