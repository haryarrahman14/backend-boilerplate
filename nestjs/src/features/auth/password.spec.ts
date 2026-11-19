import { getDummyHash, hashPassword, verifyPassword } from './password.js';

describe('password', () => {
  it('hashes with argon2id and the spec parameters (m=19456, t=2, p=1)', async () => {
    const hash = await hashPassword('correct horse battery');
    expect(hash).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
  });

  it('salts every hash', async () => {
    expect(await hashPassword('same')).not.toEqual(await hashPassword('same'));
  });

  it('verifies the right password and rejects a wrong one', async () => {
    const hash = await hashPassword('correct horse battery');
    expect(await verifyPassword(hash, 'correct horse battery')).toBe(true);
    expect(await verifyPassword(hash, 'correct horse batterY')).toBe(false);
  });

  it('returns false (never throws) for a malformed hash', async () => {
    expect(await verifyPassword('not-a-phc-string', 'whatever')).toBe(false);
  });

  it('dummy hash has the same parameters and matches nothing', async () => {
    const dummy = await getDummyHash();
    expect(dummy).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
    expect(await getDummyHash()).toBe(dummy);
    expect(await verifyPassword(dummy, 'correct horse battery')).toBe(false);
  });

  it('never runs argon2 on more than 128 code points (and such a password never matches)', async () => {
    const long = '😀'.repeat(129);
    const hash = await hashPassword('😀'.repeat(128));
    expect(await verifyPassword(hash, '😀'.repeat(128))).toBe(true);
    expect(await verifyPassword(await hashPassword(long), long)).toBe(false);
  });
});
