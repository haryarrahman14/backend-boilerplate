import { loginDecision } from './login-decision.js';

const base = { passwordOk: true, disabled: false, emailVerified: true, requireVerifiedEmail: false };

describe('loginDecision', () => {
  it('lets a verified password into an active account', () => {
    expect(loginDecision(base)).toBe('ok');
  });

  it('a wrong password is 401 even for a disabled or unverified account (no status oracle)', () => {
    expect(loginDecision({ ...base, passwordOk: false, disabled: true })).toBe('invalid_credentials');
    expect(loginDecision({ ...base, passwordOk: false, emailVerified: false, requireVerifiedEmail: true })).toBe('invalid_credentials');
  });

  it('reveals a disabled account only after the password verified', () => {
    expect(loginDecision({ ...base, disabled: true })).toBe('account_disabled');
    expect(loginDecision({ ...base, disabled: true, emailVerified: false, requireVerifiedEmail: true })).toBe('account_disabled');
  });

  it('applies AUTH_REQUIRE_VERIFIED_EMAIL only when set', () => {
    expect(loginDecision({ ...base, emailVerified: false })).toBe('ok');
    expect(loginDecision({ ...base, emailVerified: false, requireVerifiedEmail: true })).toBe('email_not_verified');
  });
});
