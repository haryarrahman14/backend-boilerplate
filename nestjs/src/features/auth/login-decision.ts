// Pure (unit tested): what a login answers once the password check has run.

export type LoginOutcome = 'ok' | 'invalid_credentials' | 'account_disabled' | 'email_not_verified';

/**
 * SPEC 4/5: an unknown user or a wrong password is always 401, and only someone who proved the password learns
 * that the account is disabled (403 account_disabled) or unverified (403 email_not_verified).
 */
export function loginDecision(input: {
  passwordOk: boolean;
  disabled: boolean;
  emailVerified: boolean;
  requireVerifiedEmail: boolean;
}): LoginOutcome {
  if (!input.passwordOk) return 'invalid_credentials';
  if (input.disabled) return 'account_disabled';
  if (input.requireVerifiedEmail && !input.emailVerified) return 'email_not_verified';
  return 'ok';
}
