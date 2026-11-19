import { EMAIL_REGEX } from './validation.decorator.js';

describe('EMAIL_REGEX (SPEC 4)', () => {
  it.each(['ada@example.com', 'a.b+tag@sub.example.co', "o'brien@example.ie", 'x_y-z@exa-mple.com', 'a!#$%&*/=?^`{|}~@example.com'])(
    'accepts %p',
    (email) => expect(EMAIL_REGEX.test(email)).toBe(true),
  );

  it.each([
    'victim<attacker@evil.example>',
    '"a b"@example.com',
    'a@b',
    'a@@example.com',
    'josé@example.com',
    'a b@example.com',
    'a@exa_mple.com',
    'Ada@Example.com', // must be lowercased first
    'a@example.com\n',
    'a@example..com',
    '@example.com',
    'a@.example.com',
  ])('rejects %p', (email) => expect(EMAIL_REGEX.test(email)).toBe(false));
});
