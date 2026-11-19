import { IsStrictEmail, NormalizeEmail } from '../../../platform/validation/validation.decorator.js';

/** Body of resend-verification and forgot-password. */
export class EmailDto {
  /** Trimmed + lowercased, then must match SPEC 4's address regex (ASCII, max 254). @example ada@example.com */
  @NormalizeEmail() @IsStrictEmail()
  email: string;
}
