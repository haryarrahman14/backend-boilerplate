import { IsString } from 'class-validator';
import { CharLength, IsStrictEmail, NoControlChars, NormalizeEmail, Trim } from '../../../platform/validation/validation.decorator.js';

export class RegisterDto {
  /** Trimmed + lowercased, then must match SPEC 4's address regex (ASCII, max 254). @example ada@example.com */
  @NormalizeEmail() @IsStrictEmail()
  email: string;

  /** 15–128 characters. @example correct horse battery */
  @IsString() @CharLength(15, 128)
  password: string;

  /** 1–100 code points after trimming, no control characters. @example Ada Lovelace */
  @Trim() @IsString() @CharLength(1, 100) @NoControlChars()
  name: string;
}
