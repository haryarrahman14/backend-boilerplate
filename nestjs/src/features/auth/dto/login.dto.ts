import { IsNotEmpty, IsString } from 'class-validator';
import { NormalizeEmail } from '../../../platform/validation/validation.decorator.js';

// Deliberately loose: any wrong value must end in the same 401 invalid_credentials, not a 422 hint.
export class LoginDto {
  /** @example ada@example.com */
  @NormalizeEmail() @IsString() @IsNotEmpty()
  email: string;

  /** @example correct horse battery */
  @IsString() @IsNotEmpty()
  password: string;
}
