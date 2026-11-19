import { IsNotEmpty, IsString } from 'class-validator';
import { CharLength } from '../../../platform/validation/validation.decorator.js';

export class ResetPasswordDto {
  /** The `token` query parameter of the emailed link. */
  @IsString() @IsNotEmpty()
  token: string;

  /** 15–128 characters. Validated before the token is consumed. */
  @IsString() @CharLength(15, 128)
  password: string;
}
