import { IsOptional, IsString } from 'class-validator';
import { CharLength, NoControlChars, Trim } from '../../../platform/validation/validation.decorator.js';

/** Only `name` is accepted; anything else (role, email, ...) is stripped by the whitelist. */
export class UpdateUserDto {
  /** 1–100 code points after trimming, no control characters. Absent → nothing changes. @example Grace Hopper */
  @IsOptional() @Trim() @IsString() @CharLength(1, 100) @NoControlChars()
  name?: string;
}
