import { IsNotEmpty, IsString } from 'class-validator';
import { CharLength } from '../../../platform/validation/validation.decorator.js';

export class ChangePasswordDto {
  @IsString() @IsNotEmpty()
  current_password: string;

  /** 15–128 characters. */
  @IsString() @CharLength(15, 128)
  new_password: string;
}
