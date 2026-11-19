import { IsInt, IsString, Min } from 'class-validator';
import { CharLength, NoControlChars } from '../../../platform/validation/validation.decorator.js';

export class PresignFileDto {
  /** Original client filename, stored as-is but never used in the object key. @example invoice.pdf */
  @IsString() @CharLength(1, 255) @NoControlChars()
  filename: string;

  /** Must be one of UPLOAD_ALLOWED_TYPES. @example application/pdf */
  @IsString()
  content_type: string;

  /** Declared size in bytes: a JSON integer (not a string), at most UPLOAD_MAX_BYTES. @example 2048 */
  @IsInt() @Min(1)
  size: number;
}
