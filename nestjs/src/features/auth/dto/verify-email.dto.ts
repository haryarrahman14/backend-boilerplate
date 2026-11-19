import { IsNotEmpty, IsString } from 'class-validator';

export class VerifyEmailDto {
  /** The `token` query parameter of the emailed link. */
  @IsString() @IsNotEmpty()
  token: string;
}
