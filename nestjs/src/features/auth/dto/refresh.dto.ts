import { IsNotEmpty, IsString } from 'class-validator';

export class RefreshDto {
  /** `<session_id>.<secret>` from login or the previous refresh. */
  @IsString() @IsNotEmpty()
  refresh_token: string;
}
