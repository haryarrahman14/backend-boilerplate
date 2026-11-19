import { IsNotEmpty, IsString } from 'class-validator';

/** Body of DELETE /users/me: the current password, checked like a login. */
export class DeleteAccountDto {
  @IsString() @IsNotEmpty()
  password: string;
}
