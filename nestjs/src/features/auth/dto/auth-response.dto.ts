import { UserDto } from '../../users/dto/user.dto.js';

export class TokensDto {
  access_token: string;
  /** `<session_id>.<secret>`, rotated on every refresh. */
  refresh_token: string;
  /** @example Bearer */
  token_type: 'Bearer';
  /** Access token lifetime in seconds. @example 900 */
  expires_in: number;
  user: UserDto;
}

export class MessageDto {
  message: string;
}

export class SessionDto {
  id: string;
  user_agent: string | null;
  ip: string | null;
  created_at: Date;
  last_used_at: Date;
  /** True for the session of the access token making this request. */
  current: boolean;
}

export class SessionListDto {
  data: SessionDto[];
}
