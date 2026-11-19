import { PageMetaDto } from '../../../platform/http/pagination.dto.js';
import { UserDto } from './user.dto.js';

export class UserListDto {
  data: UserDto[];
  meta: PageMetaDto;
}
