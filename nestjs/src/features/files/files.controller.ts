import { Body, Controller, Delete, Get, HttpCode, HttpStatus, Param, Post, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { type AuthContext, CurrentAuth } from '../../platform/auth/auth.decorator.js';
import { ParseUuidPipe } from '../../platform/http/parse-uuid.pipe.js';
import { PaginationQueryDto } from '../../platform/http/pagination.dto.js';
import { FileEnvelopeDto, FileListDto, FileWithDownloadDto, PresignResponseDto } from './dto/file.dto.js';
import { PresignFileDto } from './dto/presign-file.dto.js';
import { FilesService } from './files.service.js';

// A malformed id is just another file that does not exist.
const FileId = () => Param('id', ParseUuidPipe);

@ApiTags('files')
@ApiBearerAuth()
@Controller('files')
export class FilesController {
  constructor(private readonly files: FilesService) {}

  /** Creates a pending row and returns a presigned PUT for uploading straight to the bucket. */
  @Post('presign')
  @HttpCode(HttpStatus.CREATED)
  presign(@CurrentAuth() auth: AuthContext, @Body() dto: PresignFileDto): Promise<PresignResponseDto> {
    return this.files.presign(auth.user.id, dto);
  }

  /** Checks the object exists in the bucket and marks the file uploaded. Idempotent. */
  @Post(':id/complete')
  @HttpCode(HttpStatus.OK)
  async complete(@CurrentAuth() auth: AuthContext, @FileId() id: string): Promise<FileEnvelopeDto> {
    return { file: await this.files.complete(auth.user.id, id) };
  }

  @Get()
  list(@CurrentAuth() auth: AuthContext, @Query() query: PaginationQueryDto): Promise<FileListDto> {
    return this.files.list(auth.user.id, query);
  }

  @Get(':id')
  get(@CurrentAuth() auth: AuthContext, @FileId() id: string): Promise<FileWithDownloadDto> {
    return this.files.get(auth.user.id, id);
  }

  /** Deletes the object, then the row. */
  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  remove(@CurrentAuth() auth: AuthContext, @FileId() id: string): Promise<void> {
    return this.files.remove(auth.user.id, id);
  }
}
