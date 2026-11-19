import type { File } from '../../../generated/prisma/client.js';
import { PageMetaDto } from '../../../platform/http/pagination.dto.js';

/** The `file` object of SPEC 5. */
export class FileDto {
  id: string;
  filename: string;
  content_type: string;
  size: number;
  /** @example pending */
  status: 'pending' | 'uploaded';
  created_at: Date;
  uploaded_at: Date | null;

  static from(f: File): FileDto {
    return {
      id: f.id,
      filename: f.filename,
      content_type: f.contentType,
      size: Number(f.size), // bigint column; sizes are capped far below 2^53
      status: f.status as FileDto['status'],
      created_at: f.createdAt,
      uploaded_at: f.uploadedAt,
    };
  }
}

export class UploadInstructionsDto {
  url: string;
  /** @example PUT */
  method: 'PUT';
  /** Send exactly these headers with the PUT; Content-Type is part of the signature. */
  headers: Record<string, string>;
  /** @example 900 */
  expires_in: number;
}

export class PresignResponseDto {
  file: FileDto;
  upload: UploadInstructionsDto;
}

export class FileEnvelopeDto {
  file: FileDto;
}

export class FileWithDownloadDto {
  file: FileDto;
  /** Presigned GET (900 s) once uploaded, null while pending. */
  download_url: string | null;
}

export class FileListDto {
  data: FileDto[];
  meta: PageMetaDto;
}
