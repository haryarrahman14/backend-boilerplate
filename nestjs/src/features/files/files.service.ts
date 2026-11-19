import { randomUUID } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Env } from '../../platform/config/env.validation.js';
import { ApiError } from '../../platform/errors/api-error.js';
import { pageMeta, type PaginationQueryDto } from '../../platform/http/pagination.dto.js';
import { PrismaService } from '../../platform/prisma/prisma.service.js';
import { PRESIGN_TTL_SECONDS, StorageService } from '../../platform/storage/storage.service.js';
import { FileDto, type FileListDto, type FileWithDownloadDto, type PresignResponseDto } from './dto/file.dto.js';
import type { PresignFileDto } from './dto/presign-file.dto.js';

const EXTENSION = /^\.[a-z0-9]{1,10}$/;

/** `users/<user_id>/<file_id>` + the lowercased extension when it is safe; the client filename never goes in. */
export function objectKey(userId: string, fileId: string, filename: string): string {
  const dot = filename.lastIndexOf('.');
  const ext = dot === -1 ? '' : filename.slice(dot).toLowerCase();
  return `users/${userId}/${fileId}${EXTENSION.test(ext) ? ext : ''}`;
}

/**
 * Direct-to-bucket uploads. The presigned PUT signs Content-Length = declared size, so the bucket itself
 * refuses any other length; the size check at `complete` stays as a second line of defence.
 */
@Injectable()
export class FilesService {
  private readonly maxBytes: number;
  private readonly allowedTypes: string[];

  constructor(
    private readonly prisma: PrismaService,
    private readonly storage: StorageService,
    config: ConfigService<Env, true>,
  ) {
    this.maxBytes = config.get('UPLOAD_MAX_BYTES', { infer: true });
    this.allowedTypes = config.get('UPLOAD_ALLOWED_TYPES', { infer: true });
  }

  async presign(userId: string, dto: PresignFileDto): Promise<PresignResponseDto> {
    const errors = [];
    if (!this.allowedTypes.includes(dto.content_type)) {
      errors.push({ field: 'content_type', message: `content_type must be one of: ${this.allowedTypes.join(', ')}` });
    }
    if (dto.size > this.maxBytes) errors.push({ field: 'size', message: `size must not exceed ${this.maxBytes} bytes` });
    if (errors.length) throw ApiError.validation(errors);

    const id = randomUUID();
    const key = objectKey(userId, id, dto.filename);
    const file = await this.prisma.file.create({
      data: { id, userId, key, filename: dto.filename, contentType: dto.content_type, size: dto.size },
    });
    return {
      file: FileDto.from(file),
      upload: {
        url: await this.storage.presignPut(key, dto.content_type, dto.size),
        method: 'PUT',
        headers: { 'Content-Type': dto.content_type },
        expires_in: PRESIGN_TTL_SECONDS,
      },
    };
  }

  async complete(userId: string, id: string): Promise<FileDto> {
    const file = await this.owned(userId, id);
    if (file.status === 'uploaded') return FileDto.from(file); // idempotent

    const size = await this.storage.headSize(file.key);
    if (size === null) throw ApiError.uploadIncomplete();
    if (size > this.maxBytes) {
      await this.storage.delete(file.key);
      await this.prisma.file.deleteMany({ where: { id: file.id } });
      throw ApiError.validation([{ field: 'size', message: `uploaded object exceeds ${this.maxBytes} bytes and was deleted` }]);
    }
    // Conditional on still pending, so two concurrent completes cannot both move uploaded_at.
    await this.prisma.file.updateMany({
      where: { id: file.id, status: 'pending' },
      data: { status: 'uploaded', size, uploadedAt: new Date() },
    });
    return FileDto.from(await this.owned(userId, id));
  }

  async list(userId: string, q: PaginationQueryDto): Promise<FileListDto> {
    const [files, total] = await this.prisma.$transaction([
      this.prisma.file.findMany({
        where: { userId },
        orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
        skip: q.skip,
        take: q.per_page,
      }),
      this.prisma.file.count({ where: { userId } }),
    ]);
    return { data: files.map((f) => FileDto.from(f)), meta: pageMeta(q, total) };
  }

  async get(userId: string, id: string): Promise<FileWithDownloadDto> {
    const file = await this.owned(userId, id);
    return {
      file: FileDto.from(file),
      download_url: file.status === 'uploaded' ? await this.storage.presignGet(file.key) : null,
    };
  }

  async remove(userId: string, id: string): Promise<void> {
    const file = await this.owned(userId, id);
    await this.storage.delete(file.key);
    await this.prisma.file.deleteMany({ where: { id: file.id } });
  }

  /** Someone else's file is indistinguishable from a missing one. */
  private async owned(userId: string, id: string) {
    const file = await this.prisma.file.findFirst({ where: { id, userId } });
    if (!file) throw ApiError.notFound('File not found');
    return file;
  }
}
