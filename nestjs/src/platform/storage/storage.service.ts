import {
  DeleteObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  NotFound,
  PutObjectCommand,
  S3Client,
  S3ServiceException,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Env } from '../config/env.validation.js';

export const PRESIGN_TTL_SECONDS = 900;

/** S3-compatible object storage (Cloudflare R2 in production, MinIO locally). */
@Injectable()
export class StorageService {
  private readonly s3: S3Client;
  private readonly bucket: string;

  constructor(config: ConfigService<Env, true>) {
    this.bucket = config.get('S3_BUCKET', { infer: true });
    this.s3 = new S3Client({
      endpoint: config.get('S3_ENDPOINT', { infer: true }),
      region: config.get('S3_REGION', { infer: true }),
      credentials: {
        accessKeyId: config.get('S3_ACCESS_KEY_ID', { infer: true }),
        secretAccessKey: config.get('S3_SECRET_ACCESS_KEY', { infer: true }),
      },
      forcePathStyle: true, // SPEC 2: path-style for both R2 and MinIO
      // Otherwise the SDK adds CRC32 checksum params to presigned PUTs, which browsers can't satisfy.
      requestChecksumCalculation: 'WHEN_REQUIRED',
      responseChecksumValidation: 'WHEN_REQUIRED',
    });
  }

  /**
   * Presigned PUT with Content-Type and Content-Length as signed headers (SPEC 5): the bucket rejects any other
   * type or any other body length, before and after `complete`.
   */
  presignPut(key: string, contentType: string, size: number): Promise<string> {
    return getSignedUrl(
      this.s3,
      new PutObjectCommand({ Bucket: this.bucket, Key: key, ContentType: contentType, ContentLength: size }),
      { expiresIn: PRESIGN_TTL_SECONDS, signableHeaders: new Set(['content-type', 'content-length']) },
    );
  }

  /** Presigned GET that always downloads (never renders inline on the bucket origin). */
  presignGet(key: string): Promise<string> {
    // A bare `attachment`, like the other implementations: no client-chosen filename in a response header.
    return getSignedUrl(this.s3, new GetObjectCommand({ Bucket: this.bucket, Key: key, ResponseContentDisposition: 'attachment' }), {
      expiresIn: PRESIGN_TTL_SECONDS,
    });
  }

  /** Size in bytes, or null when the object does not exist. */
  async headSize(key: string): Promise<number | null> {
    try {
      const head = await this.s3.send(new HeadObjectCommand({ Bucket: this.bucket, Key: key }));
      return head.ContentLength ?? 0;
    } catch (err) {
      if (err instanceof NotFound || (err instanceof S3ServiceException && err.$metadata.httpStatusCode === 404)) return null;
      throw err;
    }
  }

  async delete(key: string): Promise<void> {
    await this.s3.send(new DeleteObjectCommand({ Bucket: this.bucket, Key: key }));
  }
}
