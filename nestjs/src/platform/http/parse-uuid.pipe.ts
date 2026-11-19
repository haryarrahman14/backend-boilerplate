import { Injectable, type PipeTransform } from '@nestjs/common';
import { ApiError } from '../errors/api-error.js';

const CANONICAL_UUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/**
 * SPEC 1: path ids must be the canonical 36-char hyphenated form. Anything else (braces, `urn:`, no dashes, garbage)
 * is just a resource that does not exist: 404, before it reaches Postgres (which would accept some of those forms).
 */
@Injectable()
export class ParseUuidPipe implements PipeTransform<string, string> {
  transform(value: string): string {
    if (!CANONICAL_UUID.test(value)) throw ApiError.notFound();
    return value.toLowerCase();
  }
}
