import { IsInt, Max, Min } from 'class-validator';
import { ToQueryInt } from '../validation/validation.decorator.js';

const PAGE_MAX = 2147483647; // SPEC 1: int4 max

/** `?page=1&per_page=20`; out of range, non-integer or overflowing → 422 (SPEC.md section 1). */
export class PaginationQueryDto {
  /** @example 1 */
  @ToQueryInt() @IsInt() @Min(1) @Max(PAGE_MAX)
  page: number = 1;

  /** @example 20 */
  @ToQueryInt() @IsInt() @Min(1) @Max(100)
  per_page: number = 20;

  get skip(): number {
    return (this.page - 1) * this.per_page;
  }
}

export class PageMetaDto {
  page: number;
  per_page: number;
  total: number;
}

export const pageMeta = (q: PaginationQueryDto, total: number): PageMetaDto => ({ page: q.page, per_page: q.per_page, total });
