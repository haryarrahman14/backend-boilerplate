import { plainToInstance } from 'class-transformer';
import { validateSync } from 'class-validator';
import { PaginationQueryDto } from './pagination.dto.js';

const check = (query: Record<string, string>) => {
  const dto = plainToInstance(PaginationQueryDto, query);
  return { dto, errors: validateSync(dto).map((e) => e.property) };
};

describe('PaginationQueryDto', () => {
  it('defaults to page 1, 20 per page', () => {
    const { dto, errors } = check({});
    expect(errors).toEqual([]);
    expect([dto.page, dto.per_page, dto.skip]).toEqual([1, 20, 0]);
  });

  it('accepts the int4 maximum page', () => {
    expect(check({ page: '2147483647', per_page: '100' }).errors).toEqual([]);
  });

  it.each(['0', '-1', '1.5', '1e3', 'abc', '', ' 1', '2147483648', '99999999999999999999'])('rejects page=%p', (page) => {
    expect(check({ page }).errors).toEqual(['page']);
  });

  it.each(['0', '101', '20.0'])('rejects per_page=%p', (per_page) => {
    expect(check({ per_page }).errors).toEqual(['per_page']);
  });
});
