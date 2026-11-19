"""`?page=&per_page=` parsing and the `{data, meta}` envelope shared by paginated routes."""

from typing import Annotated

from fastapi import Depends, Query
from pydantic import BaseModel


class PageParams(BaseModel):
    page: int
    per_page: int

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.per_page


def page_params(
    page: Annotated[int, Query(ge=1, le=2**31 - 1)] = 1,  # upper bound keeps OFFSET inside Postgres bigint
    per_page: Annotated[int, Query(ge=1, le=100)] = 20,
) -> PageParams:
    return PageParams(page=page, per_page=per_page)


Pagination = Annotated[PageParams, Depends(page_params)]


class PageMeta(BaseModel):
    page: int
    per_page: int
    total: int
