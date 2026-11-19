"""Async SQLAlchemy engine + one session per request. The models live in each feature."""

from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.platform.config import DatabaseTarget


class Base(DeclarativeBase):
    pass


def make_engine(target: DatabaseTarget) -> AsyncEngine:
    # hide_parameters: driver errors would otherwise print `[parameters: (...)]`, i.e. argon2 and token hashes.
    return create_async_engine(
        target.url,
        connect_args=target.connect_args(),
        pool_size=10,
        max_overflow=10,
        pool_pre_ping=True,
        pool_recycle=1800,
        hide_parameters=True,
    )


def make_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


async def get_db(request: Request) -> AsyncIterator[AsyncSession]:
    # The request is one unit of work: handlers call `await db.commit()`; anything uncommitted rolls back on close.
    async with request.app.state.sessionmaker() as session:
        yield session


Db = Annotated[AsyncSession, Depends(get_db)]
