"""Alembic runs only from `make migrate`, never on app start. Needs DATABASE_URL, nothing else."""

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine

import app.features.auth.models
import app.features.files.models
import app.features.users.models  # noqa: F401  (register every table on Base.metadata)
from app.platform.config import DatabaseSettings
from app.platform.db import Base

config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name)
target_metadata = Base.metadata


def _migrate(connection) -> None:
    # include_schemas: the models live in auth / storage, so autogenerate must look beyond `public`.
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True, include_schemas=True)
    with context.begin_transaction():
        context.run_migrations()


async def _run() -> None:
    target = DatabaseSettings().database  # same URL + sslmode handling as the app
    engine = create_async_engine(target.url, connect_args=target.connect_args(), hide_parameters=True)
    async with engine.connect() as conn:
        await conn.run_sync(_migrate)
    await engine.dispose()


if context.is_offline_mode():
    raise SystemExit("offline mode is not supported; run against a database")
asyncio.run(_run())
