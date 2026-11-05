"""Database engine and session factory."""
import asyncio
import os
import logging

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool

from .config import settings

log = logging.getLogger(__name__)

# Tests use one connection per session (several event loops share this engine).
engine = create_async_engine(settings.database_url, pool_pre_ping=True,
                             **({"poolclass": NullPool} if os.environ.get("TGV_DB_NULLPOOL")
                                else {"pool_size": 10, "max_overflow": 20}))
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


# create_all doesn't add columns to existing tables; small additive migrations go here.
MIGRATIONS = [
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false",
]


async def init_db(attempts: int = 30) -> None:
    from sqlalchemy import text

    from . import models  # noqa: F401  (registers tables)

    for i in range(attempts):
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
                for statement in MIGRATIONS:
                    await conn.execute(text(statement))
            return
        except OSError as e:
            log.warning("database not ready (%s), retrying", e)
            await asyncio.sleep(min(2 + i, 10))
    raise RuntimeError("database not reachable")
