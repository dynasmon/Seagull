from __future__ import annotations

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

from app.core.config import settings


class Base(DeclarativeBase):
    pass


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    raw = raw.strip()
    if raw == "":
        return default
    try:
        return int(raw)
    except Exception:
        return default


def _make_engine():
    # Engine tuning notes:
    # - Ingest can become CPU-bound when using ORM row-by-row inserts.
    # - We rely on bulk insert patterns and (when supported) psycopg2 "executemany values" to reduce overhead.
    # - Pool sizing is configurable via env to match the VM's resources.
    kwargs = dict(
        future=True,
        pool_pre_ping=True,
        pool_size=_env_int("NETWATCH_DB_POOL_SIZE", 10),
        max_overflow=_env_int("NETWATCH_DB_MAX_OVERFLOW", 20),
    )

    # psycopg2 accelerators (may not be supported on very old SQLAlchemy versions)
    kwargs["executemany_mode"] = os.getenv("NETWATCH_DB_EXECUTEMANY_MODE", "values_plus_batch")
    kwargs["executemany_values_page_size"] = _env_int("NETWATCH_DB_EXECUTEMANY_VALUES_PAGE_SIZE", 1000)

    try:
        return create_engine(settings.database_url, **kwargs)
    except TypeError:
        # Fallback for environments where these kwargs are not supported.
        kwargs.pop("executemany_mode", None)
        kwargs.pop("executemany_values_page_size", None)
        return create_engine(settings.database_url, **kwargs)


engine = _make_engine()

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    future=True,
)
