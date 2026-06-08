from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings


def _make_engine():
    database_url = settings.database_url
    is_sqlite = database_url.startswith("sqlite")

    kwargs = dict(
        future=True,
        pool_pre_ping=True,
    )

    if not is_sqlite:
        kwargs["pool_size"] = max(1, int(settings.SEAGULL_DB_POOL_SIZE or 10))
        kwargs["max_overflow"] = max(0, int(settings.SEAGULL_DB_MAX_OVERFLOW or 20))
        # psycopg2 accelerators (may not be supported on very old SQLAlchemy versions)
        kwargs["executemany_mode"] = settings.SEAGULL_DB_EXECUTEMANY_MODE or "values_plus_batch"
        kwargs["executemany_values_page_size"] = max(100, int(settings.SEAGULL_DB_EXECUTEMANY_VALUES_PAGE_SIZE or 1000))

    try:
        return create_engine(database_url, **kwargs)
    except TypeError:
        # Fallback for environments where these kwargs are not supported.
        kwargs.pop("pool_size", None)
        kwargs.pop("max_overflow", None)
        kwargs.pop("executemany_mode", None)
        kwargs.pop("executemany_values_page_size", None)
        return create_engine(database_url, **kwargs)


engine = _make_engine()

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    future=True,
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
