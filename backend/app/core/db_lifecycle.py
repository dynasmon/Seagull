from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import text

from app.core.config import settings
from app.core.db import engine
from app.core.schema_bootstrap import bootstrap_schema


def _backend_root() -> Path:
    # Docker image runs from /app, local repo runs from backend/.
    cwd = Path.cwd()
    if (cwd / "alembic.ini").exists() and (cwd / "alembic").exists():
        return cwd
    if (cwd / "backend" / "alembic.ini").exists() and (cwd / "backend" / "alembic").exists():
        return cwd / "backend"
    return cwd


def _alembic_config() -> Config:
    root = _backend_root()
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "alembic"))
    cfg.set_main_option("sqlalchemy.url", settings.database_url)
    return cfg


def run_migrations() -> None:
    cfg = _alembic_config()
    if engine.dialect.name != "postgresql":
        command.upgrade(cfg, "head")
        return

    # Serialize schema upgrades across concurrently starting containers.
    # The lock is released automatically when this connection closes.
    lock_id = 8_642_701
    with engine.connect() as conn:
        conn.execute(text("SELECT pg_advisory_lock(:id)"), {"id": lock_id})
        try:
            command.upgrade(cfg, "head")
        finally:
            conn.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": lock_id})


def is_schema_current() -> bool:
    cfg = _alembic_config()
    script = ScriptDirectory.from_config(cfg)
    head = script.get_current_head()

    with engine.connect() as conn:
        context = MigrationContext.configure(conn)
        current = context.get_current_revision()

    return current == head


def ensure_database_ready() -> None:
    if settings.NETWATCH_DB_AUTO_UPGRADE:
        run_migrations()
    elif not is_schema_current():
        raise RuntimeError(
            "Database schema is not at Alembic head. "
            "Run 'alembic upgrade head' (in backend/) or set NETWATCH_DB_AUTO_UPGRADE=true."
        )

    # Runtime-safe post-migration bootstrap (indexes/checks/seeds).
    bootstrap_schema(engine)
