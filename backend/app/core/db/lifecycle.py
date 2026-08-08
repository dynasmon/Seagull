from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.exc import DBAPIError, OperationalError

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from alembic.util import CommandError
from app.core.config import settings

from .engine import engine
from .locks import advisory_lock
from .schema_bootstrap import bootstrap_schema


class FatalStartupError(RuntimeError):
    pass


_UNKNOWN_REVISION = re.compile(r"Can't locate revision identified by '([^']+)'")


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

    with advisory_lock(8_642_701):
        command.upgrade(cfg, "head")


@dataclass(frozen=True)
class SchemaStatus:
    current: str | None
    head: str | None
    known: bool

    @property
    def drifted(self) -> bool:
        return self.current != self.head


def schema_status() -> SchemaStatus:
    script = ScriptDirectory.from_config(_alembic_config())
    head = script.get_current_head()

    with engine.connect() as conn:
        current = MigrationContext.configure(conn).get_current_revision()

    if current is None:
        return SchemaStatus(current=None, head=head, known=True)

    try:
        known = script.get_revision(current) is not None
    except CommandError:
        known = False

    return SchemaStatus(current=current, head=head, known=known)


def is_schema_current() -> bool:
    return not schema_status().drifted


def ensure_database_ready() -> None:
    try:
        if settings.SEAGULL_DB_AUTO_UPGRADE:
            run_migrations()
        else:
            status = schema_status()
            if not status.known:
                raise _unknown_revision_error(str(status.current), status.head)
            if status.drifted:
                raise FatalStartupError(
                    "Database schema is not at Alembic head "
                    f"(database={status.current!r}, head={status.head!r}). "
                    "Run 'alembic upgrade head' (in backend/) or set SEAGULL_DB_AUTO_UPGRADE=true."
                )

        # Runtime-safe post-migration bootstrap (indexes/checks/seeds).
        bootstrap_schema(engine)
    except Exception as exc:
        raise _runtime_db_error(exc) from exc


def _script_head() -> str | None:
    try:
        return ScriptDirectory.from_config(_alembic_config()).get_current_head()
    except Exception:
        return None


def _unknown_revision_error(revision: str, head: str | None = None) -> FatalStartupError:
    head = head or _script_head()
    downgrade_hint = (
        f"run 'alembic downgrade {head}' in backend/, then return to this branch"
        if head
        else "downgrade it to a revision this build contains, then return to this branch"
    )
    return FatalStartupError(
        f"Database is stamped with Alembic revision {revision!r}, which does not exist in "
        f"this build (migration head is {head!r}). The database was migrated by a branch "
        "whose migration files are not in the current checkout, so no upgrade path can be "
        "resolved.\n"
        "Fix options:\n"
        f"1) Keep data: check out the branch that owns {revision!r}, {downgrade_hint}.\n"
        "2) Reset disposable local state: run './seagull nuke' then './seagull up'."
    )


def _runtime_db_error(exc: Exception) -> Exception:
    if isinstance(exc, CommandError):
        match = _UNKNOWN_REVISION.search(str(exc))
        return _unknown_revision_error(match.group(1)) if match else exc

    if not isinstance(exc, (OperationalError, DBAPIError)):
        return exc

    msg = str(exc).strip()
    msg_lower = msg.lower()

    if "password authentication failed for user" in msg_lower:
        user = settings.DB_USER or settings.DB_NAME or "seagull"
        return RuntimeError(
            "PostgreSQL authentication failed during startup "
            f"(user={user!r}). This usually means credentials in .env no longer "
            "match the existing postgres-data volume.\n"
            "Fix options:\n"
            "1) Keep data: restore POSTGRES_PASSWORD/SEAGULL_DB_PASSWORD to the "
            "password used when the volume was first initialized.\n"
            "2) Reset disposable local state: run 'make nuke' then 'make dev'."
        )

    if "database" in msg_lower and "does not exist" in msg_lower:
        return RuntimeError(
            "PostgreSQL is reachable, but the configured database does not exist. "
            "Verify POSTGRES_DB/SEAGULL_DB_NAME and re-run 'make dev'."
        )

    return exc
