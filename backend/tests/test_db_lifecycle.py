from __future__ import annotations

import os

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "sqlite:///./test.db")

from sqlalchemy.exc import OperationalError

from alembic.util import CommandError
from app.core.db import lifecycle as db_lifecycle


def test_runtime_db_error_for_password_auth_failure() -> None:
    exc = OperationalError(
        "SELECT 1",
        {},
        Exception('password authentication failed for user "seagull"'),
    )

    out = db_lifecycle._runtime_db_error(exc)
    assert isinstance(out, RuntimeError)
    assert "authentication failed" in str(out).lower()
    assert "make nuke" in str(out)


def test_runtime_db_error_for_missing_database() -> None:
    exc = OperationalError(
        "SELECT 1",
        {},
        Exception('database "missing_db" does not exist'),
    )

    out = db_lifecycle._runtime_db_error(exc)
    assert isinstance(out, RuntimeError)
    assert "does not exist" in str(out).lower()


def test_runtime_db_error_passthrough_for_non_db_exception() -> None:
    exc = RuntimeError("custom failure")
    out = db_lifecycle._runtime_db_error(exc)
    assert out is exc


def test_runtime_db_error_for_revision_missing_from_this_build() -> None:
    exc = CommandError("Can't locate revision identified by '20260803_0035'")

    out = db_lifecycle._runtime_db_error(exc)
    assert isinstance(out, db_lifecycle.FatalStartupError)
    assert "20260803_0035" in str(out)
    assert "seagull nuke" in str(out)


def test_runtime_db_error_passthrough_for_unrelated_command_error() -> None:
    exc = CommandError("Target database is not up to date.")
    assert db_lifecycle._runtime_db_error(exc) is exc


def test_unknown_revision_error_names_the_downgrade_target() -> None:
    out = db_lifecycle._unknown_revision_error("20260803_0035", "20260720_0033")

    assert isinstance(out, db_lifecycle.FatalStartupError)
    assert "alembic downgrade 20260720_0033" in str(out)


def test_unknown_revision_error_without_a_resolvable_head(monkeypatch) -> None:
    monkeypatch.setattr(db_lifecycle, "_script_head", lambda: None)

    out = db_lifecycle._unknown_revision_error("20260803_0035")
    assert isinstance(out, db_lifecycle.FatalStartupError)
    assert "20260803_0035" in str(out)
    assert "alembic downgrade" not in str(out)


def test_schema_status_reports_drift() -> None:
    assert db_lifecycle.SchemaStatus(current="a", head="b", known=True).drifted
    assert not db_lifecycle.SchemaStatus(current="a", head="a", known=True).drifted


def test_fatal_startup_error_is_a_runtime_error() -> None:
    assert issubclass(db_lifecycle.FatalStartupError, RuntimeError)
