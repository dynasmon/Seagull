from __future__ import annotations

from sqlalchemy.exc import OperationalError

from app.core import db_lifecycle


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
