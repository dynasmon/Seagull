from __future__ import annotations

import os

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "sqlite:///./test.db")

import pytest

from app import main as app_main
from app.core.db.lifecycle import FatalStartupError


def test_main_process_is_never_aborted(monkeypatch) -> None:
    monkeypatch.setattr(app_main.multiprocessing, "parent_process", lambda: None)
    monkeypatch.setattr(app_main.os, "kill", lambda *a: pytest.fail("signalled the parent"))
    monkeypatch.setattr(app_main.os, "_exit", lambda *a: pytest.fail("exited the process"))

    app_main._abort_supervised_worker()


def test_supervised_worker_signals_its_supervisor_and_exits(monkeypatch) -> None:
    killed: list[tuple[int, int]] = []
    exited: list[int] = []
    monkeypatch.setattr(app_main.multiprocessing, "parent_process", lambda: object())
    monkeypatch.setattr(app_main.os, "getppid", lambda: 4242)
    monkeypatch.setattr(app_main.os, "kill", lambda pid, sig: killed.append((pid, sig)))
    monkeypatch.setattr(app_main.os, "_exit", lambda code: exited.append(code))

    app_main._abort_supervised_worker()

    assert killed == [(4242, app_main.signal.SIGTERM)]
    assert exited == [app_main._FATAL_STARTUP_EXIT_CODE]


def test_worker_still_exits_when_the_supervisor_is_already_gone(monkeypatch) -> None:
    exited: list[int] = []

    def _raise(pid: int, sig: int) -> None:
        raise ProcessLookupError

    monkeypatch.setattr(app_main.multiprocessing, "parent_process", lambda: object())
    monkeypatch.setattr(app_main.os, "kill", _raise)
    monkeypatch.setattr(app_main.os, "_exit", lambda code: exited.append(code))

    app_main._abort_supervised_worker()

    assert exited == [app_main._FATAL_STARTUP_EXIT_CODE]


def test_fatal_startup_is_reported_on_stderr(capsys) -> None:
    app_main._report_fatal_startup(FatalStartupError("revision '0035' is not in this build"))

    err = capsys.readouterr().err
    assert "FATAL" in err
    assert "revision '0035' is not in this build" in err
