from __future__ import annotations

from types import SimpleNamespace

from cli import main as cli_main


def test_up_prod_stops_on_failed_core_health(monkeypatch) -> None:
    run_calls = []
    commit_calls = []
    summary_calls = []

    monkeypatch.setattr(cli_main._prepare, "run", lambda: None)
    monkeypatch.setattr(cli_main._state, "check", lambda: (cli_main._state.OK, ""))
    monkeypatch.setattr(cli_main._state, "commit", lambda: commit_calls.append(True))
    monkeypatch.setattr(cli_main._compose, "STACK_FILES", ["compose.yml"])
    monkeypatch.setattr(cli_main._compose, "PROD_CORE_SERVICES", ["postgres"])
    monkeypatch.setattr(
        cli_main._compose,
        "run",
        lambda files, args, persist_redis=False: run_calls.append((tuple(files), tuple(args), persist_redis))
        or SimpleNamespace(returncode=0),
    )
    monkeypatch.setattr(cli_main._health, "wait_healthy", lambda *args, **kwargs: False)
    monkeypatch.setattr(cli_main._health, "print_summary", lambda *args, **kwargs: summary_calls.append((args, kwargs)))

    rc = cli_main._up_prod(fresh=False)

    assert rc == 1
    assert len(run_calls) == 1
    assert commit_calls == []
    assert len(summary_calls) == 1


def test_cmd_up_ensures_geoip_before_starting_stack(monkeypatch) -> None:
    calls = []

    monkeypatch.setattr(cli_main._env, "bootstrap", lambda: calls.append("bootstrap"))
    monkeypatch.setattr(cli_main._env, "environment", lambda: "dev")
    monkeypatch.setattr(cli_main._geoip, "ensure", lambda: calls.append("geoip") or False)
    monkeypatch.setattr(cli_main, "_up_dev", lambda files, persist: calls.append("up") or 0)

    rc = cli_main.cmd_up(SimpleNamespace(mode=None, persist=False, dev_reload=False, fresh=False))

    assert rc == 0
    assert calls == ["bootstrap", "geoip", "up"]


def _dev_stack_up(monkeypatch, run_calls):
    monkeypatch.setattr(cli_main._preflight, "run", lambda: None)
    monkeypatch.setattr(
        cli_main._compose,
        "run",
        lambda files, args, persist_redis=False: run_calls.append((tuple(files), tuple(args)))
        or SimpleNamespace(returncode=0),
    )
    monkeypatch.setattr(cli_main._health, "wait_healthy", lambda *args, **kwargs: True)
    monkeypatch.setattr(cli_main._health, "print_summary", lambda *args, **kwargs: None)


def test_up_dev_starts_only_the_platform_stack(monkeypatch) -> None:
    run_calls = []
    _dev_stack_up(monkeypatch, run_calls)

    rc = cli_main._up_dev(files=["compose.yml"], persist=False)

    assert rc == 0
    assert len(run_calls) == 1


def test_up_dev_still_fails_when_stack_unhealthy(monkeypatch) -> None:
    run_calls = []
    _dev_stack_up(monkeypatch, run_calls)
    monkeypatch.setattr(cli_main._health, "wait_healthy", lambda *args, **kwargs: False)

    rc = cli_main._up_dev(files=["compose.yml"], persist=False)

    assert rc == 1


def test_up_dev_fails_when_compose_up_fails(monkeypatch) -> None:
    monkeypatch.setattr(cli_main._preflight, "run", lambda: None)
    monkeypatch.setattr(
        cli_main._compose,
        "run",
        lambda files, args, persist_redis=False: SimpleNamespace(returncode=1),
    )

    rc = cli_main._up_dev(files=["compose.yml"], persist=False)

    assert rc == 1
