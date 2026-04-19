from __future__ import annotations

from types import SimpleNamespace

from cli import main as cli_main


def test_up_prod_stops_on_failed_core_health(monkeypatch) -> None:
    run_calls = []
    mint_calls = []
    commit_calls = []
    summary_calls = []

    monkeypatch.setattr(cli_main._prepare, "run", lambda: None)
    monkeypatch.setattr(cli_main._state, "check", lambda: (cli_main._state.OK, ""))
    monkeypatch.setattr(cli_main._state, "commit", lambda: commit_calls.append(True))
    monkeypatch.setattr(cli_main._compose, "STACK_FILES", ["compose.yml"])
    monkeypatch.setattr(cli_main._compose, "PROD_CORE_SERVICES", ["postgres"])
    monkeypatch.setattr(cli_main._compose, "PROD_AGENT_SERVICES", ["seagull-agent-core"])
    monkeypatch.setattr(
        cli_main._compose,
        "run",
        lambda files, args, persist_redis=False: run_calls.append((tuple(files), tuple(args), persist_redis))
        or SimpleNamespace(returncode=0),
    )
    monkeypatch.setattr(cli_main._health, "wait_healthy", lambda *args, **kwargs: False)
    monkeypatch.setattr(cli_main._health, "print_summary", lambda *args, **kwargs: summary_calls.append((args, kwargs)))
    monkeypatch.setattr(cli_main._tokens, "mint", lambda *args, **kwargs: mint_calls.append((args, kwargs)))

    rc = cli_main._up_prod(fresh=False, systemd_agent=False)

    assert rc == 1
    assert len(run_calls) == 1
    assert mint_calls == []
    assert commit_calls == []
    assert len(summary_calls) == 1
