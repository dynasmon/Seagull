from __future__ import annotations

from types import SimpleNamespace

from cli import main as cli_main
from cli.stack import systemd as cli_systemd


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


def test_reconcile_systemd_agent_repairs_invalid_install(monkeypatch) -> None:
    mint_calls = []
    install_calls = []

    def _raise_validate():
        raise cli_systemd.ValidationError("broken")

    monkeypatch.setattr(cli_main._systemd, "validate", _raise_validate)
    monkeypatch.setattr(cli_main._systemd, "is_active", lambda: False)
    monkeypatch.setattr(cli_main._systemd, "installed_agent_id", lambda: "agent-core-1")
    monkeypatch.setattr(cli_main._tokens, "mint", lambda *args, **kwargs: mint_calls.append((args, kwargs)))
    monkeypatch.setattr(cli_main._systemd, "repo_bootstrap_token_for_agent", lambda agent_id: "abt.agent-core-1.fresh" if agent_id == "agent-core-1" else "")
    monkeypatch.setattr(
        cli_main._systemd,
        "install",
        lambda *, bootstrap_token=None: install_calls.append(bootstrap_token) or 0,
    )

    validations = iter([cli_systemd.ValidationError("broken"), None])

    def _validate_after_repair():
        result = next(validations)
        if isinstance(result, Exception):
            raise result
        return None

    monkeypatch.setattr(cli_main._systemd, "validate", _validate_after_repair)
    monkeypatch.setattr(cli_main._systemd, "is_active", lambda: True)

    rc = cli_main._reconcile_systemd_agent()

    assert rc == 0
    assert len(mint_calls) == 1
    assert install_calls == ["abt.agent-core-1.fresh"]


def test_cmd_restart_systemd_reconciles_after_compose_up(monkeypatch) -> None:
    run_calls = []
    reconcile_calls = []

    monkeypatch.setattr(cli_main._env, "bootstrap", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli_main._preflight, "run", lambda: None)
    monkeypatch.setattr(cli_main._systemd, "sync_ca", lambda: 0)
    monkeypatch.setattr(
        cli_main._compose,
        "run",
        lambda files, args, persist_redis=False: run_calls.append((tuple(files), tuple(args), persist_redis))
        or SimpleNamespace(returncode=0),
    )
    monkeypatch.setattr(cli_main, "_reconcile_systemd_agent", lambda: reconcile_calls.append(True) or 0)

    rc = cli_main.cmd_restart(
        SimpleNamespace(
            persist=False,
            quick=False,
            dev_reload=False,
            systemd_agent=False,
            agent_mode="systemd",
        )
    )

    assert rc == 0
    assert len(run_calls) == 2
    assert len(reconcile_calls) == 1
