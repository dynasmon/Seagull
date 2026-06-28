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
    monkeypatch.setattr(cli_main._systemd, "sync_ca", lambda: 0)
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
    monkeypatch.setattr(cli_main._tokens, "mint", lambda *args, **kwargs: mint_calls.append((args, kwargs)))

    rc = cli_main._up_prod(fresh=False)

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
    monkeypatch.setattr(cli_main._geoip, "ensure", lambda: False)
    monkeypatch.setattr(cli_main._preflight, "run", lambda: None)
    monkeypatch.setenv("SEAGULL_SKIP_AGENT_RECONCILE", "false")
    monkeypatch.setattr(cli_main.shutil, "which", lambda name: "/usr/bin/systemctl")
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
        )
    )

    assert rc == 0
    assert len(run_calls) == 2
    assert len(reconcile_calls) == 1


def test_cmd_up_ensures_geoip_before_starting_stack(monkeypatch) -> None:
    calls = []

    monkeypatch.setattr(cli_main._env, "bootstrap", lambda: calls.append("bootstrap"))
    monkeypatch.setattr(cli_main._env, "read", lambda key, default="": "dev" if key == "SEAGULL_MODE" else default)
    monkeypatch.setattr(cli_main._geoip, "ensure", lambda: calls.append("geoip") or False)
    monkeypatch.setattr(
        cli_main,
        "_up_dev",
        lambda files, persist: calls.append("up") or 0,
    )

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
    monkeypatch.setattr(cli_main._health, "wait_healthy", lambda *a, **k: True)
    monkeypatch.setattr(cli_main._health, "print_summary", lambda *a, **k: None)


def test_up_dev_skips_agent_when_systemd_absent(monkeypatch) -> None:
    run_calls, sync_calls = [], []
    _dev_stack_up(monkeypatch, run_calls)
    monkeypatch.setenv("SEAGULL_SKIP_AGENT_RECONCILE", "false")
    monkeypatch.setattr(cli_main.shutil, "which", lambda name: None)
    monkeypatch.setattr(cli_main._systemd, "sync_ca", lambda: sync_calls.append(True) or 0)

    rc = cli_main._up_dev(files=["compose.yml"], persist=False)

    assert rc == 0
    assert sync_calls == []
    assert len(run_calls) == 1


def test_up_dev_skips_agent_when_flag_set(monkeypatch) -> None:
    run_calls, sync_calls = [], []
    _dev_stack_up(monkeypatch, run_calls)
    monkeypatch.setenv("SEAGULL_SKIP_AGENT_RECONCILE", "true")
    monkeypatch.setattr(cli_main.shutil, "which", lambda name: "/usr/bin/systemctl")
    monkeypatch.setattr(cli_main._systemd, "sync_ca", lambda: sync_calls.append(True) or 0)

    rc = cli_main._up_dev(files=["compose.yml"], persist=False)

    assert rc == 0
    assert sync_calls == []


def test_up_dev_agent_failure_is_non_fatal(monkeypatch) -> None:
    run_calls = []
    _dev_stack_up(monkeypatch, run_calls)
    monkeypatch.setenv("SEAGULL_SKIP_AGENT_RECONCILE", "false")
    monkeypatch.setattr(cli_main.shutil, "which", lambda name: "/usr/bin/systemctl")
    monkeypatch.setattr(cli_main._systemd, "sync_ca", lambda: 1)
    monkeypatch.setattr(cli_main, "_reconcile_systemd_agent", lambda: 1)

    rc = cli_main._up_dev(files=["compose.yml"], persist=False)

    assert rc == 0


def test_up_dev_agent_exception_is_non_fatal(monkeypatch) -> None:
    run_calls = []
    _dev_stack_up(monkeypatch, run_calls)
    monkeypatch.setenv("SEAGULL_SKIP_AGENT_RECONCILE", "false")
    monkeypatch.setattr(cli_main.shutil, "which", lambda name: "/usr/bin/systemctl")

    def _boom():
        raise FileNotFoundError("sudo")

    monkeypatch.setattr(cli_main._systemd, "sync_ca", _boom)

    rc = cli_main._up_dev(files=["compose.yml"], persist=False)

    assert rc == 0


def test_up_dev_still_fails_when_stack_unhealthy(monkeypatch) -> None:
    run_calls = []
    _dev_stack_up(monkeypatch, run_calls)
    monkeypatch.setattr(cli_main._health, "wait_healthy", lambda *a, **k: False)
    sync_calls = []
    monkeypatch.setattr(cli_main.shutil, "which", lambda name: "/usr/bin/systemctl")
    monkeypatch.setattr(cli_main._systemd, "sync_ca", lambda: sync_calls.append(True) or 0)

    rc = cli_main._up_dev(files=["compose.yml"], persist=False)

    assert rc == 1
    assert sync_calls == []


def test_up_dev_fails_when_compose_up_fails(monkeypatch) -> None:
    monkeypatch.setattr(cli_main._preflight, "run", lambda: None)
    monkeypatch.setattr(
        cli_main._compose, "run",
        lambda files, args, persist_redis=False: SimpleNamespace(returncode=1),
    )

    rc = cli_main._up_dev(files=["compose.yml"], persist=False)

    assert rc == 1
