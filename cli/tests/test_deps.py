from __future__ import annotations

import subprocess

import cli.main as cli_main
from cli.stack import deps as cli_deps


def test_check_flags_missing_commands(monkeypatch) -> None:
    monkeypatch.setattr(cli_deps.shutil, "which", lambda name: None)
    results = {name: ok for name, ok, _ in cli_deps.check(include_agent_build=False)}
    assert results["docker"] is False
    assert results["jq"] is False
    assert "docker compose" not in results
    assert "docker daemon" not in results


def test_platform_check_excludes_agent_build_toolchain(monkeypatch) -> None:
    monkeypatch.setattr(cli_deps.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(cli_deps, "_output", lambda cmd: "v2.27.0")
    monkeypatch.setattr(cli_deps, "_ok", lambda cmd: True)
    names = [name for name, _, _ in cli_deps.check(include_agent_build=False)]
    assert "gcc" not in names
    assert "libpcap headers" not in names
    assert "systemctl" not in names
    assert not any(name.startswith("go ") for name in names)


def test_agent_build_check_is_opt_in(monkeypatch) -> None:
    monkeypatch.setattr(cli_deps.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        cli_deps, "_output",
        lambda cmd: "go version go1.22.2 linux/amd64" if cmd[0] == "go" else "v2.27.0",
    )
    monkeypatch.setattr(cli_deps, "_ok", lambda cmd: True)
    names = [name for name, _, _ in cli_deps.check(include_agent_build=True)]
    assert "gcc" in names
    assert "libpcap headers" in names
    assert "systemctl" in names


def test_agent_build_follows_local_reconcile_flag(monkeypatch) -> None:
    monkeypatch.setattr(cli_deps.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        cli_deps, "_output",
        lambda cmd: "go version go1.22.2 linux/amd64" if cmd[0] == "go" else "v2.27.0",
    )
    monkeypatch.setattr(cli_deps, "_ok", lambda cmd: True)

    monkeypatch.setenv("SEAGULL_AGENT_LOCAL_RECONCILE", "false")
    assert "gcc" not in [name for name, _, _ in cli_deps.check()]

    monkeypatch.setenv("SEAGULL_AGENT_LOCAL_RECONCILE", "true")
    assert "gcc" in [name for name, _, _ in cli_deps.check()]


def test_check_rejects_old_go(monkeypatch) -> None:
    monkeypatch.setattr(cli_deps.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        cli_deps, "_output",
        lambda cmd: "go version go1.19.8 linux/amd64" if cmd[0] == "go" else "v2.27.0",
    )
    monkeypatch.setattr(cli_deps, "_ok", lambda cmd: True)
    results = {name: ok for name, ok, _ in cli_deps.check(include_agent_build=True)}
    assert results["go (>= 1.21)"] is False


def test_check_accepts_current_go(monkeypatch) -> None:
    monkeypatch.setattr(cli_deps.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        cli_deps, "_output",
        lambda cmd: "go version go1.22.2 linux/amd64" if cmd[0] == "go" else "v2.27.0",
    )
    monkeypatch.setattr(cli_deps, "_ok", lambda cmd: True)
    results = {name: ok for name, ok, _ in cli_deps.check(include_agent_build=True)}
    assert results["go (>= 1.21)"] is True
    assert results["docker compose"] is True
    assert results["docker daemon"] is True


def test_print_report_returns_nonzero_on_missing(capsys) -> None:
    rc = cli_deps.print_report([("docker", True, ""), ("jq", False, "jq not found in PATH")])
    out = capsys.readouterr().out
    assert rc == 1
    assert "MISSING" in out
    assert cli_deps.INSTALL_HINT in out


def test_install_uses_sudo_for_non_root(monkeypatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(cli_deps.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        cli_deps.subprocess, "run",
        lambda cmd, cwd=None: calls.append(cmd) or subprocess.CompletedProcess(cmd, 0),
    )
    monkeypatch.setattr(cli_deps, "check_and_report", lambda: 0)
    assert cli_deps.install() == 0
    assert calls and calls[0][:2] == ["sudo", "bash"]
    assert calls[0][2].endswith("deploy/install-deps.sh")


def test_dash_d_alias_runs_deps_check(monkeypatch) -> None:
    seen: list[bool] = []
    monkeypatch.setattr(
        cli_main._deps, "check_and_report",
        lambda **kwargs: seen.append(True) or 0,
    )
    monkeypatch.setattr(cli_main.sys, "argv", ["seagull", "-d"])
    assert cli_main.main() == 0
    assert seen == [True]


def test_dash_d_install_alias_runs_installer(monkeypatch) -> None:
    seen: list[bool] = []
    monkeypatch.setattr(cli_main._deps, "install", lambda: seen.append(True) or 0)
    monkeypatch.setattr(cli_main.sys, "argv", ["seagull", "-d", "--install"])
    assert cli_main.main() == 0
    assert seen == [True]


def test_missing_host_dependency_proxy_raises_actionable_error() -> None:
    proxy = cli_main._MissingHostDependency("cryptography")
    try:
        proxy.run()
    except RuntimeError as exc:
        assert "cryptography" in str(exc)
        assert cli_deps.INSTALL_HINT in str(exc)
    else:
        raise AssertionError("expected RuntimeError")
