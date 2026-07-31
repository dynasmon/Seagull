from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

from ..config import env as _env


INSTALL_HINT = "./seagull -d --install"


def _output(cmd: list[str]) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if proc.returncode != 0:
        return ""
    return proc.stdout.strip()


def _ok(cmd: list[str]) -> bool:
    try:
        return subprocess.run(cmd, capture_output=True, timeout=15).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _docker_daemon_status() -> tuple[bool, str]:
    if _ok(["docker", "info"]):
        return True, ""
    if Path("/var/run/docker.sock").exists():
        return False, (
            "no access to the docker daemon — add your user to the docker group, "
            "then log out and back in (or run: newgrp docker)"
        )
    return False, "docker daemon unreachable — start it: sudo systemctl enable --now docker"


def check() -> list[tuple[str, bool, str]]:
    results: list[tuple[str, bool, str]] = []

    docker_present = shutil.which("docker") is not None
    results.append(("docker", docker_present, "" if docker_present else "docker engine not found"))
    if docker_present:
        compose_version = _output(["docker", "compose", "version", "--short"])
        results.append((
            "docker compose", bool(compose_version),
            compose_version or "compose plugin not installed",
        ))
        daemon_ok, daemon_hint = _docker_daemon_status()
        results.append(("docker daemon", daemon_ok, daemon_hint))

    crypto_present = importlib.util.find_spec("cryptography") is not None
    results.append((
        "python cryptography", crypto_present,
        "" if crypto_present else "python3-cryptography not installed (needed for the internal PKI)",
    ))

    for name in ("curl", "jq", "git", "sudo"):
        present = shutil.which(name) is not None
        results.append((name, present, "" if present else f"{name} not found in PATH"))

    return results


def print_report(results: list[tuple[str, bool, str]]) -> int:
    width = max(len(name) for name, _, _ in results)
    missing: list[str] = []
    for name, ok, detail in results:
        status = "ok     " if ok else "MISSING"
        line = f"[deps] {name.ljust(width)}  {status}"
        if detail:
            line += f"  {detail}"
        print(line)
        if not ok:
            missing.append(name)
    print()
    if missing:
        print(f"[deps] {len(missing)} issue(s): {', '.join(missing)}")
        print(f"[deps] fix: {INSTALL_HINT}")
        return 1
    print("[deps] all host dependencies satisfied")
    return 0


def check_and_report() -> int:
    return print_report(check())


def install() -> int:
    script = _env.root() / "deploy" / "install-deps.sh"
    if not script.exists():
        print(f"[deps] installer script not found: {script}", file=sys.stderr)
        return 1
    cmd = ["bash", str(script)]
    if os.geteuid() != 0:
        cmd = ["sudo"] + cmd
    rc = subprocess.run(cmd, cwd=str(_env.root())).returncode
    if rc != 0:
        return rc
    print()
    return check_and_report()
