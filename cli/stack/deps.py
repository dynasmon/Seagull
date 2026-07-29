from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from ..config import env as _env


GO_MIN = (1, 21)
PCAP_HEADER_PATHS = ("/usr/include/pcap.h", "/usr/include/pcap/pcap.h")
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


def _go_status() -> tuple[bool, str]:
    if not shutil.which("go"):
        return False, "go toolchain not found"
    raw = _output(["go", "version"])
    match = re.search(r"go(\d+)\.(\d+)", raw)
    if not match:
        return False, "could not parse go version"
    version = (int(match.group(1)), int(match.group(2)))
    label = f"go{match.group(1)}.{match.group(2)}"
    if version < GO_MIN:
        return False, f"{label} is older than go{GO_MIN[0]}.{GO_MIN[1]}"
    parts = raw.split()
    return True, parts[2] if len(parts) > 2 else label


def _docker_daemon_status() -> tuple[bool, str]:
    if _ok(["docker", "info"]):
        return True, ""
    if Path("/var/run/docker.sock").exists():
        return False, (
            "no access to the docker daemon — add your user to the docker group, "
            "then log out and back in (or run: newgrp docker)"
        )
    return False, "docker daemon unreachable — start it: sudo systemctl enable --now docker"


def agent_build_enabled() -> bool:
    raw = os.environ.get("SEAGULL_AGENT_LOCAL_RECONCILE")
    if raw is None:
        raw = _env.read("SEAGULL_AGENT_LOCAL_RECONCILE", "false")
    return str(raw).strip().lower() in ("true", "1", "yes", "on")


def check(*, include_agent_build: bool | None = None) -> list[tuple[str, bool, str]]:
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

    if include_agent_build is None:
        include_agent_build = agent_build_enabled()
    if include_agent_build:
        results.extend(agent_build_check())

    return results


def agent_build_check() -> list[tuple[str, bool, str]]:
    results: list[tuple[str, bool, str]] = []

    go_ok, go_detail = _go_status()
    results.append((f"go (>= {GO_MIN[0]}.{GO_MIN[1]})", go_ok, go_detail))

    gcc_present = shutil.which("gcc") is not None
    results.append(("gcc", gcc_present, "" if gcc_present else "C compiler not found (agent build uses cgo)"))

    pcap_present = any(Path(p).exists() for p in PCAP_HEADER_PATHS)
    results.append((
        "libpcap headers", pcap_present,
        "" if pcap_present else "libpcap-dev (or libpcap-devel) not installed",
    ))

    for name in ("setcap", "systemctl"):
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


def check_and_report(*, include_agent_build: bool | None = None) -> int:
    return print_report(check(include_agent_build=include_agent_build))


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
