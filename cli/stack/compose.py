from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Optional

from ..config import env as _env


STACK_FILES = ["compose.yml"]
DEV_RELOAD_FILES = ["compose.yml", "compose.dev-reload.yml"]
LOCAL_OVERRIDE_FILE = "compose.override.yml"

PROD_CORE_SERVICES = [
    "postgres", "redis", "elasticsearch", "clickhouse",
    "seagull-backend", "seagull-ingest-pipeline",
    "seagull-intelligence-worker", "seagull-maintenance-worker",
    "seagull-portal", "caddy",
]


def local_override_files() -> list[str]:
    if (_env.root() / LOCAL_OVERRIDE_FILE).exists():
        return [LOCAL_OVERRIDE_FILE]
    return []


def _file_flags(files: list[str]) -> list[str]:
    flags: list[str] = []
    for f in list(files) + local_override_files():
        flags += ["-f", f]
    return flags


def _persist_redis_env() -> dict[str, str]:
    return {
        "SEAGULL_REDIS_CONFIG": "redis.dev.persist.conf",
        "SEAGULL_REDIS_STOP_GRACE_PERIOD": "30s",
    }


def pki_group_id() -> int:
    root = _env.root()
    candidates = (
        root / "secrets" / "pki" / "agent-ca.key",
        root / "secrets" / "pki" / "server" / "mtls.key",
        root / "secrets" / "pki",
    )
    for path in candidates:
        try:
            return os.stat(path).st_gid
        except OSError:
            continue
    return os.getgid()


def run(
    files: list[str],
    args: list[str],
    persist_redis: bool = False,
    check: bool = False,
    cwd: Optional[Path] = None,
) -> subprocess.CompletedProcess:
    env = {**os.environ}
    env.setdefault("SEAGULL_PKI_GID", str(pki_group_id()))
    if persist_redis:
        env.update(_persist_redis_env())
    cmd = ["docker", "compose"] + _file_flags(files) + args
    return subprocess.run(
        cmd,
        cwd=str(cwd or _env.root()),
        env=env,
        check=check,
    )


def validate(files: list[str]) -> bool:
    result = run(files, ["config", "-q"])
    return result.returncode == 0
