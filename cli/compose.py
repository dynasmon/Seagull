from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Optional

from . import env as _env


_BASE_FILES = [
    "compose.base.yml",
    "compose.data.yml",
    "compose.backend.yml",
    "compose.portal.yml",
    "compose.observability.yml",
    "compose.agents.yml",
]

DEV_FILES = _BASE_FILES + ["compose.dev.yml"]
DEV_TLS_FILES = DEV_FILES + ["compose.dev.tls.yml"]
PROD_FILES = _BASE_FILES + ["compose.prod.yml"]

PROD_CORE_SERVICES = [
    "postgres", "redis", "elasticsearch", "clickhouse",
    "seagull-backend", "seagull-ingest-pipeline",
    "seagull-intelligence-worker", "seagull-maintenance-worker",
    "seagull-portal", "caddy",
]

PROD_AGENT_SERVICES = ["seagull-agent-core", "seagull-agent-sensor"]
DEV_AGENT_SERVICES = ["seagull-agent-core", "seagull-agent-sensor"]


def _file_flags(files: list[str]) -> list[str]:
    flags: list[str] = []
    for f in files:
        flags += ["-f", f]
    return flags


def _redis_env(persist: bool) -> dict[str, str]:
    if not persist:
        return {}
    return {
        "SEAGULL_REDIS_DEV_CONFIG": "redis.dev.persist.conf",
        "SEAGULL_REDIS_STOP_GRACE_PERIOD": "30s",
    }


def run(
    files: list[str],
    args: list[str],
    persist_redis: bool = False,
    check: bool = False,
    cwd: Optional[Path] = None,
) -> subprocess.CompletedProcess:
    env = {**os.environ, **_redis_env(persist_redis)}
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
