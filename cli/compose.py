from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Optional

from . import env as _env


STACK_FILES = ["compose.yml"]
DEV_RELOAD_FILES = ["compose.yml", "compose.dev-reload.yml"]

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


def _persist_redis_env() -> dict[str, str]:
    return {
        "SEAGULL_REDIS_CONFIG": "redis.dev.persist.conf",
        "SEAGULL_REDIS_STOP_GRACE_PERIOD": "30s",
    }


def run(
    files: list[str],
    args: list[str],
    persist_redis: bool = False,
    check: bool = False,
    cwd: Optional[Path] = None,
) -> subprocess.CompletedProcess:
    env = {**os.environ}
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
