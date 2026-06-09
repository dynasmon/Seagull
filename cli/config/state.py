from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Optional

from . import env as _env


_SCHEMA_VERSION = "2"

_FINGERPRINT_KEYS = [
    "POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD",
    "SEAGULL_REDIS_PASSWORD", "SEAGULL_ES_USERNAME", "SEAGULL_ES_PASSWORD",
    "SEAGULL_JWT_SECRET", "SEAGULL_BOOTSTRAP_ADMIN_PASSWORD",
    "SEAGULL_AUDIT_HASH_PEPPER",
    "AGENT_CORE_ID", "AGENT_SENSOR_ID", "AGENT_LATERAL_ID",
]

_MANAGED_VOLUMES = [
    "postgres-data", "redis-data", "elastic-data",
    "clickhouse-data", "caddy-data", "caddy-config",
]

OK = "ok"
NO_STATE = "no_state"
DRIFT = "drift"
ORPHAN_VOLUMES = "orphan_volumes"


def _state_dir() -> Path:
    return _env.root() / "secrets" / "runtime"


def _state_file() -> Path:
    return _state_dir() / "prod-state.json"


def _project_name() -> str:
    name = os.environ.get("COMPOSE_PROJECT_NAME", "")
    if not name:
        import re
        name = _env.root().name.lower()
        name = re.sub(r"[^a-z0-9]+", "-", name).strip("-")
    return name


def _read_env_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text().splitlines():
        if not raw or raw.startswith("#") or "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        values[key] = value
    return values


def _file_sha(path_str: str) -> str:
    if not path_str:
        return ""
    p = Path(path_str)
    return sha256(p.read_bytes()).hexdigest() if p.exists() and p.is_file() else ""


def fingerprint(env_file: Optional[Path] = None) -> str:
    path = env_file or _env.env_path()
    values = _read_env_values(path)
    redis_file = values.get("SEAGULL_REDIS_PASSWORD_FILE", "")
    payload = {
        "schema_version": _SCHEMA_VERSION,
        "project_name": _project_name(),
        "keys": {k: values.get(k, "") for k in _FINGERPRINT_KEYS},
        "file_keys": {
            "SEAGULL_REDIS_PASSWORD_FILE": {
                "path": redis_file,
                "sha256": _file_sha(redis_file),
            },
        },
    }
    return sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def _existing_managed_volumes() -> list[str]:
    try:
        result = subprocess.run(
            ["docker", "volume", "ls", "--format", "{{.Name}}"],
            capture_output=True, text=True, check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return []
    project = _project_name()
    existing = set(result.stdout.splitlines())
    return [f"{project}_{v}" for v in _MANAGED_VOLUMES if f"{project}_{v}" in existing]


def check(env_file: Optional[Path] = None) -> tuple[str, str]:
    sf = _state_file()
    fp = fingerprint(env_file)

    if not sf.exists():
        volumes = _existing_managed_volumes()
        if volumes:
            msg = (
                "[prod-state] existing runtime volumes found without a state marker; "
                "forcing one-time reset for a deterministic first production boot\n"
                + "\n".join(volumes)
            )
            return ORPHAN_VOLUMES, msg
        return NO_STATE, ""

    try:
        data = json.loads(sf.read_text())
    except Exception:
        return DRIFT, "[prod-state] corrupt state file; reset required"

    if data.get("schema_version") != _SCHEMA_VERSION:
        return DRIFT, "[prod-state] stored runtime schema version changed; reset required"
    if data.get("project_name") != _project_name():
        stored = data.get("project_name", "")
        current = _project_name()
        return DRIFT, f"[prod-state] compose project name changed from '{stored}' to '{current}'; reset required"
    if data.get("fingerprint") != fp:
        return DRIFT, "[prod-state] critical production secrets/config changed since the last successful boot; reset required"

    return OK, ""


def commit(env_file: Optional[Path] = None) -> None:
    sd = _state_dir()
    sd.mkdir(parents=True, exist_ok=True)
    sd.chmod(0o700)
    sf = _state_file()
    data = {
        "schema_version": _SCHEMA_VERSION,
        "project_name": _project_name(),
        "fingerprint": fingerprint(env_file),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    sf.write_text(json.dumps(data, indent=2) + "\n")
    sf.chmod(0o600)
    print("[prod-state] recorded runtime state fingerprint")


def clear() -> None:
    sf = _state_file()
    if sf.exists():
        sf.unlink()
