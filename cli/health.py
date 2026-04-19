from __future__ import annotations

import json
import subprocess
import sys
import time

from . import compose as _compose
from . import env as _env


ESSENTIAL_DEV = ["postgres", "redis", "seagull-backend"]
ESSENTIAL_PROD = [
    "postgres", "redis", "elasticsearch",
    "seagull-backend", "seagull-ingest-pipeline",
]


def _ps_records(files: list[str]) -> list[dict]:
    result = subprocess.run(
        ["docker", "compose"] + _compose._file_flags(files) + ["ps", "--format", "json"],
        capture_output=True,
        text=True,
        cwd=str(_env.root()),
    )
    if result.returncode != 0:
        return []
    records: list[dict] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, list):
                records.extend(obj)
            else:
                records.append(obj)
        except json.JSONDecodeError:
            pass
    return records


def _match_service(record: dict, name: str) -> bool:
    svc = record.get("Service", "") or record.get("Name", "")
    return svc == name or svc.endswith(f"_{name}") or svc.endswith(f"-{name}")


def _service_ok(records: list[dict], name: str) -> bool:
    for r in records:
        if not _match_service(r, name):
            continue
        state = (r.get("State", "") or "").lower()
        health = (r.get("Health", "") or "").lower()
        if state != "running":
            return False
        return health in ("", "healthy")
    return False


def _service_label(records: list[dict], name: str) -> str:
    for r in records:
        if not _match_service(r, name):
            continue
        state = (r.get("State", "") or "").lower()
        health = (r.get("Health", "") or "").lower()
        if health:
            return health
        return state
    return "missing"


def wait_healthy(
    files: list[str],
    services: list[str],
    timeout: int = 120,
    interval: float = 3.0,
) -> bool:
    print(f"[up] waiting for {len(services)} service(s) to be ready (up to {timeout}s)...")
    start = time.monotonic()
    last_labels: dict[str, str] = {}

    while time.monotonic() - start < timeout:
        records = _ps_records(files)
        labels = {svc: _service_label(records, svc) for svc in services}

        if labels != last_labels:
            for svc, label in labels.items():
                marker = "✓" if label in ("running", "healthy") else "…"
                print(f"  {marker} {svc}: {label}")
            last_labels = labels

        if all(_service_ok(records, svc) for svc in services):
            elapsed = int(time.monotonic() - start)
            print(f"[up] all core services ready ({elapsed}s)")
            return True

        time.sleep(interval)

    print(
        f"[up] timeout: not all services became healthy within {timeout}s",
        file=sys.stderr,
    )
    return False


def print_summary(files: list[str]) -> None:
    subprocess.run(
        ["docker", "compose"] + _compose._file_flags(files) + ["ps"],
        cwd=str(_env.root()),
    )
