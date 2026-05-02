from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

from sqlalchemy.exc import OperationalError

from app.core.config import settings
from app.core.db.lifecycle import ensure_database_ready
from app.core.config.env_secrets import getenv_compat
from app.core.observability import log_event, setup_logging
from app.features.events import proto_intel_repository
from app.shared.protocol_intel import analyze_event


setup_logging("worker-proto-intel")
logger = logging.getLogger("seagull.worker.proto_intel")

OFFSET_PROTO_INTEL = "proto_intel_v1"


def _env_int(name: str, default: int) -> int:
    raw = getenv_compat(name)
    if raw is None:
        return default
    raw = raw.strip()
    if raw == "":
        return default
    try:
        return int(raw)
    except Exception:
        return default


def _env_float(name: str, default: float) -> float:
    raw = getenv_compat(name)
    if raw is None:
        return default
    raw = raw.strip()
    if raw == "":
        return default
    try:
        return float(raw)
    except Exception:
        return default


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _ensure_bootstrap() -> None:
    ensure_database_ready()
    proto_intel_repository.ensure_offset_row(OFFSET_PROTO_INTEL)


def _get_last_id() -> int:
    return proto_intel_repository.get_last_offset(OFFSET_PROTO_INTEL)


def _set_last_id(last_id: int) -> None:
    proto_intel_repository.set_last_offset(OFFSET_PROTO_INTEL, last_id)


def _pick_batch_max_id(last_id: int, max_rows: int) -> int:
    return proto_intel_repository.pick_batch_max_event_id(last_id, max_rows)


def _fetch_batch(last_id: int, max_id: int, batch_size: int) -> List[Dict[str, Any]]:
    return proto_intel_repository.fetch_unprocessed_batch(last_id=last_id, max_id=max_id, batch_size=batch_size)


def _patch_event(event_id: int, patch: Dict[str, Any]) -> None:
    proto_intel_repository.patch_event_proto_intel(event_id, patch)


def main() -> None:
    settings.validate_for_service("worker-proto-intel")
    every_s = _env_float("SEAGULL_PROTO_INTEL_EVERY_SECONDS", 1.0)
    idle_sleep_s = _env_float("SEAGULL_PROTO_INTEL_IDLE_SLEEP_SECONDS", 2.0)
    max_rows = _env_int("SEAGULL_PROTO_INTEL_MAX_ROWS", 5000)
    batch_size = _env_int("SEAGULL_PROTO_INTEL_BATCH_SIZE", 500)
    payload_max = _env_int("SEAGULL_PROTO_INTEL_PAYLOAD_MAX_BYTES", 4096)

    backoff = 1.0

    while True:
        try:
            _ensure_bootstrap()

            last_id = _get_last_id()
            max_id = _pick_batch_max_id(last_id, max_rows)

            if max_id <= last_id:
                time.sleep(idle_sleep_s)
                backoff = 1.0
                continue

            rows = _fetch_batch(last_id, max_id, batch_size)
            if not rows:
                _set_last_id(max_id)
                time.sleep(max(every_s, 0.1))
                backoff = 1.0
                continue

            last_done = last_id
            t0 = time.time()

            for r in rows:
                eid = int(r["id"])
                event_type = str(r.get("event_type") or "")
                proto = str(r.get("proto") or "")
                src_port = r.get("src_port")
                dst_port = r.get("dst_port")
                extra = r.get("extra") or {}
                if not isinstance(extra, dict):
                    extra = {}

                patch = analyze_event(
                    event_type=event_type,
                    proto=proto,
                    src_port=src_port,
                    dst_port=dst_port,
                    extra=extra,
                    payload_max_bytes=payload_max,
                )

                if not patch:
                    patch = {"proto_intel_at": _utc_now_iso()}

                _patch_event(eid, patch)
                last_done = eid

            _set_last_id(last_done)
            took_ms = int((time.time() - t0) * 1000)
            log_event(logger, "info", "proto_intel_ok", last_id=last_id, max_id=max_id, processed=len(rows), took_ms=took_ms)

            backoff = 1.0
            time.sleep(max(every_s, 0.1))

        except OperationalError as e:
            wait_s = min(backoff, 15.0)
            log_event(logger, "warning", "proto_intel_db_not_ready", wait_s=wait_s, error=str(e).splitlines()[0])
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 15.0)

        except Exception as e:
            wait_s = min(backoff, 30.0)
            log_event(logger, "error", "proto_intel_loop_error", wait_s=wait_s, error=repr(e))
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 30.0)


if __name__ == "__main__":
    main()
