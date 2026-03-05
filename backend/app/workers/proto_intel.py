"""Protocol intelligence worker.

This worker performs protocol-aware parsing on net_events to derive:
- DNS metadata (qname/qtype/rcode/answers)
- HTTP request metadata (host/method/path/user-agent)
- TLS fingerprints (JA3 + JA4) and basic TLS fields (SNI/ALPN/version)

The computed fields are stored in net_events.extra so APIs can aggregate quickly.

Important:
- The current Go agents may not send raw L7 bytes yet. In that case, the worker still
  populates a conservative app_proto guess based on ports/transport.
- As agents evolve to send ClientHello or L7 payload samples (base64), this worker will
  automatically start producing richer metadata.

Environment:
- NETWATCH_PROTO_INTEL_EVERY_SECONDS (default 1.0)
- NETWATCH_PROTO_INTEL_IDLE_SLEEP_SECONDS (default 2.0)
- NETWATCH_PROTO_INTEL_MAX_ROWS (default 5000)
- NETWATCH_PROTO_INTEL_BATCH_SIZE (default 500)
- NETWATCH_PROTO_INTEL_PAYLOAD_MAX_BYTES (default 4096)
- NETWATCH_PROTO_INTEL_PORT_HINTS (optional custom port->protocol hints)

Marker:
- proto_intel_at (RFC3339 UTC)
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from app.core.db import engine
from app.protocol_intel import analyze_event


OFFSET_PROTO_INTEL = "proto_intel_v1"


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
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
    raw = os.getenv(name)
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
    """Keep worker boot-safe when running in Compose."""

    with engine.begin() as conn:
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS search_index_offsets (
                    name TEXT PRIMARY KEY,
                    last_id INTEGER NOT NULL DEFAULT 0,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                );
                """
            )
        )
        conn.execute(
            text(
                """
                INSERT INTO search_index_offsets (name, last_id)
                VALUES (:n, 0)
                ON CONFLICT (name) DO NOTHING;
                """
            ),
            {"n": OFFSET_PROTO_INTEL},
        )


def _get_last_id() -> int:
    with engine.begin() as conn:
        row = conn.execute(text("SELECT last_id FROM search_index_offsets WHERE name=:n"), {"n": OFFSET_PROTO_INTEL}).fetchone()
        return int(row[0]) if row else 0


def _set_last_id(last_id: int) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO search_index_offsets (name, last_id)
                VALUES (:n, :id)
                ON CONFLICT (name) DO UPDATE
                SET last_id = EXCLUDED.last_id,
                    updated_at = now();
                """
            ),
            {"n": OFFSET_PROTO_INTEL, "id": int(last_id)},
        )


def _pick_batch_max_id(last_id: int, max_rows: int) -> int:
    with engine.begin() as conn:
        row = conn.execute(text("SELECT MAX(id) FROM net_events WHERE id > :last"), {"last": int(last_id)}).fetchone()
        max_id = int(row[0]) if row and row[0] is not None else last_id
    return min(max_id, last_id + max_rows)


def _fetch_batch(last_id: int, max_id: int, batch_size: int) -> List[Dict[str, Any]]:
    with engine.begin() as conn:
        rows = conn.execute(
            text(
                """
                SELECT id, event_type, proto, src_port, dst_port, extra
                FROM net_events
                WHERE id > :last_id
                  AND id <= :max_id
                  AND NOT (extra ? 'proto_intel_at')
                ORDER BY id
                LIMIT :limit;
                """
            ),
            {"last_id": int(last_id), "max_id": int(max_id), "limit": int(batch_size)},
        ).mappings().all()
        return [dict(r) for r in rows]


def _patch_event(event_id: int, patch: Dict[str, Any]) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                UPDATE net_events
                SET extra = extra || CAST(:patch AS jsonb)
                WHERE id = :id;
                """
            ),
            {"id": int(event_id), "patch": json.dumps(patch, separators=(",", ":"))},
        )


def main() -> None:
    every_s = _env_float("NETWATCH_PROTO_INTEL_EVERY_SECONDS", 1.0)
    idle_sleep_s = _env_float("NETWATCH_PROTO_INTEL_IDLE_SLEEP_SECONDS", 2.0)
    max_rows = _env_int("NETWATCH_PROTO_INTEL_MAX_ROWS", 5000)
    batch_size = _env_int("NETWATCH_PROTO_INTEL_BATCH_SIZE", 500)
    payload_max = _env_int("NETWATCH_PROTO_INTEL_PAYLOAD_MAX_BYTES", 4096)

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
                # No missing proto_intel markers in this range; advance offset to avoid rescans.
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
            print(f"[PROTO] ok last_id={last_id} max_id={max_id} processed={len(rows)} took_ms={took_ms}")

            backoff = 1.0
            time.sleep(max(every_s, 0.1))

        except OperationalError as e:
            wait_s = min(backoff, 15.0)
            print(f"[PROTO] db_not_ready wait_s={wait_s} error={str(e).splitlines()[0]}")
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 15.0)

        except Exception as e:
            wait_s = min(backoff, 30.0)
            print(f"[PROTO] error wait_s={wait_s} error={repr(e)}")
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 30.0)


if __name__ == "__main__":
    main()
