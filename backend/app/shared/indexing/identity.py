from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict


def normalized_event_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    if isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(timezone.utc)
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    return datetime.now(timezone.utc)


def _port(value: Any) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return 0
    return port if 0 <= port <= 65535 else 0


def _byte_count(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def event_fingerprint(row: Dict[str, Any]) -> str:
    extra = row.get("extra")
    if not isinstance(extra, dict):
        extra = {}
    return "|".join(
        [
            str(row.get("agent_id") or ""),
            str(row.get("event_type") or ""),
            normalized_event_timestamp(row.get("timestamp")).isoformat(),
            str(row.get("src_ip") or ""),
            str(row.get("dst_ip") or ""),
            str(_port(row.get("src_port"))),
            str(_port(row.get("dst_port"))),
            str(row.get("proto") or ""),
            str(_byte_count(row.get("bytes"))),
            json.dumps(extra, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str),
        ]
    )


def event_document_id(row: Dict[str, Any]) -> str:
    for key in ("pg_event_id", "id"):
        try:
            event_id = int(row.get(key) or 0)
        except (TypeError, ValueError):
            event_id = 0
        if event_id > 0:
            return str(event_id)
    digest = hashlib.sha1(event_fingerprint(row).encode("utf-8"), usedforsecurity=False)
    return digest.hexdigest()
