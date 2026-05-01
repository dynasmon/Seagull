from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from app.core.config import settings
from app.core.cache import get_redis
from app.features.realtime.service import publish_realtime


EXPOSURE_REALTIME_SUMMARY_GATE_KEY = "seagull:realtime:exposure:summary:2s"
EXPOSURE_REALTIME_ASSET_GATE_KEY_PREFIX = "seagull:realtime:exposure:asset"
EXPOSURE_REALTIME_FINDING_GATE_KEY_PREFIX = "seagull:realtime:exposure:finding"
EXPOSURE_RECALC_REQUEST_TTL_SECONDS = 3600


def graph_nodes_hard_limit() -> int:
    return max(10, int(settings.SEAGULL_EXPOSURE_MAX_GRAPH_NODES_PER_ASSET or 10))


def graph_edges_hard_limit() -> int:
    return max(10, int(settings.SEAGULL_EXPOSURE_MAX_GRAPH_EDGES_PER_ASSET or 10))


def _to_iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat()


def _gate_once(*, key: str, ttl_s: int) -> bool:
    ttl = max(1, int(ttl_s))
    redis_client = get_redis()
    if redis_client is None:
        return True
    try:
        return bool(redis_client.set(str(key), "1", ex=ttl, nx=True))
    except Exception:
        return True


def publish_summary_updated(*, updated_at: datetime | None, asset_key: str | None = None, reason: str | None = None) -> None:
    if not _gate_once(key=EXPOSURE_REALTIME_SUMMARY_GATE_KEY, ttl_s=2):
        return
    publish_realtime(
        "exposure.summary.updated",
        {
            "updated_at": _to_iso(updated_at),
            "asset_key": str(asset_key or "").strip() or None,
            "reason": str(reason or "refresh"),
        },
    )


def publish_asset_updated(row) -> None:
    asset_key = str(getattr(row, "asset_key", "") or "").strip()
    if not asset_key:
        return
    if not _gate_once(key=f"{EXPOSURE_REALTIME_ASSET_GATE_KEY_PREFIX}:{asset_key}", ttl_s=1):
        return
    publish_realtime(
        "exposure.asset.updated",
        {
            "asset_key": asset_key,
            "agent_id": str(getattr(row, "agent_id", "") or "").strip() or None,
            "risk_score": int(getattr(row, "risk_score", 0) or 0),
            "severity": str(getattr(row, "severity", "unknown") or "unknown"),
            "confidence": int(getattr(row, "confidence", 0) or 0),
            "status": str(getattr(row, "status", "unknown") or "unknown"),
            "updated_at": _to_iso(getattr(row, "updated_at", None)),
        },
    )


def publish_finding_updated(row) -> None:
    finding_key = str(getattr(row, "finding_key", "") or "").strip()
    if not finding_key:
        return
    if not _gate_once(key=f"{EXPOSURE_REALTIME_FINDING_GATE_KEY_PREFIX}:{finding_key}", ttl_s=1):
        return
    publish_realtime(
        "exposure.finding.updated",
        {
            "finding_key": finding_key,
            "asset_key": str(getattr(row, "asset_key", "") or "").strip() or None,
            "agent_id": str(getattr(row, "agent_id", "") or "").strip() or None,
            "finding_type": str(getattr(row, "finding_type", "event") or "event"),
            "severity": str(getattr(row, "severity", "unknown") or "unknown"),
            "status": str(getattr(row, "status", "open") or "open"),
            "score_delta": int(getattr(row, "score_delta", 0) or 0),
            "updated_at": _to_iso(getattr(row, "updated_at", None)),
        },
    )


def request_recalculation(*, requested_at: datetime, requested_by: str, request_id: str | None) -> None:
    payload = {
        "requested_at": _to_iso(requested_at),
        "requested_by": str(requested_by or "").strip() or "unknown",
        "request_id": str(request_id or "").strip() or None,
        "mode": "full",
    }
    redis_client = get_redis()
    if redis_client is not None:
        try:
            redis_client.set(
                "seagull:exposure:recalc:request",
                json.dumps(payload, separators=(",", ":"), ensure_ascii=True),
                ex=EXPOSURE_RECALC_REQUEST_TTL_SECONDS,
            )
        except Exception:
            return


def load_recalculation_request(request_key: str) -> dict[str, Any] | None:
    redis_client = get_redis()
    if redis_client is None:
        return None
    try:
        raw = redis_client.get(request_key)
    except Exception:
        return None
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        parsed = json.loads(raw)
    except Exception:
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed
