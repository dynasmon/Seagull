from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from app.features.network_topology.domain.config import _config_stale_after_minutes, _config_window_minutes
from app.features.network_topology.domain.serializers import _to_utc
from app.features.network_topology.schemas import TopologyCoverageOut

_UTC = timezone.utc


def _freshness_metadata(snapshot) -> dict[str, Any]:
    generated_at = datetime.now(_UTC)
    projected_at = _to_utc(snapshot.created_at) if snapshot else None
    freshness_seconds: int | None = None
    if projected_at is not None:
        freshness_seconds = max(0, int((generated_at - projected_at).total_seconds()))
    stale_after_seconds = _config_stale_after_minutes() * 60
    stale = projected_at is None or freshness_seconds is None or freshness_seconds > stale_after_seconds

    metrics = snapshot.metrics if snapshot and isinstance(snapshot.metrics, dict) else {}
    data_window = metrics.get("data_window") if isinstance(metrics.get("data_window"), dict) else None
    if data_window is None:
        data_window = _default_data_window(generated_at)

    source_coverage = metrics.get("source_coverage") if isinstance(metrics.get("source_coverage"), dict) else None
    if source_coverage is None:
        source_coverage = snapshot.coverage if snapshot and isinstance(snapshot.coverage, dict) else {}

    truncation = metrics.get("truncation") if isinstance(metrics.get("truncation"), dict) else {}

    return {
        "generated_at": generated_at,
        "projected_at": projected_at,
        "data_window": data_window,
        "freshness_seconds": freshness_seconds,
        "stale": bool(stale),
        "source_coverage": source_coverage,
        "truncation": truncation,
    }

def _default_data_window(now: datetime) -> dict[str, Any]:
    window = _config_window_minutes()
    start = now - timedelta(minutes=window)
    return {
        "window_minutes": int(window),
        "start_at": start.isoformat(),
        "end_at": now.isoformat(),
    }

def _build_snapshot_metrics(
    *,
    coverage: TopologyCoverageOut,
    projected_by: str,
    reason: str,
    requested_at: datetime,
    window_minutes: int,
    max_events_per_run: int,
) -> dict[str, Any]:
    now = datetime.now(_UTC)
    coverage_dict = _model_dict(coverage)
    warnings = [str(x) for x in coverage.warnings]
    ingest_pressure = _ingest_pressure_snapshot()
    source_coverage = {
        "projection": coverage_dict,
        "agents": {"projected": int(coverage.agents_projected)},
        "inventory": {"agents_with_inventory": int(coverage.agents_with_inventory)},
        "flows": {"edges_added": int(coverage.flow_edges_added), "window_minutes": int(window_minutes)},
        "alerts": {"edges_added": int(coverage.alert_edges_added), "window_minutes": int(window_minutes)},
        "exposure": {"edges_added": int(coverage.exposure_edges_added)},
        "ingest_pressure": ingest_pressure,
    }
    truncation = {
        "max_events_per_run": int(max_events_per_run),
        "warnings": warnings,
        "agents_truncated": "agent_limit_reached" in warnings,
        "inventory_truncated": "inventory_limit_reached" in warnings,
        "flows_truncated": "flow_edge_limit_reached" in warnings,
        "alerts_truncated": "alert_limit_reached" in warnings,
        "exposure_truncated": "exposure_limit_reached" in warnings,
        "sampled": bool((ingest_pressure or {}).get("sampled")),
    }
    return {
        "projected_by": str(projected_by or "worker"),
        "reason": str(reason or "worker"),
        "requested_at": requested_at.isoformat(),
        "data_window": {
            "window_minutes": int(window_minutes),
            "start_at": (now - timedelta(minutes=int(window_minutes))).isoformat(),
            "end_at": now.isoformat(),
        },
        "source_coverage": source_coverage,
        "truncation": truncation,
    }

def _model_dict(model: Any) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()

def _ingest_pressure_snapshot() -> dict[str, Any]:
    try:
        from app.features.ingest.control.service import get_storm_status

        raw = get_storm_status()
    except Exception:
        raw = None
    if not isinstance(raw, dict):
        return {"sampled": False, "phase": "unknown"}
    phase = str(raw.get("phase") or "ok")
    sample_hot = raw.get("sample_hot_percent")
    sample_warm = raw.get("sample_warm_percent")
    try:
        hot_i = int(sample_hot)
    except Exception:
        hot_i = 100
    sampled = bool(raw.get("active")) or phase not in {"ok", "normal"} or hot_i < 100
    return {
        "sampled": bool(sampled),
        "phase": phase,
        "reason": str(raw.get("reason") or "ok"),
        "backlog_events": int(raw.get("backlog_events") or 0),
        "backlog_messages": int(raw.get("backlog_messages") or 0),
        "sample_hot_percent": hot_i,
        "sample_warm_percent": int(sample_warm or 0),
    }
