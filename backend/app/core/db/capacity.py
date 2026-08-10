from __future__ import annotations

import logging
import time
from typing import Any, Dict, Iterable, List, Mapping

from sqlalchemy import text

from app.core.config import settings
from app.core.observability import log_event, set_gauge

from .engine import engine

logger = logging.getLogger("seagull.db.capacity")

SEQUENCE_USAGE_SQL = text(
    "SELECT sequencename, COALESCE(last_value, 0) AS last_value, max_value "
    "FROM pg_sequences WHERE schemaname = current_schema()"
)

_report: List[Dict[str, Any]] = []
_reported_at: float = 0.0
_last_warn_log_at: float = 0.0


def _probe_ttl_seconds() -> float:
    try:
        return max(0.0, float(settings.SEAGULL_DB_SEQUENCE_PROBE_TTL_SECONDS or 0.0))
    except (TypeError, ValueError):
        return 30.0


def _warn_ratio() -> float:
    try:
        return min(1.0, max(0.0, float(settings.SEAGULL_DB_SEQUENCE_WARN_RATIO or 0.0)))
    except (TypeError, ValueError):
        return 0.85


def build_sequence_report(rows: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    report: List[Dict[str, Any]] = []
    for row in rows:
        try:
            max_value = int(row["max_value"] or 0)
            last_value = int(row["last_value"] or 0)
        except (TypeError, ValueError, KeyError):
            continue
        if max_value <= 0:
            continue
        name = str(row.get("sequencename") or "").strip()
        if not name:
            continue
        report.append(
            {
                "sequence": name,
                "last_value": last_value,
                "max_value": max_value,
                "used_ratio": min(1.0, max(0.0, last_value / max_value)),
            }
        )
    report.sort(key=lambda item: (-item["used_ratio"], item["sequence"]))
    return report


def sequence_capacity_report() -> List[Dict[str, Any]]:
    global _report, _reported_at, _last_warn_log_at

    if engine.dialect.name != "postgresql":
        return []

    now = time.monotonic()
    if _reported_at and (now - _reported_at) < _probe_ttl_seconds():
        return _report

    try:
        with engine.connect() as conn:
            rows = conn.execute(SEQUENCE_USAGE_SQL).mappings().all()
    except Exception as exc:
        log_event(logger, "warning", "sequence_capacity_probe_failed", error_type=type(exc).__name__)
        return _report

    previous = {item["sequence"] for item in _report}
    _report = build_sequence_report(rows)
    _reported_at = now

    for item in _report:
        set_gauge("postgres_sequence_used_ratio", item["used_ratio"], sequence=item["sequence"])
    for name in sorted(previous - {item["sequence"] for item in _report}):
        set_gauge("postgres_sequence_used_ratio", 0.0, sequence=name)

    floor = _warn_ratio()
    exhausting = [item for item in _report if floor > 0 and item["used_ratio"] >= floor]
    if exhausting and (now - _last_warn_log_at) >= 60.0:
        _last_warn_log_at = now
        worst = exhausting[0]
        log_event(
            logger,
            "warning",
            "sequence_capacity_near_exhaustion",
            sequence=worst["sequence"],
            last_value=worst["last_value"],
            max_value=worst["max_value"],
            used_ratio=round(worst["used_ratio"], 6),
            sequences_over_floor=len(exhausting),
        )

    return _report


def reset_sequence_capacity_cache() -> None:
    global _report, _reported_at, _last_warn_log_at
    _report = []
    _reported_at = 0.0
    _last_warn_log_at = 0.0
