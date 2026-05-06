from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.features.detections.models import DetectionRuleHealthModel
from app.features.detections.repository import upsert_rule_health_batch

_FAILING_THRESHOLD = 3


@dataclass
class RuleExecResult:
    rule_id: str
    rule_version: int
    content_hash: str
    duration_ms: int
    alerts_created: int = 0
    suppressions_applied: int = 0
    events_scanned: Optional[int] = None
    error: Optional[BaseException] = None
    disabled: bool = False


def _content_hash(rule: dict[str, Any]) -> str:
    try:
        raw = json.dumps(rule, sort_keys=True, default=str).encode()
        return hashlib.sha256(raw).hexdigest()[:16]
    except Exception:
        return ""


def _build_record(
    result: RuleExecResult,
    existing: Optional[DetectionRuleHealthModel],
    now: datetime,
) -> dict[str, Any]:
    if result.disabled:
        status = "disabled"
        consecutive_failures = 0
        last_success_at = existing.last_success_at if existing else None
        last_error_at = existing.last_error_at if existing else None
    elif result.error is not None:
        consecutive_failures = (existing.consecutive_failures if existing else 0) + 1
        status = "failing" if consecutive_failures >= _FAILING_THRESHOLD else "degraded"
        last_success_at = existing.last_success_at if existing else None
        last_error_at = now
    else:
        consecutive_failures = 0
        status = "healthy"
        last_success_at = now
        last_error_at = existing.last_error_at if existing else None

    return {
        "rule_id": result.rule_id,
        "rule_version": result.rule_version,
        "content_hash": result.content_hash,
        "status": status,
        "consecutive_failures": consecutive_failures,
        "last_run_at": now,
        "last_success_at": last_success_at,
        "last_error_at": last_error_at,
        "duration_ms": result.duration_ms,
        "events_scanned": result.events_scanned,
        "alerts_created": result.alerts_created,
        "suppressions_applied": result.suppressions_applied,
        "error_type": type(result.error).__name__ if result.error else None,
        "error_message": str(result.error)[:512] if result.error else None,
        "updated_at": now,
    }


def build_health_records(
    results: list[RuleExecResult],
    existing: dict[str, DetectionRuleHealthModel],
    now: datetime,
) -> list[dict[str, Any]]:
    return [_build_record(r, existing.get(r.rule_id), now) for r in results]


def flush_cycle_health(
    db: Session,
    results: list[RuleExecResult],
    existing: dict[str, DetectionRuleHealthModel],
    now: datetime,
) -> None:
    records = build_health_records(results, existing, now)
    upsert_rule_health_batch(db, records)
