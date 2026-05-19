from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

from sqlalchemy.orm import Session

from app.features.ueba import repository
from app.features.ueba.models import (
    UebaBaselineModel,
    UebaDetectorRunModel,
    UebaDetectorStateModel,
    UebaFindingModel,
)

_SEVERITY_RANK = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

_BASELINE_MUTABLE_FIELDS = (
    "detector_id",
    "detector_version",
    "agent_id",
    "entity_type",
    "entity_value",
    "metric_name",
    "bucket_key",
    "status",
    "sample_count",
    "warmup_started_at",
    "matured_at",
    "window_started_at",
    "window_ended_at",
    "last_observed_at",
    "expected_value",
    "dispersion",
    "lower_bound",
    "upper_bound",
    "confidence",
    "state",
)

_FINDING_LATEST_FIELDS = (
    "detector_id",
    "detector_version",
    "baseline_id",
    "agent_id",
    "entity_type",
    "entity_value",
    "metric_name",
    "bucket_key",
    "expected_value",
    "observed_value",
    "deviation_score",
    "summary",
)

_FINDING_OPTIONAL_LATEST_FIELDS = (
    "alert_id",
    "mitre_tactic",
    "mitre_technique_id",
    "mitre_technique",
)


@dataclass(frozen=True)
class FindingObservationResult:
    finding: UebaFindingModel
    created: bool
    in_cooldown: bool


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _max_dt(left: datetime | None, right: datetime | None) -> datetime | None:
    if left is None:
        return right
    if right is None:
        return left
    return max(_normalize_dt(left), _normalize_dt(right))


def _min_dt(left: datetime | None, right: datetime | None) -> datetime | None:
    if left is None:
        return right
    if right is None:
        return left
    return min(_normalize_dt(left), _normalize_dt(right))


def _merge_reason_codes(existing: Iterable[str] | None, incoming: Iterable[str] | None) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for value in [*(existing or []), *(incoming or [])]:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        merged.append(text)
    return merged


def _merge_dict(existing: dict[str, Any] | None, incoming: dict[str, Any] | None) -> dict[str, Any]:
    merged = dict(existing or {})
    merged.update(dict(incoming or {}))
    return merged


def _prefer_higher_severity(current: str | None, incoming: str | None) -> str:
    current_norm = str(current or "medium")
    incoming_norm = str(incoming or current_norm)
    if _SEVERITY_RANK.get(incoming_norm, -1) >= _SEVERITY_RANK.get(current_norm, -1):
        return incoming_norm
    return current_norm


def upsert_baseline(db: Session, **values: Any) -> tuple[UebaBaselineModel, bool]:
    payload = dict(values)
    baseline_key = str(payload["baseline_key"])
    updated_at = payload.pop("updated_at", None) or _utc_now()

    row = repository.get_baseline_by_key(db, baseline_key)
    if row is None:
        payload["updated_at"] = updated_at
        new_row = repository.create_baseline(db, **payload)
        repository.flush(db)  # autoflush=False — flush so same-session lookups see the new row
        return new_row, True

    for field in _BASELINE_MUTABLE_FIELDS:
        if field in payload:
            setattr(row, field, payload[field])
    row.updated_at = updated_at
    return repository.save_baseline(db, row), False


def record_finding_observation(db: Session, **values: Any) -> FindingObservationResult:
    payload = dict(values)
    dedup_key = str(payload["dedup_key"])
    observed_at = payload.get("last_seen_at") or _utc_now()
    updated_at = payload.pop("updated_at", None) or observed_at

    row = repository.get_open_finding_by_dedup_key(db, dedup_key)
    if row is None:
        payload["updated_at"] = updated_at
        payload.setdefault("occurrence_count", 1)
        new_finding = repository.create_finding(db, **payload)
        repository.flush(db)  # autoflush=False — flush so same-session lookups see the new row
        return FindingObservationResult(
            finding=new_finding,
            created=True,
            in_cooldown=False,
        )

    prior_cooldown_until = row.cooldown_until
    in_cooldown = prior_cooldown_until is not None and _normalize_dt(observed_at) <= _normalize_dt(prior_cooldown_until)

    for field in _FINDING_LATEST_FIELDS:
        if field in payload:
            setattr(row, field, payload[field])
    for field in _FINDING_OPTIONAL_LATEST_FIELDS:
        if payload.get(field) is not None:
            setattr(row, field, payload[field])

    row.status = "open"
    row.closed_at = None
    row.first_seen_at = _min_dt(row.first_seen_at, payload.get("first_seen_at"))
    row.last_seen_at = _max_dt(row.last_seen_at, payload.get("last_seen_at"))
    row.window_started_at = _min_dt(row.window_started_at, payload.get("window_started_at"))
    row.window_ended_at = _max_dt(row.window_ended_at, payload.get("window_ended_at"))
    row.cooldown_until = _max_dt(row.cooldown_until, payload.get("cooldown_until"))
    row.occurrence_count = int(row.occurrence_count or 0) + max(1, int(payload.get("occurrence_count") or 1))
    row.severity = _prefer_higher_severity(row.severity, payload.get("severity"))
    row.confidence = max(int(row.confidence or 0), int(payload.get("confidence") or 0))
    row.risk_score = max(int(row.risk_score or 0), int(payload.get("risk_score") or 0))
    row.reason_codes = _merge_reason_codes(row.reason_codes, payload.get("reason_codes"))
    row.explanation = _merge_dict(row.explanation, payload.get("explanation"))
    row.updated_at = updated_at

    return FindingObservationResult(
        finding=repository.save_finding(db, row),
        created=False,
        in_cooldown=in_cooldown,
    )


def append_finding_evidence(db: Session, *, finding_id: int, specs: Iterable[dict[str, Any]]) -> int:
    existing_signatures = {_evidence_signature_from_row(row) for row in repository.list_finding_evidence(db, finding_id)}
    inserted = 0
    for raw_spec in specs:
        spec = dict(raw_spec)
        signature = _evidence_signature_from_values(spec)
        if signature in existing_signatures:
            continue
        existing_signatures.add(signature)
        repository.create_finding_evidence(db, finding_id=finding_id, **spec)
        inserted += 1
    return inserted


def link_alert_to_finding(
    db: Session,
    *,
    finding: UebaFindingModel,
    alert_id: int,
    linked_at: datetime | None = None,
) -> UebaFindingModel:
    finding.alert_id = int(alert_id)
    finding.updated_at = linked_at or _utc_now()
    return repository.save_finding(db, finding)


def upsert_detector_state(db: Session, **values: Any) -> tuple[UebaDetectorStateModel, bool]:
    payload = dict(values)
    detector_id = str(payload["detector_id"])
    updated_at = payload.pop("updated_at", None) or _utc_now()

    row = repository.get_detector_state(db, detector_id)
    if row is None:
        payload["updated_at"] = updated_at
        return repository.create_detector_state(db, **payload), True

    for field, value in payload.items():
        if field == "detector_id":
            continue
        setattr(row, field, value)
    row.updated_at = updated_at
    return repository.save_detector_state(db, row), False


def start_detector_run(
    db: Session,
    *,
    detector_id: str,
    detector_version: int | None,
    started_at: datetime,
    window_started_at: datetime | None,
    window_ended_at: datetime | None,
    context: dict[str, Any] | None = None,
) -> UebaDetectorRunModel:
    run = repository.create_detector_run(
        db,
        detector_id=detector_id,
        detector_version=detector_version,
        started_at=started_at,
        status="running",
        window_started_at=window_started_at,
        window_ended_at=window_ended_at,
        context=dict(context or {}),
    )
    state, _ = upsert_detector_state(
        db,
        detector_id=detector_id,
        detector_version=detector_version,
        enabled=True,
        last_run_at=started_at,
        last_window_started_at=window_started_at,
        last_window_ended_at=window_ended_at,
        updated_at=started_at,
    )
    if state.status == "disabled":
        state.enabled = False
    return run


def complete_detector_run(
    db: Session,
    *,
    run: UebaDetectorRunModel,
    finished_at: datetime,
    scanned_events: int,
    evaluated_entities: int,
    baselines_created: int,
    baselines_updated: int,
    findings_created: int,
    findings_updated: int,
    alerts_created: int,
    suppressions_applied: int,
    baseline_count: int,
    mature_baseline_count: int,
    open_findings: int,
    context_patch: dict[str, Any] | None = None,
) -> UebaDetectorRunModel:
    run.finished_at = finished_at
    run.status = "completed"
    run.scanned_events = int(scanned_events)
    run.evaluated_entities = int(evaluated_entities)
    run.baselines_created = int(baselines_created)
    run.baselines_updated = int(baselines_updated)
    run.findings_created = int(findings_created)
    run.findings_updated = int(findings_updated)
    run.alerts_created = int(alerts_created)
    run.suppressions_applied = int(suppressions_applied)
    run.duration_ms = _duration_ms(run.started_at, finished_at)
    run.context = _merge_dict(run.context, context_patch)
    run.error_type = None
    run.error_message = None
    repository.save_detector_run(db, run)

    upsert_detector_state(
        db,
        detector_id=run.detector_id,
        detector_version=run.detector_version,
        enabled=True,
        status="healthy",
        consecutive_failures=0,
        baseline_count=int(baseline_count),
        mature_baseline_count=int(mature_baseline_count),
        open_findings=int(open_findings),
        last_run_at=run.started_at,
        last_success_at=finished_at,
        last_window_started_at=run.window_started_at,
        last_window_ended_at=run.window_ended_at,
        error_type=None,
        error_message=None,
        updated_at=finished_at,
    )
    return run


def fail_detector_run(
    db: Session,
    *,
    run: UebaDetectorRunModel,
    failed_at: datetime,
    error_type: str,
    error_message: str,
    failing_after: int = 3,
    context_patch: dict[str, Any] | None = None,
) -> UebaDetectorRunModel:
    run.finished_at = failed_at
    run.status = "failed"
    run.duration_ms = _duration_ms(run.started_at, failed_at)
    run.error_type = str(error_type or "")[:128] or None
    run.error_message = str(error_message or "")[:512] or None
    run.context = _merge_dict(run.context, context_patch)
    repository.save_detector_run(db, run)

    existing = repository.get_detector_state(db, run.detector_id)
    next_failures = int(existing.consecutive_failures or 0) + 1 if existing is not None else 1
    next_status = "failing" if next_failures >= max(1, int(failing_after)) else "degraded"
    upsert_detector_state(
        db,
        detector_id=run.detector_id,
        detector_version=run.detector_version,
        enabled=True,
        status=next_status,
        consecutive_failures=next_failures,
        last_run_at=run.started_at,
        last_error_at=failed_at,
        last_window_started_at=run.window_started_at,
        last_window_ended_at=run.window_ended_at,
        error_type=run.error_type,
        error_message=run.error_message,
        updated_at=failed_at,
    )
    return run


def _duration_ms(started_at: datetime, finished_at: datetime) -> int:
    return max(0, int((_normalize_dt(finished_at) - _normalize_dt(started_at)).total_seconds() * 1000))


def _normalize_dt(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _evidence_signature_from_values(values: dict[str, Any]) -> tuple[Any, ...]:
    return (
        values.get("event_id"),
        values.get("alert_id"),
        values.get("evidence_type"),
        values.get("evidence_role"),
        _signature_datetime(values.get("observed_at")),
        values.get("entity_type"),
        values.get("entity_value"),
        values.get("matched_field"),
        values.get("matched_value"),
        values.get("summary"),
    )


def _evidence_signature_from_row(row) -> tuple[Any, ...]:
    return _evidence_signature_from_values(
        {
            "event_id": row.event_id,
            "alert_id": row.alert_id,
            "evidence_type": row.evidence_type,
            "evidence_role": row.evidence_role,
            "observed_at": row.observed_at,
            "entity_type": row.entity_type,
            "entity_value": row.entity_value,
            "matched_field": row.matched_field,
            "matched_value": row.matched_value,
            "summary": row.summary,
        }
    )


def _signature_datetime(value: Any) -> Any:
    if not isinstance(value, datetime):
        return value
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value.isoformat()
