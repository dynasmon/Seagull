from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.api.pagination import make_cursor_ts_id, parse_cursor_ts_id
from app.core.config import settings
from app.features.ueba import repository
from app.features.ueba.schemas import (
    UebaBaselineOut,
    UebaBaselinesQuery,
    UebaDetectorRunOut,
    UebaDetectorStateOut,
    UebaFindingDetailOut,
    UebaFindingEvidenceOut,
    UebaFindingListItemOut,
    UebaFindingsQuery,
    UebaFindingTriageIn,
    UebaRunsQuery,
    UebaSummaryOut,
)
from app.shared.schemas import CursorPage


def get_summary(db: Session) -> UebaSummaryOut:
    metrics = repository.summary_metrics(db)
    return UebaSummaryOut(
        enabled=bool(settings.SEAGULL_UEBA_ENABLED),
        **metrics,
    )


def list_findings(db: Session, *, params: UebaFindingsQuery) -> CursorPage[UebaFindingListItemOut]:
    cursor_parsed = parse_cursor_ts_id(params.cursor) if params.cursor else None
    rows = repository.list_findings_page(
        db,
        page_size=params.page_size,
        detector_id=params.detector_id,
        agent_id=params.agent_id,
        entity_type=params.entity_type,
        entity_value=params.entity_value,
        metric_name=params.metric_name,
        status=params.status,
        severity=params.severity,
        min_risk_score=params.min_risk_score,
        cursor_parsed=cursor_parsed,
    )
    has_more = len(rows) > int(params.page_size)
    items = rows[: int(params.page_size)]
    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = make_cursor_ts_id(last.last_seen_at, int(last.id))
    return CursorPage(
        items=[UebaFindingListItemOut.model_validate(row) for row in items],
        next_cursor=next_cursor,
        has_more=has_more,
    )


def get_finding_detail(db: Session, finding_id: int) -> UebaFindingDetailOut:
    row = repository.get_finding(db, int(finding_id))
    if row is None:
        raise HTTPException(status_code=404, detail="UEBA finding not found")
    evidence = repository.list_finding_evidence(db, int(finding_id))
    baseline = repository.get_baseline(db, int(row.baseline_id)) if row.baseline_id is not None else None
    payload = UebaFindingListItemOut.model_validate(row).model_dump()
    return UebaFindingDetailOut(
        **payload,
        baseline=(UebaBaselineOut.model_validate(baseline) if baseline is not None else None),
        evidence=[UebaFindingEvidenceOut.model_validate(item) for item in evidence],
    )


def list_baselines(db: Session, *, params: UebaBaselinesQuery) -> CursorPage[UebaBaselineOut]:
    cursor_parsed = parse_cursor_ts_id(params.cursor) if params.cursor else None
    rows = repository.list_baselines_page(
        db,
        page_size=params.page_size,
        detector_id=params.detector_id,
        agent_id=params.agent_id,
        entity_type=params.entity_type,
        entity_value=params.entity_value,
        metric_name=params.metric_name,
        status=params.status,
        cursor_parsed=cursor_parsed,
    )
    has_more = len(rows) > int(params.page_size)
    items = rows[: int(params.page_size)]
    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = make_cursor_ts_id(last.last_observed_at, int(last.id))
    return CursorPage(
        items=[UebaBaselineOut.model_validate(row) for row in items],
        next_cursor=next_cursor,
        has_more=has_more,
    )


def list_detector_states(db: Session) -> list[UebaDetectorStateOut]:
    return [UebaDetectorStateOut.model_validate(row) for row in repository.list_detector_states(db)]


def list_detector_runs(db: Session, *, params: UebaRunsQuery) -> CursorPage[UebaDetectorRunOut]:
    cursor_parsed = parse_cursor_ts_id(params.cursor) if params.cursor else None
    rows = repository.list_detector_runs_page(
        db,
        page_size=params.page_size,
        detector_id=params.detector_id,
        status=params.status,
        cursor_parsed=cursor_parsed,
    )
    has_more = len(rows) > int(params.page_size)
    items = rows[: int(params.page_size)]
    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = make_cursor_ts_id(last.started_at, int(last.id))
    return CursorPage(
        items=[UebaDetectorRunOut.model_validate(row) for row in items],
        next_cursor=next_cursor,
        has_more=has_more,
    )


def triage_finding(db: Session, finding_id: int, body: UebaFindingTriageIn) -> UebaFindingDetailOut:
    from datetime import datetime, timedelta, timezone
    row = repository.get_finding(db, finding_id)
    if row is None:
        raise HTTPException(status_code=404, detail="UEBA finding not found")
    if body.status in ("closed", "suppressed"):
        row.status = body.status
        row.closed_at = datetime.now(timezone.utc)
    elif body.status == "open":
        row.status = "open"
        row.closed_at = None
    if body.cooldown_extension_minutes is not None:
        now = datetime.now(timezone.utc)
        base = row.cooldown_until if (row.cooldown_until and row.cooldown_until > now) else now
        row.cooldown_until = base + timedelta(minutes=body.cooldown_extension_minutes)
    repository.flush(db)
    repository.refresh(db, row)
    return get_finding_detail(db, finding_id)
