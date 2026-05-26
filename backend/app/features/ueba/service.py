from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from app.core.api.pagination import make_cursor_ts_id, parse_cursor_ts_id
from app.core.audit import audit_actor, write_audit_event
from app.core.config import settings
from app.core.observability import log_event
from app.features.ueba import repository
from app.features.ueba.config import load_feedback_config, load_ml_config
from app.features.ueba.domain import feedback as fb
from app.features.ueba.domain import ml, peer_groups
from app.features.ueba.schemas import (
    UebaBaselineOut,
    UebaBaselinesQuery,
    UebaDetectorRunOut,
    UebaDetectorStateOut,
    UebaFeedbackOut,
    UebaFindingDetailOut,
    UebaFindingEvidenceOut,
    UebaFindingListItemOut,
    UebaFindingsQuery,
    UebaFindingTriageIn,
    UebaRunsQuery,
    UebaSummaryOut,
)
from app.shared.schemas import CursorPage

logger = logging.getLogger("seagull.ueba.service")


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _parse_context_datetime(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None
    return _as_utc(parsed)


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
    feedback = repository.list_feedback_for_finding(db, int(finding_id))
    payload = UebaFindingListItemOut.model_validate(row).model_dump()
    return UebaFindingDetailOut(
        **payload,
        baseline=(UebaBaselineOut.model_validate(baseline) if baseline is not None else None),
        evidence=[UebaFindingEvidenceOut.model_validate(item) for item in evidence],
        feedback=[UebaFeedbackOut.model_validate(item) for item in feedback],
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
    out: list[UebaDetectorStateOut] = []
    now = datetime.now(timezone.utc)
    ml_cfg = load_ml_config()
    for row in repository.list_detector_states(db):
        payload = UebaDetectorStateOut.model_validate(row).model_dump()
        if row.detector_id == "rare_process_name_v1":
            status, trained_at = repository.latest_ml_model_status(
                db,
                detector_id=row.detector_id,
                model_type=ml.MODEL_TYPE_ISOLATION_FOREST,
            )
            trained_at_utc = _as_utc(trained_at)
            if status == "active" and trained_at_utc is not None:
                age = now - trained_at_utc
                if age.total_seconds() > ml_cfg.if_model_stale_seconds:
                    status = "stale"
            payload["ml_model_status"] = status
            payload["ml_model_trained_at"] = trained_at_utc
        elif row.detector_id == peer_groups.PEER_GROUP_DETECTOR_ID:
            context = dict(row.context or {})
            trained_at = _parse_context_datetime(context.get("last_clustering_at"))
            enabled = bool(context.get("peer_scoring_enabled"))
            payload["ml_model_status"] = "active" if enabled else "unavailable"
            payload["ml_model_trained_at"] = trained_at
        out.append(UebaDetectorStateOut(**payload))
    return out


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


def triage_finding(
    db: Session,
    finding_id: int,
    body: UebaFindingTriageIn,
    *,
    annotated_by: str = "system",
    actor_user_id: int | None = None,
    request: Request | None = None,
) -> UebaFindingDetailOut:
    row = repository.get_finding(db, int(finding_id))
    if row is None:
        raise HTTPException(status_code=404, detail="UEBA finding not found")

    now = datetime.now(timezone.utc)
    actor = str(annotated_by or "system")[:128]
    verdict = body.verdict
    suppression_created = False
    prior_verdict = row.latest_verdict

    cfg: object = None
    ttl_seconds: int | None = None
    is_override: bool = False

    if verdict is not None:
        cfg = load_feedback_config()
        ttl_seconds = body.suppression_ttl_seconds
        if (
            verdict == fb.VERDICT_FALSE_POSITIVE
            and "suppression_ttl_seconds" not in body.model_fields_set
        ):
            ttl_seconds = cfg.default_suppression_ttl_seconds

        latest = repository.get_latest_feedback_for_finding(db, int(row.id))
        prior_verdict = latest.verdict if latest is not None else row.latest_verdict
        is_override = fb.verdict_conflict(prior_verdict, verdict)
        if is_override and not body.override:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Finding already marked {prior_verdict!r}; "
                    f"set override=true to record {verdict!r}."
                ),
            )

    try:
        if verdict is not None:
            feedback_row = repository.create_feedback(
                db,
                finding_id=int(row.id),
                detector_id=str(row.detector_id),
                entity_type=str(row.entity_type),
                entity_value=str(row.entity_value),
                agent_id=(str(row.agent_id) if row.agent_id else None),
                verdict=verdict,
                annotated_by=actor,
                annotated_at=now,
                suppression_ttl_seconds=ttl_seconds,
                notes=body.notes,
                is_override=bool(is_override),
            )
            repository.flush(db)

            baseline = repository.get_baseline(db, int(row.baseline_id)) if row.baseline_id is not None else None
            adj_state = None
            if baseline is not None:
                state = fb.feedback_state_from_baseline(baseline)
                adj_state = fb.project_verdict(state, verdict=verdict, cfg=cfg, now=now)
                repository.update_baseline_feedback(db, baseline, **fb.baseline_feedback_updates(adj_state))


            if verdict == fb.VERDICT_FALSE_POSITIVE:
                plan = fb.resolve_suppression(ttl_seconds=ttl_seconds, now=now)
                if plan.create:
                    scope_key = fb.suppression_scope_key(
                        row.detector_id, row.agent_id, row.entity_type, row.entity_value
                    )
                    repository.upsert_suppression(
                        db,
                        scope_key=scope_key,
                        detector_id=str(row.detector_id),
                        agent_id=(str(row.agent_id) if row.agent_id else None),
                        entity_type=str(row.entity_type),
                        entity_value=str(row.entity_value),
                        reason="false_positive_feedback",
                        feedback_id=int(feedback_row.id),
                        annotated_by=actor,
                        created_at=now,
                        expires_at=plan.expires_at,
                        active=True,
                    )
                    suppression_created = True

            row.latest_verdict = verdict
            row.latest_verdict_at = now
            row.latest_verdict_by = actor

            log_event(
                logger,
                "info",
                "ueba_feedback_recorded",
                finding_id=int(row.id),
                detector_id=str(row.detector_id),
                verdict=verdict,
                entity_type=str(row.entity_type),
                entity_value=str(row.entity_value),
                agent_id=(str(row.agent_id) if row.agent_id else None),
                suppression_created=suppression_created,
                is_override=bool(is_override),
                annotated_by=actor,
            )
            if adj_state is not None:
                log_event(
                    logger,
                    "info",
                    "ueba_baseline_feedback_adjustment",
                    finding_id=int(row.id),
                    baseline_id=int(baseline.id),
                    verdict=verdict,
                    fp_count=adj_state.fp_count,
                    tp_count=adj_state.tp_count,
                    confidence_delta=adj_state.confidence_delta,
                    sensitivity_scale=round(adj_state.sensitivity_scale, 4),
                    cooldown_scale=round(adj_state.cooldown_scale, 4),
                )

            write_audit_event(
                db,
                request=request,
                actor=audit_actor(actor_user_id, actor),
                event_type="ueba_triage",
                action="ueba.finding.verdict",
                resource_type="ueba_finding",
                resource_id=str(row.id),
                outcome="success",
                before={"latest_verdict": prior_verdict},
                after={"latest_verdict": verdict, "suppression_created": suppression_created},
                context={
                    "detector_id": str(row.detector_id),
                    "entity_type": str(row.entity_type),
                    "entity_value": str(row.entity_value),
                    "agent_id": (str(row.agent_id) if row.agent_id else None),
                    "suppression_ttl_seconds": ttl_seconds,
                    "override": bool(body.override),
                    "notes": body.notes,
                },
            )

        effective_status = body.status
        if effective_status is None and verdict is not None:
            effective_status = fb.default_status_for_verdict(verdict, suppression_created=suppression_created)
        if effective_status in ("closed", "suppressed"):
            row.status = effective_status
            row.closed_at = now
        elif effective_status == "open":
            row.status = "open"
            row.closed_at = None

        if body.cooldown_extension_minutes is not None:
            current = _as_utc(row.cooldown_until)
            base = current if (current and current > now) else now
            row.cooldown_until = base + timedelta(minutes=body.cooldown_extension_minutes)

        repository.flush(db)
        repository.commit(db)
    except HTTPException:
        raise
    except Exception:
        db.rollback()
        raise

    repository.refresh(db, row)
    return get_finding_detail(db, int(finding_id))
