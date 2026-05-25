from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.orm import Session

from app.features.ueba.models import (
    UebaBaselineModel,
    UebaDetectorRunModel,
    UebaDetectorStateModel,
    UebaFeedbackModel,
    UebaFindingEvidenceModel,
    UebaFindingModel,
    UebaMlModelModel,
    UebaPeerGroupModel,
    UebaSuppressionModel,
)


def _utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def create_baseline(db: Session, **values) -> UebaBaselineModel:
    row = UebaBaselineModel(**values)
    db.add(row)
    return row


def save_baseline(db: Session, row: UebaBaselineModel) -> UebaBaselineModel:
    db.add(row)
    return row


def get_baseline(db: Session, baseline_id: int) -> UebaBaselineModel | None:
    return db.get(UebaBaselineModel, int(baseline_id))


def get_baseline_by_key(db: Session, baseline_key: str) -> UebaBaselineModel | None:
    stmt = select(UebaBaselineModel).where(UebaBaselineModel.baseline_key == baseline_key)
    return db.execute(stmt).scalars().first()


def list_detector_baselines(
    db: Session,
    *,
    detector_id: str,
    limit: int,
    include_stale: bool = False,
) -> list[UebaBaselineModel]:
    stmt = select(UebaBaselineModel).where(UebaBaselineModel.detector_id == detector_id)
    if not include_stale:
        stmt = stmt.where(UebaBaselineModel.status != "stale")
    stmt = stmt.order_by(UebaBaselineModel.last_observed_at.desc(), UebaBaselineModel.id.desc())
    return db.execute(stmt.limit(max(1, int(limit)))).scalars().all()


def count_detector_baselines(db: Session, detector_id: str) -> tuple[int, int]:
    row = db.execute(
        select(
            func.count(UebaBaselineModel.id),
            func.sum(case((UebaBaselineModel.status == "mature", 1), else_=0)),
        ).where(UebaBaselineModel.detector_id == detector_id)
    ).one()
    return int(row[0] or 0), int(row[1] or 0)


def list_baselines_page(
    db: Session,
    *,
    page_size: int,
    detector_id: str | None,
    agent_id: str | None,
    entity_type: str | None,
    entity_value: str | None,
    metric_name: str | None,
    status: str | None,
    cursor_parsed: tuple[datetime, int] | None,
) -> list[UebaBaselineModel]:
    stmt = select(UebaBaselineModel).order_by(
        UebaBaselineModel.last_observed_at.desc(),
        UebaBaselineModel.id.desc(),
    )
    if detector_id:
        stmt = stmt.where(UebaBaselineModel.detector_id == detector_id)
    if agent_id:
        stmt = stmt.where(UebaBaselineModel.agent_id == agent_id)
    if entity_type:
        stmt = stmt.where(UebaBaselineModel.entity_type == entity_type)
    if entity_value:
        stmt = stmt.where(UebaBaselineModel.entity_value == entity_value)
    if metric_name:
        stmt = stmt.where(UebaBaselineModel.metric_name == metric_name)
    if status:
        stmt = stmt.where(UebaBaselineModel.status == status)
    if cursor_parsed:
        c_ts, c_id = cursor_parsed
        stmt = stmt.where(
            or_(
                UebaBaselineModel.last_observed_at < c_ts,
                and_(UebaBaselineModel.last_observed_at == c_ts, UebaBaselineModel.id < c_id),
            )
        )
    return db.execute(stmt.limit(int(page_size) + 1)).scalars().all()


def create_finding(db: Session, **values) -> UebaFindingModel:
    row = UebaFindingModel(**values)
    db.add(row)
    return row


def save_finding(db: Session, row: UebaFindingModel) -> UebaFindingModel:
    db.add(row)
    return row


def get_finding(db: Session, finding_id: int) -> UebaFindingModel | None:
    return db.get(UebaFindingModel, int(finding_id))


def get_open_finding_by_dedup_key(db: Session, dedup_key: str) -> UebaFindingModel | None:
    stmt = (
        select(UebaFindingModel)
        .where(UebaFindingModel.dedup_key == dedup_key)
        .where(UebaFindingModel.status == "open")
        .order_by(UebaFindingModel.last_seen_at.desc(), UebaFindingModel.id.desc())
        .limit(1)
    )
    return db.execute(stmt).scalars().first()


def count_open_findings_for_detector(db: Session, detector_id: str) -> int:
    value = db.execute(
        select(func.count(UebaFindingModel.id)).where(
            UebaFindingModel.detector_id == detector_id,
            UebaFindingModel.status == "open",
        )
    ).scalar()
    return int(value or 0)


def list_findings_page(
    db: Session,
    *,
    page_size: int,
    detector_id: str | None,
    agent_id: str | None,
    entity_type: str | None,
    entity_value: str | None,
    metric_name: str | None,
    status: str | None,
    severity: str | None,
    min_risk_score: int | None,
    cursor_parsed: tuple[datetime, int] | None,
) -> list[UebaFindingModel]:
    stmt = select(UebaFindingModel).order_by(
        UebaFindingModel.last_seen_at.desc(),
        UebaFindingModel.id.desc(),
    )
    if detector_id:
        stmt = stmt.where(UebaFindingModel.detector_id == detector_id)
    if agent_id:
        stmt = stmt.where(UebaFindingModel.agent_id == agent_id)
    if entity_type:
        stmt = stmt.where(UebaFindingModel.entity_type == entity_type)
    if entity_value:
        stmt = stmt.where(UebaFindingModel.entity_value == entity_value)
    if metric_name:
        stmt = stmt.where(UebaFindingModel.metric_name == metric_name)
    if status:
        stmt = stmt.where(UebaFindingModel.status == status)
    if severity:
        stmt = stmt.where(UebaFindingModel.severity == severity)
    if min_risk_score is not None:
        stmt = stmt.where(UebaFindingModel.risk_score >= int(min_risk_score))
    if cursor_parsed:
        c_ts, c_id = cursor_parsed
        stmt = stmt.where(
            or_(
                UebaFindingModel.last_seen_at < c_ts,
                and_(UebaFindingModel.last_seen_at == c_ts, UebaFindingModel.id < c_id),
            )
        )
    return db.execute(stmt.limit(int(page_size) + 1)).scalars().all()


def create_finding_evidence(db: Session, **values) -> UebaFindingEvidenceModel:
    row = UebaFindingEvidenceModel(**values)
    db.add(row)
    return row


def list_finding_evidence(db: Session, finding_id: int) -> list[UebaFindingEvidenceModel]:
    stmt = (
        select(UebaFindingEvidenceModel)
        .where(UebaFindingEvidenceModel.finding_id == int(finding_id))
        .order_by(UebaFindingEvidenceModel.observed_at.asc(), UebaFindingEvidenceModel.id.asc())
    )
    return db.execute(stmt).scalars().all()


def create_detector_state(db: Session, **values) -> UebaDetectorStateModel:
    row = UebaDetectorStateModel(**values)
    db.add(row)
    return row


def save_detector_state(db: Session, row: UebaDetectorStateModel) -> UebaDetectorStateModel:
    db.add(row)
    return row


def get_detector_state(db: Session, detector_id: str) -> UebaDetectorStateModel | None:
    return db.get(UebaDetectorStateModel, detector_id)


def list_detector_states(db: Session) -> list[UebaDetectorStateModel]:
    stmt = select(UebaDetectorStateModel).order_by(UebaDetectorStateModel.detector_id.asc())
    return db.execute(stmt).scalars().all()


def create_detector_run(db: Session, **values) -> UebaDetectorRunModel:
    row = UebaDetectorRunModel(**values)
    db.add(row)
    return row


def save_detector_run(db: Session, row: UebaDetectorRunModel) -> UebaDetectorRunModel:
    db.add(row)
    return row


def get_detector_run(db: Session, run_id: int) -> UebaDetectorRunModel | None:
    return db.get(UebaDetectorRunModel, int(run_id))


def list_detector_runs_page(
    db: Session,
    *,
    page_size: int,
    detector_id: str | None,
    status: str | None,
    cursor_parsed: tuple[datetime, int] | None,
) -> list[UebaDetectorRunModel]:
    stmt = select(UebaDetectorRunModel).order_by(
        UebaDetectorRunModel.started_at.desc(),
        UebaDetectorRunModel.id.desc(),
    )
    if detector_id:
        stmt = stmt.where(UebaDetectorRunModel.detector_id == detector_id)
    if status:
        stmt = stmt.where(UebaDetectorRunModel.status == status)
    if cursor_parsed:
        c_ts, c_id = cursor_parsed
        stmt = stmt.where(
            or_(
                UebaDetectorRunModel.started_at < c_ts,
                and_(UebaDetectorRunModel.started_at == c_ts, UebaDetectorRunModel.id < c_id),
            )
        )
    return db.execute(stmt.limit(int(page_size) + 1)).scalars().all()


def create_feedback(db: Session, **values) -> UebaFeedbackModel:
    row = UebaFeedbackModel(**values)
    db.add(row)
    return row


def get_latest_feedback_for_finding(db: Session, finding_id: int) -> UebaFeedbackModel | None:
    stmt = (
        select(UebaFeedbackModel)
        .where(UebaFeedbackModel.finding_id == int(finding_id))
        .order_by(UebaFeedbackModel.annotated_at.desc(), UebaFeedbackModel.id.desc())
        .limit(1)
    )
    return db.execute(stmt).scalars().first()


def list_feedback_for_finding(db: Session, finding_id: int) -> list[UebaFeedbackModel]:
    stmt = (
        select(UebaFeedbackModel)
        .where(UebaFeedbackModel.finding_id == int(finding_id))
        .order_by(UebaFeedbackModel.annotated_at.desc(), UebaFeedbackModel.id.desc())
    )
    return db.execute(stmt).scalars().all()


def count_verdicts_since(db: Session, *, since: datetime) -> int:
    value = db.execute(
        select(func.count(UebaFeedbackModel.id)).where(UebaFeedbackModel.annotated_at >= _utc(since))
    ).scalar()
    return int(value or 0)


def update_baseline_feedback(db: Session, baseline: UebaBaselineModel, **updates) -> UebaBaselineModel:
    for field, value in updates.items():
        setattr(baseline, field, value)
    db.add(baseline)
    return baseline


def get_suppression_by_scope_key(db: Session, scope_key: str) -> UebaSuppressionModel | None:
    stmt = select(UebaSuppressionModel).where(UebaSuppressionModel.scope_key == scope_key)
    return db.execute(stmt).scalars().first()


def upsert_suppression(db: Session, *, scope_key: str, **values) -> tuple[UebaSuppressionModel, bool]:
    """One suppression row per scope: reactivate/refresh the existing row or create it."""
    row = get_suppression_by_scope_key(db, scope_key)
    if row is None:
        row = UebaSuppressionModel(scope_key=scope_key, **values)
        db.add(row)
        return row, True
    for field, value in values.items():
        setattr(row, field, value)
    db.add(row)
    return row, False


def find_active_suppression(db: Session, *, scope_key: str, now: datetime) -> UebaSuppressionModel | None:
    now_v = _utc(now)
    stmt = (
        select(UebaSuppressionModel)
        .where(UebaSuppressionModel.scope_key == scope_key)
        .where(UebaSuppressionModel.active.is_(True))
        .where(or_(UebaSuppressionModel.expires_at.is_(None), UebaSuppressionModel.expires_at > now_v))
        .limit(1)
    )
    return db.execute(stmt).scalars().first()


def count_active_suppressions(db: Session, *, now: datetime) -> int:
    now_v = _utc(now)
    value = db.execute(
        select(func.count(UebaSuppressionModel.id))
        .where(UebaSuppressionModel.active.is_(True))
        .where(or_(UebaSuppressionModel.expires_at.is_(None), UebaSuppressionModel.expires_at > now_v))
    ).scalar()
    return int(value or 0)


def sweep_expired_suppressions(db: Session, *, now: datetime) -> int:
    now_v = _utc(now)
    rows = db.execute(
        select(UebaSuppressionModel).where(
            UebaSuppressionModel.expires_at.isnot(None),
            UebaSuppressionModel.expires_at <= now_v,
            UebaSuppressionModel.active.is_(True),
        )
    ).scalars().all()
    for row in rows:
        row.active = False
        db.add(row)
    return len(rows)


def create_ml_model(db: Session, **values) -> UebaMlModelModel:
    row = UebaMlModelModel(**values)
    db.add(row)
    return row


def get_active_ml_model(
    db: Session,
    *,
    detector_id: str,
    agent_id: str | None,
    model_type: str,
    feature_schema_version: int | None = None,
) -> UebaMlModelModel | None:
    stmt = (
        select(UebaMlModelModel)
        .where(
            UebaMlModelModel.detector_id == detector_id,
            UebaMlModelModel.agent_id == agent_id,
            UebaMlModelModel.model_type == model_type,
            UebaMlModelModel.status == "active",
        )
        .order_by(UebaMlModelModel.training_finished_at.desc(), UebaMlModelModel.id.desc())
        .limit(1)
    )
    if feature_schema_version is not None:
        stmt = stmt.where(UebaMlModelModel.feature_schema_version == int(feature_schema_version))
    return db.execute(stmt).scalars().first()


def get_latest_ml_model(
    db: Session,
    *,
    detector_id: str,
    agent_id: str | None,
    model_type: str,
) -> UebaMlModelModel | None:
    stmt = (
        select(UebaMlModelModel)
        .where(
            UebaMlModelModel.detector_id == detector_id,
            UebaMlModelModel.agent_id == agent_id,
            UebaMlModelModel.model_type == model_type,
        )
        .order_by(UebaMlModelModel.training_finished_at.desc(), UebaMlModelModel.id.desc())
        .limit(1)
    )
    return db.execute(stmt).scalars().first()


def latest_ml_model_status(db: Session, *, detector_id: str, model_type: str) -> tuple[str, datetime | None]:
    row = db.execute(
        select(UebaMlModelModel.status, UebaMlModelModel.training_finished_at)
        .where(UebaMlModelModel.detector_id == detector_id, UebaMlModelModel.model_type == model_type)
        .order_by(UebaMlModelModel.training_finished_at.desc(), UebaMlModelModel.id.desc())
        .limit(1)
    ).first()
    if row is None:
        return "unavailable", None
    status = str(row[0] or "unavailable")
    if status == "active":
        return "active", row[1]
    if status == "training":
        return "training", row[1]
    return "stale", row[1]


def mark_active_ml_models_superseded(
    db: Session,
    *,
    detector_id: str,
    agent_id: str | None,
    model_type: str,
) -> int:
    rows = db.execute(
        select(UebaMlModelModel).where(
            UebaMlModelModel.detector_id == detector_id,
            UebaMlModelModel.agent_id == agent_id,
            UebaMlModelModel.model_type == model_type,
            UebaMlModelModel.status == "active",
        )
    ).scalars().all()
    for row in rows:
        row.status = "superseded"
        db.add(row)
    return len(rows)


def mark_ml_model_used(db: Session, row: UebaMlModelModel, *, used_at: datetime) -> None:
    row.last_used_at = _utc(used_at)
    db.add(row)


def sweep_superseded_ml_models(db: Session, *, cutoff: datetime) -> int:
    rows = db.execute(
        select(UebaMlModelModel).where(
            UebaMlModelModel.status == "superseded",
            UebaMlModelModel.training_finished_at < _utc(cutoff),
        )
    ).scalars().all()
    for row in rows:
        db.delete(row)
    return len(rows)


def list_mature_agent_ids(db: Session, *, matured_before: datetime | None = None) -> list[str]:
    stmt = (
        select(UebaBaselineModel.agent_id)
        .where(UebaBaselineModel.status == "mature", UebaBaselineModel.agent_id.isnot(None))
        .group_by(UebaBaselineModel.agent_id)
        .order_by(UebaBaselineModel.agent_id.asc())
    )
    if matured_before is not None:
        stmt = stmt.where(UebaBaselineModel.matured_at.isnot(None), UebaBaselineModel.matured_at <= _utc(matured_before))
    return [str(value) for value in db.execute(stmt).scalars().all() if value]


def create_peer_group(db: Session, **values) -> UebaPeerGroupModel:
    row = UebaPeerGroupModel(**values)
    db.add(row)
    return row


def latest_peer_group_run_id(db: Session) -> str | None:
    computed_at = db.execute(select(func.max(UebaPeerGroupModel.computed_at))).scalar()
    if computed_at is None:
        return None
    return db.execute(
        select(UebaPeerGroupModel.run_id)
        .where(UebaPeerGroupModel.computed_at == computed_at)
        .order_by(UebaPeerGroupModel.id.desc())
        .limit(1)
    ).scalar()


def list_peer_groups_for_run(db: Session, *, run_id: str) -> list[UebaPeerGroupModel]:
    stmt = select(UebaPeerGroupModel).where(UebaPeerGroupModel.run_id == run_id)
    return db.execute(stmt).scalars().all()


def get_latest_peer_group_for_agent(db: Session, *, agent_id: str) -> UebaPeerGroupModel | None:
    stmt = (
        select(UebaPeerGroupModel)
        .where(UebaPeerGroupModel.agent_id == agent_id)
        .order_by(UebaPeerGroupModel.computed_at.desc(), UebaPeerGroupModel.id.desc())
        .limit(1)
    )
    return db.execute(stmt).scalars().first()


def sweep_peer_groups(db: Session, *, cutoff: datetime) -> int:
    rows = db.execute(select(UebaPeerGroupModel).where(UebaPeerGroupModel.computed_at < _utc(cutoff))).scalars().all()
    for row in rows:
        db.delete(row)
    return len(rows)


def list_high_peer_deviation_findings(db: Session, *, min_risk_score: int = 70) -> list[UebaFindingModel]:
    stmt = (
        select(UebaFindingModel)
        .where(
            UebaFindingModel.detector_id == "peer_group_deviation_v1",
            UebaFindingModel.status == "open",
            UebaFindingModel.risk_score >= int(min_risk_score),
        )
        .order_by(UebaFindingModel.risk_score.desc(), UebaFindingModel.last_seen_at.desc())
    )
    return db.execute(stmt).scalars().all()


def summary_metrics(db: Session, *, now: datetime | None = None) -> dict:
    baseline_row = db.execute(
        select(
            func.count(UebaBaselineModel.id),
            func.sum(case((UebaBaselineModel.status == "warmup", 1), else_=0)),
            func.sum(case((UebaBaselineModel.status == "mature", 1), else_=0)),
            func.sum(case((UebaBaselineModel.status == "stale", 1), else_=0)),
        )
    ).one()
    finding_row = db.execute(
        select(
            func.sum(case((UebaFindingModel.status == "open", 1), else_=0)),
            func.sum(
                case(
                    (
                        and_(
                            UebaFindingModel.status == "open",
                            UebaFindingModel.severity.in_(["high", "critical"]),
                        ),
                        1,
                    ),
                    else_=0,
                )
            ),
            func.sum(case((UebaFindingModel.alert_id.isnot(None), 1), else_=0)),
            func.max(UebaFindingModel.last_seen_at),
        )
    ).one()
    detector_row = db.execute(
        select(
            func.count(UebaDetectorStateModel.detector_id),
            func.sum(case((UebaDetectorStateModel.status == "healthy", 1), else_=0)),
            func.sum(case((UebaDetectorStateModel.status == "degraded", 1), else_=0)),
            func.sum(case((UebaDetectorStateModel.status == "failing", 1), else_=0)),
        )
    ).one()
    latest_run_at = db.execute(select(func.max(UebaDetectorRunModel.started_at))).scalar()

    now_v = _utc(now)
    since_24h = now_v - timedelta(hours=24)
    since_7d = now_v - timedelta(days=7)
    verdicts_last_24h = int(
        db.execute(
            select(func.count(UebaFeedbackModel.id)).where(UebaFeedbackModel.annotated_at >= since_24h)
        ).scalar()
        or 0
    )
    fp_closed_7d = int(
        db.execute(
            select(func.count(UebaFindingModel.id)).where(
                UebaFindingModel.latest_verdict == "false_positive",
                UebaFindingModel.closed_at.isnot(None),
                UebaFindingModel.closed_at >= since_7d,
            )
        ).scalar()
        or 0
    )
    closed_7d = int(
        db.execute(
            select(func.count(UebaFindingModel.id)).where(
                UebaFindingModel.status.in_(["closed", "suppressed"]),
                UebaFindingModel.closed_at.isnot(None),
                UebaFindingModel.closed_at >= since_7d,
            )
        ).scalar()
        or 0
    )
    false_positive_rate_7d = round(fp_closed_7d / closed_7d, 4) if closed_7d > 0 else 0.0
    suppressed_entities = count_active_suppressions(db, now=now_v)

    return {
        "total_baselines": int(baseline_row[0] or 0),
        "warming_baselines": int(baseline_row[1] or 0),
        "mature_baselines": int(baseline_row[2] or 0),
        "stale_baselines": int(baseline_row[3] or 0),
        "open_findings": int(finding_row[0] or 0),
        "high_or_critical_open_findings": int(finding_row[1] or 0),
        "linked_alerts": int(finding_row[2] or 0),
        "latest_finding_at": finding_row[3],
        "detectors_total": int(detector_row[0] or 0),
        "detectors_healthy": int(detector_row[1] or 0),
        "detectors_degraded": int(detector_row[2] or 0),
        "detectors_failing": int(detector_row[3] or 0),
        "latest_run_at": latest_run_at,
        "verdicts_last_24h": verdicts_last_24h,
        "false_positive_rate_7d": false_positive_rate_7d,
        "suppressed_entities": suppressed_entities,
    }


def flush(db: Session) -> None:
    db.flush()


def refresh(db: Session, row) -> None:
    db.refresh(row)


def commit(db: Session) -> None:
    db.commit()
