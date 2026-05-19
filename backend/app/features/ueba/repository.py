from __future__ import annotations

from datetime import datetime

from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.orm import Session

from app.features.ueba.models import (
    UebaBaselineModel,
    UebaDetectorRunModel,
    UebaDetectorStateModel,
    UebaFindingEvidenceModel,
    UebaFindingModel,
)


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


def summary_metrics(db: Session) -> dict:
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
    }


def flush(db: Session) -> None:
    db.flush()


def refresh(db: Session, row) -> None:
    db.refresh(row)


def commit(db: Session) -> None:
    db.commit()
