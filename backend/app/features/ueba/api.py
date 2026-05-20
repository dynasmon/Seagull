from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.db.session import managed_session
from app.features.auth.session import get_current_user
from app.features.ueba import service
from app.features.ueba.schemas import (
    UebaBaselineOut,
    UebaBaselinesQuery,
    UebaBaselineStatus,
    UebaDetectorRunOut,
    UebaDetectorStateOut,
    UebaFindingDetailOut,
    UebaFindingListItemOut,
    UebaFindingsQuery,
    UebaFindingStatus,
    UebaFindingTriageIn,
    UebaRunsQuery,
    UebaRunStatus,
    UebaSeverity,
    UebaSummaryOut,
)
from app.shared.schemas import CursorPage

router = APIRouter(
    prefix="/ueba",
    tags=["ueba"],
    dependencies=[Depends(get_current_user)],
)


@router.get("/summary", response_model=UebaSummaryOut)
def get_summary(db: Session = Depends(get_db)):
    with managed_session(db) as db_session:
        return service.get_summary(db_session)


@router.get("/findings", response_model=CursorPage[UebaFindingListItemOut])
def list_findings(
    page_size: int = Query(50, ge=1, le=200),
    cursor: str | None = Query(None),
    detector_id: str | None = Query(None, min_length=1, max_length=96),
    agent_id: str | None = Query(None, min_length=1, max_length=64),
    entity_type: str | None = Query(None, min_length=1, max_length=64),
    entity_value: str | None = Query(None, min_length=1, max_length=256),
    metric_name: str | None = Query(None, min_length=1, max_length=96),
    status_filter: UebaFindingStatus | None = Query(None, alias="status"),
    severity: UebaSeverity | None = Query(None),
    min_risk_score: int | None = Query(None, ge=0, le=100),
    db: Session = Depends(get_db),
):
    params = UebaFindingsQuery(
        page_size=page_size,
        cursor=cursor,
        detector_id=detector_id,
        agent_id=agent_id,
        entity_type=entity_type,
        entity_value=entity_value,
        metric_name=metric_name,
        status=status_filter,
        severity=severity,
        min_risk_score=min_risk_score,
    )
    with managed_session(db) as db_session:
        return service.list_findings(db_session, params=params)


@router.get("/findings/{finding_id}", response_model=UebaFindingDetailOut)
def get_finding_detail(finding_id: int, db: Session = Depends(get_db)):
    with managed_session(db) as db_session:
        return service.get_finding_detail(db_session, finding_id)


@router.get("/baselines", response_model=CursorPage[UebaBaselineOut])
def list_baselines(
    page_size: int = Query(50, ge=1, le=200),
    cursor: str | None = Query(None),
    detector_id: str | None = Query(None, min_length=1, max_length=96),
    agent_id: str | None = Query(None, min_length=1, max_length=64),
    entity_type: str | None = Query(None, min_length=1, max_length=64),
    entity_value: str | None = Query(None, min_length=1, max_length=256),
    metric_name: str | None = Query(None, min_length=1, max_length=96),
    status_filter: UebaBaselineStatus | None = Query(None, alias="status"),
    db: Session = Depends(get_db),
):
    params = UebaBaselinesQuery(
        page_size=page_size,
        cursor=cursor,
        detector_id=detector_id,
        agent_id=agent_id,
        entity_type=entity_type,
        entity_value=entity_value,
        metric_name=metric_name,
        status=status_filter,
    )
    with managed_session(db) as db_session:
        return service.list_baselines(db_session, params=params)


@router.get("/detectors", response_model=list[UebaDetectorStateOut])
def list_detectors(db: Session = Depends(get_db)):
    with managed_session(db) as db_session:
        return service.list_detector_states(db_session)


@router.get("/runs", response_model=CursorPage[UebaDetectorRunOut])
def list_runs(
    page_size: int = Query(50, ge=1, le=200),
    cursor: str | None = Query(None),
    detector_id: str | None = Query(None, min_length=1, max_length=96),
    status_filter: UebaRunStatus | None = Query(None, alias="status"),
    db: Session = Depends(get_db),
):
    params = UebaRunsQuery(
        page_size=page_size,
        cursor=cursor,
        detector_id=detector_id,
        status=status_filter,
    )
    with managed_session(db) as db_session:
        return service.list_detector_runs(db_session, params=params)


@router.patch("/findings/{finding_id}", response_model=UebaFindingDetailOut)
def triage_finding_endpoint(
    finding_id: int,
    body: UebaFindingTriageIn,
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.triage_finding(db_session, finding_id, body)
