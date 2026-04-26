from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.api_db import managed_session
from app.core.db import get_db
from app.core.portal_auth import get_current_user
from app.features.exposure import service
from app.features.exposure.schemas import (
    ExposureAssetPostureDB,
    ExposureEdgeDB,
    ExposureFindingDB,
    ExposureNodeDB,
    ExposureScoreHistoryDB,
)
from app.shared.schemas import CursorPage

router = APIRouter(
    prefix="/exposure",
    tags=["exposure"],
    dependencies=[Depends(get_current_user)],
)


@router.get("/posture", response_model=CursorPage[ExposureAssetPostureDB])
def list_postures(
    agent_id: str | None = Query(None),
    min_score: int | None = Query(None, ge=0, le=100),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    page_size: int = Query(50, ge=1, le=200),
    cursor: str | None = Query(None),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.list_asset_postures(
            db_session,
            agent_id=agent_id,
            min_score=min_score,
            severity=severity,
            status=status,
            page_size=page_size,
            cursor=cursor,
        )


@router.get("/posture/{asset_key:path}", response_model=ExposureAssetPostureDB)
def get_posture(
    asset_key: str,
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        row = service.get_asset_posture(db_session, asset_key)
        if row is None:
            from fastapi import HTTPException  # noqa: PLC0415
            raise HTTPException(status_code=404, detail="Asset posture not found")
        return row


@router.get("/findings", response_model=CursorPage[ExposureFindingDB])
def list_findings(
    asset_key: str | None = Query(None),
    agent_id: str | None = Query(None),
    finding_type: str | None = Query(None),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    page_size: int = Query(50, ge=1, le=200),
    cursor: str | None = Query(None),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.list_findings(
            db_session,
            asset_key=asset_key,
            agent_id=agent_id,
            finding_type=finding_type,
            severity=severity,
            status=status,
            page_size=page_size,
            cursor=cursor,
        )


@router.get("/graph/nodes", response_model=list[ExposureNodeDB])
def list_nodes(
    asset_key: str = Query(...),
    page_size: int = Query(100, ge=1, le=200),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.list_nodes_for_asset(db_session, asset_key=asset_key, page_size=page_size)


@router.get("/graph/edges", response_model=list[ExposureEdgeDB])
def list_edges(
    asset_key: str = Query(...),
    page_size: int = Query(100, ge=1, le=200),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.list_edges_for_asset(db_session, asset_key=asset_key, page_size=page_size)


@router.get("/score-history", response_model=list[ExposureScoreHistoryDB])
def score_history(
    asset_key: str = Query(...),
    limit: int = Query(90, ge=1, le=365),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.list_score_history(db_session, asset_key=asset_key, limit=limit)
