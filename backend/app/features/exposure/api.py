from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, Response, status
from sqlalchemy.orm import Session

from app.core.api.conditional import maybe_not_modified
from app.core.audit import write_audit_event
from app.core.db import get_db
from app.core.db.session import managed_session
from app.core.observability import incr_counter
from app.features.auth.session import PortalPrincipal, get_current_user, require_admin
from app.features.exposure import service
from app.features.exposure.schemas import (
    ExposureAssetDetailOut,
    ExposureAssetPostureOut,
    ExposureAssetsQuery,
    ExposureAttackPathOut,
    ExposureErrorOut,
    ExposureFindingOut,
    ExposureFindingsQuery,
    ExposureGraphOut,
    ExposureGraphQuery,
    ExposureInvestigationResultOut,
    ExposurePathsQuery,
    ExposureRecalculateOut,
    ExposureSummaryOut,
    ExposureTriageResponseActionOut,
)
from app.shared.schemas import CursorPage

router = APIRouter(
    prefix="/exposure",
    tags=["exposure"],
    dependencies=[Depends(get_current_user)],
)


@router.get("/summary", response_model=ExposureSummaryOut)
async def get_summary(request: Request, response: Response):
    payload, etag, outcome = await service.get_exposure_summary_async()
    response.headers["X-Cache-Outcome"] = outcome
    incr_counter("api_cache_outcome_total", route="/exposure/summary", outcome=outcome)
    not_modified = maybe_not_modified(response, request.headers.get("If-None-Match"), etag, outcome=outcome)
    if not_modified is not None:
        incr_counter("api_304_total", route="/exposure/summary")
        return not_modified
    return payload


@router.get("/assets", response_model=CursorPage[ExposureAssetPostureOut])
def list_assets(
    page_size: int = Query(50, ge=1, le=200),
    cursor: str | None = Query(None),
    q: str | None = Query(None, max_length=128),
    severity: str | None = Query(None),
    min_score: int | None = Query(None, ge=0, le=100),
    agent_id: str | None = Query(None, min_length=1, max_length=64),
    status_filter: str | None = Query(None, alias="status"),
    reason_code: str | None = Query(None, max_length=64),
    has_attack_chain: bool | None = Query(None),
    has_critical_vuln: bool | None = Query(None),
    has_persistence_signal: bool | None = Query(None),
    sort: str = Query("risk_desc"),
    db: Session = Depends(get_db),
):
    params = ExposureAssetsQuery(
        page_size=page_size,
        cursor=cursor,
        q=q,
        severity=severity,
        min_score=min_score,
        agent_id=agent_id,
        status=status_filter,
        reason_code=reason_code,
        has_attack_chain=has_attack_chain,
        has_critical_vuln=has_critical_vuln,
        has_persistence_signal=has_persistence_signal,
        sort=sort,
    )
    with managed_session(db) as db_session:
        return service.list_assets(db_session, params=params)


@router.get("/assets/{asset_key:path}/graph", response_model=ExposureGraphOut)
def get_asset_graph(
    asset_key: str,
    depth: int = Query(2, ge=1, le=8),
    node_types: list[str] | None = Query(None),
    edge_types: list[str] | None = Query(None),
    min_confidence: int = Query(1, ge=1, le=99),
    max_nodes: int = Query(80, ge=1, le=1000),
    max_edges: int = Query(120, ge=1, le=1000),
    include_resolved: bool = Query(False),
    db: Session = Depends(get_db),
):
    params = ExposureGraphQuery(
        depth=depth,
        node_types=node_types or [],
        edge_types=edge_types or [],
        min_confidence=min_confidence,
        max_nodes=max_nodes,
        max_edges=max_edges,
        include_resolved=include_resolved,
    )
    with managed_session(db) as db_session:
        normalized_asset_key = service.decode_and_validate_asset_key(asset_key)
        return service.get_asset_graph(db_session, asset_key=normalized_asset_key, params=params)


@router.get("/assets/{asset_key:path}", response_model=ExposureAssetDetailOut)
def get_asset_detail(asset_key: str, db: Session = Depends(get_db)):
    with managed_session(db) as db_session:
        normalized_asset_key = service.decode_and_validate_asset_key(asset_key)
        return service.get_asset_detail(db_session, asset_key=normalized_asset_key)


@router.get("/paths", response_model=CursorPage[ExposureAttackPathOut])
async def list_paths(
    request: Request,
    response: Response,
    page_size: int = Query(25, ge=1, le=100),
    cursor: str | None = Query(None),
    severity: str | None = Query(None),
    agent_id: str | None = Query(None, min_length=1, max_length=64),
    min_score: int | None = Query(None, ge=0, le=100),
    reason_code: str | None = Query(None, max_length=64),
):
    params = ExposurePathsQuery(
        page_size=page_size,
        cursor=cursor,
        severity=severity,
        agent_id=agent_id,
        min_score=min_score,
        reason_code=reason_code,
    )
    payload, etag, outcome = await service.list_paths_async(params=params)
    response.headers["X-Cache-Outcome"] = outcome
    incr_counter("api_cache_outcome_total", route="/exposure/paths", outcome=outcome)
    not_modified = maybe_not_modified(response, request.headers.get("If-None-Match"), etag, outcome=outcome)
    if not_modified is not None:
        incr_counter("api_304_total", route="/exposure/paths")
        return not_modified
    return payload


@router.get("/findings", response_model=CursorPage[ExposureFindingOut])
def list_findings(
    page_size: int = Query(50, ge=1, le=200),
    cursor: str | None = Query(None),
    asset_key: str | None = Query(None, max_length=256),
    agent_id: str | None = Query(None, min_length=1, max_length=64),
    finding_type: str | None = Query(None, max_length=32),
    severity: str | None = Query(None),
    status_filter: str | None = Query(None, alias="status"),
    q: str | None = Query(None, max_length=256),
    db: Session = Depends(get_db),
):
    params = ExposureFindingsQuery(
        page_size=page_size,
        cursor=cursor,
        asset_key=asset_key,
        agent_id=agent_id,
        finding_type=finding_type,
        severity=severity,
        status=status_filter,
        q=q,
    )
    with managed_session(db) as db_session:
        return service.list_findings(db_session, params=params)


@router.post(
    "/recalculate",
    response_model=ExposureRecalculateOut,
    status_code=status.HTTP_202_ACCEPTED,
    responses={409: {"model": ExposureErrorOut}},
)
def recalculate_exposure(
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.request_recalculate(db_session, request=request, admin=admin)


@router.post(
    "/assets/{asset_key:path}/investigation",
    response_model=ExposureInvestigationResultOut,
    responses={400: {"model": ExposureErrorOut}, 404: {"model": ExposureErrorOut}},
)
def open_asset_investigation(
    asset_key: str,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        normalized_asset_key = service.decode_and_validate_asset_key(asset_key)
        return service.open_asset_investigation(
            db_session,
            asset_key=normalized_asset_key,
            request=request,
            admin=admin,
            audit_writer=write_audit_event,
        )


@router.post(
    "/assets/{asset_key:path}/response-actions/triage",
    response_model=ExposureTriageResponseActionOut,
    status_code=status.HTTP_201_CREATED,
    responses={400: {"model": ExposureErrorOut}, 404: {"model": ExposureErrorOut}, 409: {"model": ExposureErrorOut}},
)
def create_asset_triage_action(
    asset_key: str,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        normalized_asset_key = service.decode_and_validate_asset_key(asset_key)
        return service.create_asset_triage_response_action(
            db_session,
            asset_key=normalized_asset_key,
            request=request,
            admin=admin,
            audit_writer=write_audit_event,
        )
