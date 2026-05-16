from __future__ import annotations

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.db.session import managed_session
from app.features.auth.session import PortalPrincipal, get_current_user, require_admin
from app.features.network_topology import service
from app.features.network_topology.schemas import (
    TopologyEdgeDetailOut,
    TopologyErrorOut,
    TopologyGraphOut,
    TopologyGraphQuery,
    TopologyGroupDetailOut,
    TopologyNodeDetailOut,
    TopologyObservationOut,
    TopologyObservationQuery,
    TopologyRecalculateOut,
    TopologySubnetOut,
    TopologySubnetQuery,
    TopologySummaryOut,
)
from app.shared.schemas import CursorPage

router = APIRouter(
    prefix="/network-topology",
    tags=["network-topology"],
    dependencies=[Depends(get_current_user)],
)


@router.get("/summary", response_model=TopologySummaryOut)
def get_summary(db: Session = Depends(get_db)):
    with managed_session(db) as db_session:
        return service.get_summary(db_session)


@router.get("/graph", response_model=TopologyGraphOut)
def get_graph(
    max_nodes: int = Query(200, ge=1, le=2000),
    max_edges: int = Query(300, ge=1, le=3000),
    min_confidence: int = Query(1, ge=1, le=99),
    agent_id: str | None = Query(None, min_length=1, max_length=64),
    node_types: list[str] | None = Query(None),
    edge_types: list[str] | None = Query(None),
    ip_scope: str | None = Query(None, max_length=32),
    since: str | None = Query(None),
    until: str | None = Query(None),
    include_stale: bool = Query(False),
    view_mode: str | None = Query(None, max_length=16),
    group_by: str | None = Query(None, max_length=16),
    focused_group_key: str | None = Query(None, max_length=256),
    exclusive_focus: bool = Query(False),
    db: Session = Depends(get_db),
):
    params = TopologyGraphQuery(
        max_nodes=max_nodes,
        max_edges=max_edges,
        min_confidence=min_confidence,
        agent_id=agent_id,
        node_types=node_types or [],
        edge_types=edge_types or [],
        ip_scope=ip_scope,
        since=_parse_dt(since),
        until=_parse_dt(until),
        include_stale=include_stale,
        view_mode=view_mode,
        group_by=group_by,
        focused_group_key=focused_group_key,
        exclusive_focus=exclusive_focus,
    )
    with managed_session(db) as db_session:
        return service.get_graph(db_session, params)


@router.get(
    "/nodes/{node_key:path}",
    response_model=TopologyNodeDetailOut,
    responses={404: {"model": TopologyErrorOut}},
)
def get_node_detail(node_key: str, db: Session = Depends(get_db)):
    with managed_session(db) as db_session:
        return service.get_node_detail(db_session, node_key)


@router.get(
    "/edges/{edge_key:path}",
    response_model=TopologyEdgeDetailOut,
    responses={404: {"model": TopologyErrorOut}},
)
def get_edge_detail(edge_key: str, db: Session = Depends(get_db)):
    with managed_session(db) as db_session:
        return service.get_edge_detail(db_session, edge_key)


@router.get(
    "/groups/{group_key:path}",
    response_model=TopologyGroupDetailOut,
    responses={404: {"model": TopologyErrorOut}},
)
def get_group_detail(
    group_key: str,
    max_nodes: int = Query(200, ge=1, le=2000),
    max_edges: int = Query(300, ge=1, le=3000),
    min_confidence: int = Query(1, ge=1, le=99),
    agent_id: str | None = Query(None, min_length=1, max_length=64),
    group_by: str | None = Query(None, max_length=16),
    since: str | None = Query(None),
    until: str | None = Query(None),
    include_stale: bool = Query(False),
    db: Session = Depends(get_db),
):
    params = TopologyGraphQuery(
        max_nodes=max_nodes,
        max_edges=max_edges,
        min_confidence=min_confidence,
        agent_id=agent_id,
        group_by=group_by,
        since=_parse_dt(since),
        until=_parse_dt(until),
        include_stale=include_stale,
    )
    with managed_session(db) as db_session:
        return service.get_group_detail(db_session, group_key, params)


@router.get("/subnets", response_model=CursorPage[TopologySubnetOut])
def list_subnets(
    page_size: int = Query(50, ge=1, le=200),
    cursor: str | None = Query(None),
    agent_id: str | None = Query(None, min_length=1, max_length=64),
    since: str | None = Query(None),
    until: str | None = Query(None),
    db: Session = Depends(get_db),
):
    params = TopologySubnetQuery(
        page_size=page_size,
        cursor=cursor,
        agent_id=agent_id,
        since=_parse_dt(since),
        until=_parse_dt(until),
    )
    with managed_session(db) as db_session:
        return service.list_subnets(db_session, params)


@router.get("/observations", response_model=CursorPage[TopologyObservationOut])
def list_observations(
    page_size: int = Query(50, ge=1, le=200),
    cursor: str | None = Query(None),
    node_key: str | None = Query(None, max_length=256),
    agent_id: str | None = Query(None, min_length=1, max_length=64),
    source_type: str | None = Query(None, max_length=32),
    since: str | None = Query(None),
    until: str | None = Query(None),
    db: Session = Depends(get_db),
):
    params = TopologyObservationQuery(
        page_size=page_size,
        cursor=cursor,
        node_key=node_key,
        agent_id=agent_id,
        source_type=source_type,
        since=_parse_dt(since),
        until=_parse_dt(until),
    )
    with managed_session(db) as db_session:
        return service.list_observations(db_session, params)


@router.post(
    "/recalculate",
    response_model=TopologyRecalculateOut,
    status_code=status.HTTP_202_ACCEPTED,
    responses={403: {"model": TopologyErrorOut}},
)
def recalculate(
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.request_recalculate(db_session, admin=admin)


def _parse_dt(value: str | None):
    if not value:
        return None
    from datetime import datetime, timezone
    try:
        dt = datetime.fromisoformat(str(value).strip().rstrip("Zz"))
    except Exception:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt
