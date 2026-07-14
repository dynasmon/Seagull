from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.core.db import get_db, routed_db
from app.core.db.session import managed_session
from app.features.agents.auth import AgentPrincipal, get_current_agent
from app.features.auth.session import get_current_user
from app.features.inventory.schemas import InventorySnapshotIn, InventorySnapshotOut
from app.features.inventory.service import (
    get_inventory_overview,
    get_latest_inventory_or_404,
    ingest_inventory,
    list_inventory_history,
    list_inventory_history_page,
)
from app.shared.schemas import CursorPage

router = APIRouter(
    prefix="/inventory",
    tags=["inventory"],
)


@router.post("", status_code=status.HTTP_201_CREATED)
async def ingest_inventory_endpoint(
    payload: InventorySnapshotIn,
    agent: AgentPrincipal = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return ingest_inventory(db_session, payload=payload, agent_id=agent.agent_id)


@router.get("/me/latest", response_model=InventorySnapshotOut)
async def get_my_latest_inventory_endpoint(
    agent: AgentPrincipal = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return get_latest_inventory_or_404(db_session, agent_id=agent.agent_id)


@router.get("/me/history", response_model=list[InventorySnapshotOut])
async def get_my_inventory_history_endpoint(
    limit: int = Query(20, ge=1, le=200),
    agent: AgentPrincipal = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return list_inventory_history(db_session, agent_id=agent.agent_id, limit=limit)


@router.get("/me/history/page", response_model=CursorPage[InventorySnapshotOut])
async def get_my_inventory_history_page_endpoint(
    page_size: int = Query(50, ge=1, le=200, description="Page size (max 200)"),
    cursor: Optional[str] = Query(None, description="Opaque cursor from a previous call"),
    agent: AgentPrincipal = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return list_inventory_history_page(db_session, agent_id=agent.agent_id, page_size=page_size, cursor=cursor)


@router.get("/{agent_id}/latest", response_model=InventorySnapshotOut)
async def get_agent_latest_inventory_endpoint(
    agent_id: str,
    _user=Depends(get_current_user),
    db: Session = Depends(routed_db("inventory-read")),
):
    with managed_session(db) as db_session:
        return get_latest_inventory_or_404(db_session, agent_id=agent_id)


@router.get("/{agent_id}/history", response_model=list[InventorySnapshotOut])
async def get_agent_inventory_history_endpoint(
    agent_id: str,
    limit: int = Query(20, ge=1, le=200),
    _user=Depends(get_current_user),
    db: Session = Depends(routed_db("inventory-read")),
):
    with managed_session(db) as db_session:
        return list_inventory_history(db_session, agent_id=agent_id, limit=limit)


@router.get("/{agent_id}/history/page", response_model=CursorPage[InventorySnapshotOut])
async def get_agent_inventory_history_page_endpoint(
    agent_id: str,
    page_size: int = Query(50, ge=1, le=200, description="Page size (max 200)"),
    cursor: Optional[str] = Query(None, description="Opaque cursor from a previous call"),
    _user=Depends(get_current_user),
    db: Session = Depends(routed_db("inventory-read")),
):
    with managed_session(db) as db_session:
        return list_inventory_history_page(db_session, agent_id=agent_id, page_size=page_size, cursor=cursor)


@router.get("/overview")
async def get_inventory_overview_endpoint(
    window_minutes: int = Query(360, ge=30, le=7 * 24 * 60, description="Time window (minutes) for inventory charts"),
    agent_id: Optional[str] = Query(None, description="Optional agent filter. Use '__all' or omit for all agents."),
    _user=Depends(get_current_user),
    db: Session = Depends(routed_db("inventory-read")),
):
    with managed_session(db) as db_session:
        return get_inventory_overview(db_session, window_minutes=window_minutes, agent_id=agent_id)
