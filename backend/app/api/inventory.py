import hashlib
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select

from app.core.agent_auth import AgentPrincipal, get_current_agent
from app.core.admin_auth import require_admin
from app.core.db import SessionLocal
from app.models.inventory import AgentInventorySnapshotModel
from app.schemas.inventory import InventorySnapshotIn, InventorySnapshotOut, PackageEntry


router = APIRouter(
    prefix="/inventory",
    tags=["inventory"],
)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_packages(packages: List[PackageEntry]) -> bytes:
    rows = [f"{p.name}\t{p.version}\t{p.arch or ''}" for p in packages]
    rows.sort()
    return ("\n".join(rows) + "\n").encode("utf-8") if rows else b""


@router.post("", status_code=status.HTTP_201_CREATED)
async def ingest_inventory(
    payload: InventorySnapshotIn,
    agent: AgentPrincipal = Depends(get_current_agent),
):
    now = datetime.now(timezone.utc)
    packages_count = payload.packages_count if payload.packages_count is not None else len(payload.packages)
    if packages_count != len(payload.packages):
        packages_count = len(payload.packages)

    packages_hash = (payload.packages_hash or "").strip()
    if not packages_hash or len(packages_hash) != 64:
        packages_hash = _sha256_hex(_canonical_packages(payload.packages))

    extra = dict(payload.extra or {})
    if payload.collected_at is not None:
        try:
            ts = payload.collected_at
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            extra.setdefault("client_collected_at", ts.isoformat())
        except Exception:
            pass

    db = SessionLocal()
    try:
        row = AgentInventorySnapshotModel(
            agent_id=agent.agent_id,
            collected_at=now,
            schema_version=int(payload.schema_version or 1),
            os=dict(payload.os or {}),
            packages=[p.dict() for p in payload.packages],
            packages_hash=packages_hash,
            packages_count=int(packages_count),
            manager=payload.manager,
            extra=extra,
        )
        db.add(row)
        db.commit()
        return {"id": row.id, "stored": True}
    finally:
        db.close()


@router.get("/me/latest", response_model=InventorySnapshotOut)
async def get_my_latest_inventory(agent: AgentPrincipal = Depends(get_current_agent)):
    db = SessionLocal()
    try:
        stmt = (
            select(AgentInventorySnapshotModel)
            .where(AgentInventorySnapshotModel.agent_id == agent.agent_id)
            .order_by(AgentInventorySnapshotModel.collected_at.desc())
            .limit(1)
        )
        row = db.execute(stmt).scalars().first()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No inventory")
        return row
    finally:
        db.close()


@router.get("/me/history", response_model=List[InventorySnapshotOut])
async def get_my_inventory_history(
    limit: int = Query(20, ge=1, le=200),
    agent: AgentPrincipal = Depends(get_current_agent),
):
    db = SessionLocal()
    try:
        stmt = (
            select(AgentInventorySnapshotModel)
            .where(AgentInventorySnapshotModel.agent_id == agent.agent_id)
            .order_by(AgentInventorySnapshotModel.collected_at.desc())
            .limit(limit)
        )
        return db.execute(stmt).scalars().all()
    finally:
        db.close()


@router.get("/{agent_id}/latest", response_model=InventorySnapshotOut)
async def get_agent_latest_inventory(request: Request, agent_id: str):
    require_admin(request)
    db = SessionLocal()
    try:
        stmt = (
            select(AgentInventorySnapshotModel)
            .where(AgentInventorySnapshotModel.agent_id == agent_id)
            .order_by(AgentInventorySnapshotModel.collected_at.desc())
            .limit(1)
        )
        row = db.execute(stmt).scalars().first()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No inventory")
        return row
    finally:
        db.close()


@router.get("/{agent_id}/history", response_model=List[InventorySnapshotOut])
async def get_agent_inventory_history(
    request: Request,
    agent_id: str,
    limit: int = Query(20, ge=1, le=200),
):
    require_admin(request)
    db = SessionLocal()
    try:
        stmt = (
            select(AgentInventorySnapshotModel)
            .where(AgentInventorySnapshotModel.agent_id == agent_id)
            .order_by(AgentInventorySnapshotModel.collected_at.desc())
            .limit(limit)
        )
        return db.execute(stmt).scalars().all()
    finally:
        db.close()
