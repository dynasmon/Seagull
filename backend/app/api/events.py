from typing import List, Optional

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select

from app.core.admin_auth import require_admin
from app.core.db import SessionLocal
from app.models.events import NetEventModel
from app.schemas.events import NetEventDB


def _admin_dep(request: Request) -> None:
    require_admin(request)


router = APIRouter(
    prefix="/events",
    tags=["events"],
    dependencies=[Depends(_admin_dep)],
)


@router.get("/recent", response_model=List[NetEventDB])
def get_recent_events(
    limit: int = Query(50, ge=1, le=1000, description="Maximum number of events to return"),
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
):
    # Return the most recent events, optionally filtered by agent_id and event_type.
    db = SessionLocal()
    try:
        stmt = select(NetEventModel).order_by(NetEventModel.timestamp.desc())
        if agent_id:
            stmt = stmt.where(NetEventModel.agent_id == agent_id)
        if event_type:
            stmt = stmt.where(NetEventModel.event_type == event_type)
        stmt = stmt.limit(limit)

        result = db.execute(stmt)
        return result.scalars().all()
    finally:
        db.close()


@router.get("/stats/ports")
def get_port_stats(
    limit: int = Query(20, ge=1, le=200, description="Maximum number of ports to return"),
):
    # Return a simple distribution of events by destination port.
    db = SessionLocal()
    try:
        stmt = (
            select(
                NetEventModel.dst_port.label("port"),
                func.count().label("count"),
            )
            .where(NetEventModel.dst_port.is_not(None))
            .group_by(NetEventModel.dst_port)
            .order_by(func.count().desc())
            .limit(limit)
        )

        rows = db.execute(stmt).all()
        return [{"port": row.port, "count": row.count} for row in rows]
    finally:
        db.close()
