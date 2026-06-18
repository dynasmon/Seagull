from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.features.inventory.models import AgentInventoryLatestModel, AgentInventorySnapshotModel


class AgentInventoryLatestSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    snapshot_id: int
    os: dict[str, Any]
    collected_at: datetime
    updated_at: datetime
    packages_count: int


class AgentInventoryLatestDTO(BaseModel):
    model_config = ConfigDict(frozen=True)

    agent_id: str
    os: dict[str, Any]
    collected_at: datetime
    updated_at: datetime
    extra: dict[str, Any]


def get_latest_inventory_for_agent(db: Session, *, agent_id: str) -> AgentInventoryLatestSummary | None:
    row = db.execute(
        select(
            AgentInventoryLatestModel.snapshot_id,
            AgentInventoryLatestModel.os,
            AgentInventoryLatestModel.collected_at,
            AgentInventoryLatestModel.updated_at,
            AgentInventoryLatestModel.packages_count,
        ).where(AgentInventoryLatestModel.agent_id == agent_id)
    ).mappings().first()
    if not row:
        return None
    return AgentInventoryLatestSummary(
        snapshot_id=row["snapshot_id"],
        os=row["os"] or {},
        collected_at=row["collected_at"],
        updated_at=row["updated_at"],
        packages_count=row["packages_count"],
    )


def list_latest_inventory(db: Session, *, limit: int) -> list[AgentInventoryLatestDTO]:
    rows = db.execute(
        select(AgentInventoryLatestModel)
        .order_by(AgentInventoryLatestModel.updated_at.desc())
        .limit(limit)
    ).scalars().all()
    return [
        AgentInventoryLatestDTO(
            agent_id=row.agent_id,
            os=row.os or {},
            collected_at=row.collected_at,
            updated_at=row.updated_at,
            extra=row.extra or {},
        )
        for row in rows
    ]


def get_snapshot_packages_count(db: Session, *, snapshot_id: int) -> int | None:
    row = db.execute(
        select(AgentInventorySnapshotModel.packages_count).where(AgentInventorySnapshotModel.id == snapshot_id)
    ).first()
    if not row:
        return None
    return int(row[0] or 0)


def get_snapshot_packages(db: Session, *, snapshot_id: int) -> list[Any]:
    row = db.execute(
        select(AgentInventorySnapshotModel.packages).where(AgentInventorySnapshotModel.id == snapshot_id)
    ).mappings().first()
    if not row:
        return []
    packages = row.get("packages")
    return packages if isinstance(packages, list) else []
