from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.features.agents.models import AgentModel


class AgentSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    agent_id: str
    display_name: str | None
    last_seen_at: datetime | None
    created_at: datetime | None
    config: dict[str, Any]
    is_revoked: bool


def _summary_from_mapping(row) -> AgentSummary:
    config = row.get("config") if isinstance(row.get("config"), dict) else {}
    return AgentSummary(
        agent_id=str(row["agent_id"]),
        display_name=row.get("display_name"),
        last_seen_at=row.get("last_seen_at"),
        created_at=row.get("created_at"),
        config=config,
        is_revoked=bool(row.get("is_revoked") or False),
    )


def _summary_from_model(row: AgentModel) -> AgentSummary:
    config = row.config if isinstance(row.config, dict) else {}
    return AgentSummary(
        agent_id=str(row.agent_id),
        display_name=row.display_name,
        last_seen_at=row.last_seen_at,
        created_at=row.created_at,
        config=config,
        is_revoked=bool(row.is_revoked or False),
    )


def list_active_agents_for_refresh(db: Session, *, limit: int) -> list[AgentSummary]:
    stmt = (
        select(
            AgentModel.agent_id,
            AgentModel.display_name,
            AgentModel.last_seen_at,
            AgentModel.config,
            AgentModel.is_revoked,
        )
        .where(AgentModel.is_revoked.is_(False))
        .order_by(AgentModel.last_seen_at.desc().nullslast(), AgentModel.agent_id)
        .limit(int(limit))
    )
    return [_summary_from_mapping(row) for row in db.execute(stmt).mappings().all()]


def get_agent_summary(db: Session, *, agent_id: str) -> AgentSummary | None:
    stmt = select(
        AgentModel.agent_id,
        AgentModel.display_name,
        AgentModel.last_seen_at,
        AgentModel.config,
        AgentModel.is_revoked,
    ).where(AgentModel.agent_id == agent_id)
    row = db.execute(stmt).mappings().first()
    if not row:
        return None
    return _summary_from_mapping(row)


def list_active_agents_for_projection(db: Session, *, limit: int) -> list[AgentSummary]:
    rows = (
        db.execute(
            select(AgentModel)
            .where(AgentModel.is_revoked.is_(False))
            .order_by(AgentModel.last_seen_at.desc())
            .limit(int(limit))
        )
        .scalars()
        .all()
    )
    return [_summary_from_model(row) for row in rows]


def list_all_agents(db: Session) -> list[AgentSummary]:
    rows = db.query(AgentModel).order_by(AgentModel.agent_id.asc()).all()
    return [_summary_from_model(row) for row in rows]
