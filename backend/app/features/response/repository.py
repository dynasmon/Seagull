from __future__ import annotations

from sqlalchemy.orm import Session

from app.features.agents.models import AgentModel
from app.features.response.models import ResponseActionModel


def get_agent(db: Session, *, agent_id: str) -> AgentModel | None:
    return db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()


def create_action(
    db: Session,
    *,
    action_type: str,
    agent_id: str,
    status: str,
    payload: dict,
    requested_by: str,
    requested_at,
    expires_at,
) -> ResponseActionModel:
    row = ResponseActionModel(
        action_type=action_type,
        agent_id=agent_id,
        status=status,
        payload=payload,
        requested_by=requested_by,
        requested_at=requested_at,
        expires_at=expires_at,
    )
    db.add(row)
    return row


def list_actions_by_status(
    db: Session,
    *,
    status: str,
    agent_id: str | None = None,
    limit: int = 100,
) -> list[ResponseActionModel]:
    q = db.query(ResponseActionModel).filter(ResponseActionModel.status == status)
    if agent_id:
        q = q.filter(ResponseActionModel.agent_id == agent_id)
    return q.order_by(ResponseActionModel.requested_at.desc(), ResponseActionModel.id.desc()).limit(int(limit)).all()


def get_action(db: Session, *, action_id: int) -> ResponseActionModel | None:
    return db.query(ResponseActionModel).filter(ResponseActionModel.id == int(action_id)).first()


def save_action(db: Session, row: ResponseActionModel) -> ResponseActionModel:
    db.add(row)
    return row


def flush(db: Session) -> None:
    db.flush()


def refresh(db: Session, row: ResponseActionModel) -> None:
    db.refresh(row)


def commit(db: Session) -> None:
    db.commit()
