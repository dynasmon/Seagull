from __future__ import annotations

from sqlalchemy.orm import Session

from app.features.agents.models import AgentModel
from app.features.response.models import ResponseActionModel, ResponseActionResultModel


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
    batch_id: str | None = None,
) -> ResponseActionModel:
    row = ResponseActionModel(
        action_type=action_type,
        agent_id=agent_id,
        status=status,
        payload=payload,
        requested_by=requested_by,
        requested_at=requested_at,
        expires_at=expires_at,
        batch_id=batch_id,
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


def list_actions(
    db: Session,
    *,
    agent_id: str | None = None,
    agent_ids: list[str] | None = None,
    status: str | None = None,
    action_types: list[str] | None = None,
    batch_id: str | None = None,
    since=None,
    limit: int = 100,
) -> list[ResponseActionModel]:
    q = db.query(ResponseActionModel)
    if agent_id:
        q = q.filter(ResponseActionModel.agent_id == agent_id)
    if agent_ids:
        q = q.filter(ResponseActionModel.agent_id.in_(list(agent_ids)))
    if status:
        q = q.filter(ResponseActionModel.status == status)
    if action_types is not None:
        q = q.filter(ResponseActionModel.action_type.in_(list(action_types)))
    if batch_id:
        q = q.filter(ResponseActionModel.batch_id == batch_id)
    if since is not None:
        q = q.filter(ResponseActionModel.requested_at >= since)
    return q.order_by(ResponseActionModel.requested_at.desc(), ResponseActionModel.id.desc()).limit(int(limit)).all()


def count_recent_actions(
    db: Session,
    *,
    agent_id: str,
    action_type: str,
    since,
    statuses: list[str],
) -> int:
    return (
        db.query(ResponseActionModel)
        .filter(
            ResponseActionModel.agent_id == agent_id,
            ResponseActionModel.action_type == action_type,
            ResponseActionModel.requested_at >= since,
            ResponseActionModel.status.in_(list(statuses)),
        )
        .count()
    )


def get_action(db: Session, *, action_id: int, for_update: bool = False) -> ResponseActionModel | None:
    q = db.query(ResponseActionModel).filter(ResponseActionModel.id == int(action_id))
    if for_update:
        q = q.with_for_update()
    return q.first()


def get_latest_result(
    db: Session,
    *,
    action_id: int,
) -> ResponseActionResultModel | None:
    return (
        db.query(ResponseActionResultModel)
        .filter(ResponseActionResultModel.response_action_id == int(action_id))
        .order_by(ResponseActionResultModel.id.desc())
        .first()
    )


def save_action(db: Session, row: ResponseActionModel) -> ResponseActionModel:
    db.add(row)
    return row


def flush(db: Session) -> None:
    db.flush()


def refresh(db: Session, row: ResponseActionModel) -> None:
    db.refresh(row)


def commit(db: Session) -> None:
    db.commit()


def get_agent_by_id(db: Session, row_id: int) -> AgentModel | None:
    return db.query(AgentModel).filter(AgentModel.id == int(row_id)).first()


def list_pending_actions_for_agent(
    db: Session,
    *,
    agent_id: str,
    limit: int = 100,
    for_update: bool = False,
) -> list[ResponseActionModel]:
    q = (
        db.query(ResponseActionModel)
        .filter(
            ResponseActionModel.agent_id == agent_id,
            ResponseActionModel.status.in_(["pending", "delivered"]),
        )
        .order_by(ResponseActionModel.requested_at.asc(), ResponseActionModel.id.asc())
        .limit(int(limit))
    )
    if for_update:
        q = q.with_for_update()
    return q.all()


def get_latest_result_for_agent(
    db: Session,
    *,
    action_id: int,
    agent_id: str,
) -> ResponseActionResultModel | None:
    return (
        db.query(ResponseActionResultModel)
        .filter(
            ResponseActionResultModel.response_action_id == int(action_id),
            ResponseActionResultModel.agent_id == agent_id,
        )
        .order_by(ResponseActionResultModel.id.desc())
        .first()
    )


def save_result(db: Session, row: ResponseActionResultModel) -> ResponseActionResultModel:
    db.add(row)
    return row
