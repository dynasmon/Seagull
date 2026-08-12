from __future__ import annotations

from datetime import datetime

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.features.agents.models import (
    AgentBootstrapTokenModel,
    AgentCertificateModel,
    AgentCredentialModel,
    AgentModel,
)


def get_agent_by_agent_id(db: Session, agent_id: str) -> AgentModel | None:
    return db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()


def get_agent_by_id(db: Session, row_id: int) -> AgentModel | None:
    return db.query(AgentModel).filter(AgentModel.id == int(row_id)).first()


def list_agents(db: Session) -> list[AgentModel]:
    return db.query(AgentModel).order_by(AgentModel.agent_id.asc()).all()


def save_agent(db: Session, row: AgentModel) -> AgentModel:
    db.add(row)
    return row


def list_active_bootstrap_tokens_for_update(
    db: Session,
    agent_id: str,
    *,
    token_type: str | None = None,
) -> list[AgentBootstrapTokenModel]:
    q = (
        db.query(AgentBootstrapTokenModel)
        .filter(
            AgentBootstrapTokenModel.agent_id == agent_id,
            AgentBootstrapTokenModel.revoked_at.is_(None),
        )
        .order_by(AgentBootstrapTokenModel.created_at.desc(), AgentBootstrapTokenModel.id.desc())
        .with_for_update()
    )
    if token_type:
        q = q.filter(AgentBootstrapTokenModel.token_type == token_type)
    return q.all()


def list_bootstrap_tokens(
    db: Session,
    agent_id: str,
    *,
    for_update: bool = False,
) -> list[AgentBootstrapTokenModel]:
    q = (
        db.query(AgentBootstrapTokenModel)
        .filter(AgentBootstrapTokenModel.agent_id == agent_id)
        .order_by(AgentBootstrapTokenModel.created_at.desc(), AgentBootstrapTokenModel.id.desc())
    )
    if for_update:
        q = q.with_for_update()
    return q.all()


def list_bootstrap_tokens_for_update(
    db: Session,
    agent_id: str,
) -> list[AgentBootstrapTokenModel]:
    return list_bootstrap_tokens(db, agent_id, for_update=True)


def list_active_renewal_tokens_for_update(db: Session, agent_id: str) -> list[AgentBootstrapTokenModel]:
    return list_active_bootstrap_tokens_for_update(db, agent_id, token_type="renewal")


def save_bootstrap_token(db: Session, row: AgentBootstrapTokenModel) -> AgentBootstrapTokenModel:
    db.add(row)
    return row


def list_active_credentials(db: Session, agent_id: str) -> list[AgentCredentialModel]:
    now = datetime.utcnow()
    return (
        db.query(AgentCredentialModel)
        .filter(
            AgentCredentialModel.agent_id == agent_id,
            or_(AgentCredentialModel.revoked_at.is_(None), AgentCredentialModel.revoked_at > now),
        )
        .all()
    )


def get_credential_by_id(db: Session, credential_id: int) -> AgentCredentialModel | None:
    return db.get(AgentCredentialModel, int(credential_id))


def save_credential(db: Session, row: AgentCredentialModel) -> AgentCredentialModel:
    db.add(row)
    return row


def save_certificate(db: Session, row: AgentCertificateModel) -> AgentCertificateModel:
    db.add(row)
    return row


def flush(db: Session) -> None:
    db.flush()


def refresh(db: Session, row) -> None:
    db.refresh(row)


def commit(db: Session) -> None:
    db.commit()
