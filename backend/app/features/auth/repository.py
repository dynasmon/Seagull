from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import Request
from sqlalchemy import update
from sqlalchemy.orm import Session

from app.core.audit import AuditActor, write_audit_event
from app.features.auth.models import (
    PortalLoginEventModel,
    PortalOneTimeTokenModel,
    PortalRefreshSessionModel,
    PortalUserModel,
)


def get_user_by_username(db: Session, username: str) -> PortalUserModel | None:
    return db.query(PortalUserModel).filter(PortalUserModel.username == username).first()


def get_user_by_id(db: Session, user_id: int) -> PortalUserModel | None:
    return db.get(PortalUserModel, int(user_id))


def save_user(db: Session, user: PortalUserModel) -> PortalUserModel:
    db.add(user)
    return user


def get_one_time_token_by_hash(db: Session, token_hash_value: str) -> PortalOneTimeTokenModel | None:
    return db.query(PortalOneTimeTokenModel).filter(PortalOneTimeTokenModel.token_hash == token_hash_value).first()


def create_one_time_token(
    db: Session,
    *,
    user_id: int,
    created_by_user_id: int | None,
    label: str | None,
    token_hash_value: str,
    created_at: datetime,
    expires_at: datetime,
) -> PortalOneTimeTokenModel:
    row = PortalOneTimeTokenModel(
        id=str(uuid.uuid4()),
        user_id=int(user_id),
        created_by_user_id=(int(created_by_user_id) if created_by_user_id is not None else None),
        label=(label or None),
        token_hash=token_hash_value,
        created_at=created_at,
        expires_at=expires_at,
        used_at=None,
        used_ip=None,
        used_user_agent=None,
        revoked_at=None,
    )
    db.add(row)
    return row


def consume_one_time_token(
    db: Session,
    *,
    token_id: str,
    used_at: datetime,
    used_ip: str,
    used_user_agent: str,
) -> bool:
    consumed = db.execute(
        update(PortalOneTimeTokenModel)
        .where(
            PortalOneTimeTokenModel.id == str(token_id),
            PortalOneTimeTokenModel.used_at.is_(None),
            PortalOneTimeTokenModel.revoked_at.is_(None),
        )
        .values(used_at=used_at, used_ip=used_ip, used_user_agent=used_user_agent)
        .returning(PortalOneTimeTokenModel.id),
        execution_options={"synchronize_session": False},
    ).scalar_one_or_none()
    return consumed is not None


def create_login_event(
    db: Session,
    *,
    user_id: int | None,
    username: str | None,
    method: str,
    succeeded: bool,
    ip: str | None,
    user_agent: str | None,
    created_at: datetime,
) -> PortalLoginEventModel:
    row = PortalLoginEventModel(
        id=str(uuid.uuid4()),
        user_id=(int(user_id) if user_id is not None else None),
        username=(username or None),
        method=method,
        succeeded=bool(succeeded),
        ip=(ip or None),
        user_agent=(user_agent or None),
        created_at=created_at,
    )
    db.add(row)
    return row


def get_refresh_session_by_token_hash(db: Session, token_hash_value: str) -> PortalRefreshSessionModel | None:
    return db.query(PortalRefreshSessionModel).filter(PortalRefreshSessionModel.token_hash == token_hash_value).first()


def create_refresh_session(
    db: Session,
    *,
    session_id: str,
    user_id: int,
    token_hash_value: str,
    created_at: datetime,
    expires_at: datetime,
    family_id: str,
    last_ip: str | None,
    last_user_agent: str | None,
) -> PortalRefreshSessionModel:
    row = PortalRefreshSessionModel(
        id=str(session_id),
        family_id=family_id,
        user_id=int(user_id),
        token_hash=token_hash_value,
        created_at=created_at,
        expires_at=expires_at,
        revoked_at=None,
        replaced_by_id=None,
        last_ip=(last_ip or None),
        last_user_agent=(last_user_agent or None),
    )
    db.add(row)
    return row


def revoke_refresh_session(
    db: Session,
    *,
    session_id: str,
    revoked_at: datetime,
    replaced_by_id: str | None = None,
    last_ip: str | None = None,
    last_user_agent: str | None = None,
) -> bool:
    values: dict[str, object] = {"revoked_at": revoked_at, "replaced_by_id": replaced_by_id}
    if last_ip is not None:
        values["last_ip"] = last_ip
    if last_user_agent is not None:
        values["last_user_agent"] = last_user_agent
    revoked = db.execute(
        update(PortalRefreshSessionModel)
        .where(
            PortalRefreshSessionModel.id == str(session_id),
            PortalRefreshSessionModel.revoked_at.is_(None),
        )
        .values(**values)
        .returning(PortalRefreshSessionModel.id),
        execution_options={"synchronize_session": False},
    ).scalar_one_or_none()
    return revoked is not None


def revoke_refresh_family(db: Session, *, family_id: str, revoked_at: datetime) -> int:
    return (
        db.query(PortalRefreshSessionModel)
        .filter(
            PortalRefreshSessionModel.family_id == family_id,
            PortalRefreshSessionModel.revoked_at.is_(None),
        )
        .update({"revoked_at": revoked_at})
    )


def revoke_active_refresh_sessions_by_user(db: Session, *, user_id: int, revoked_at: datetime) -> int:
    return (
        db.query(PortalRefreshSessionModel)
        .filter(
            PortalRefreshSessionModel.user_id == int(user_id),
            PortalRefreshSessionModel.revoked_at.is_(None),
        )
        .update({"revoked_at": revoked_at})
    )


def record_audit_event(
    db: Session,
    *,
    request: Request | None,
    actor: AuditActor,
    event_type: str,
    action: str,
    resource_type: str,
    resource_id: str | None,
    outcome: str,
    before: dict | None = None,
    after: dict | None = None,
    context: dict | None = None,
    reason: str | None = None,
    error: str | None = None,
) -> None:
    write_audit_event(
        db,
        request=request,
        actor=actor,
        event_type=event_type,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        before=(before or {}),
        after=(after or {}),
        context=(context or {}),
        reason=reason,
        error=error,
    )


def commit(db: Session) -> None:
    db.commit()


def rollback(db: Session) -> None:
    db.rollback()
