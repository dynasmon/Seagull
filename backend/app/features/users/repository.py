from __future__ import annotations

from datetime import datetime

from fastapi import Request
from sqlalchemy.orm import Session

from app.core.audit import AuditActor, write_audit_event
from app.features.auth.models import PortalRefreshSessionModel, PortalUserModel


def list_users(db: Session) -> list[PortalUserModel]:
    return db.query(PortalUserModel).order_by(PortalUserModel.username.asc()).all()


def get_user(db: Session, user_id: int) -> PortalUserModel | None:
    return db.get(PortalUserModel, int(user_id))


def get_user_by_username(db: Session, username: str) -> PortalUserModel | None:
    return db.query(PortalUserModel).filter(PortalUserModel.username == username).first()


def create_user(
    db: Session,
    *,
    username: str,
    password_hash: str,
    role: str,
    is_active: bool,
    created_at: datetime,
) -> PortalUserModel:
    row = PortalUserModel(
        username=username,
        password_hash=password_hash,
        role=role,
        is_active=bool(is_active),
        token_version=1,
        created_at=created_at,
    )
    db.add(row)
    return row


def save_user(db: Session, row: PortalUserModel) -> PortalUserModel:
    db.add(row)
    return row


def deactivate_user(db: Session, row: PortalUserModel) -> PortalUserModel:
    row.is_active = False
    row.token_version = int(getattr(row, "token_version", 1) or 1) + 1
    db.add(row)
    return row


def count_active_admins_excluding(db: Session, user_id: int) -> int:
    return int(
        db.query(PortalUserModel)
        .filter(PortalUserModel.role == "admin", PortalUserModel.is_active.is_(True), PortalUserModel.id != int(user_id))
        .count()
        or 0
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


def flush(db: Session) -> None:
    db.flush()


def refresh(db: Session, row: PortalUserModel) -> None:
    db.refresh(row)


def commit(db: Session) -> None:
    db.commit()


def rollback(db: Session) -> None:
    db.rollback()


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
    )
