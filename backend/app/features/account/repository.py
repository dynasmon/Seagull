from __future__ import annotations

from datetime import datetime

from fastapi import Request
from sqlalchemy.orm import Session

from app.core.audit import AuditActor, write_audit_event
from app.features.auth.models import PortalRefreshSessionModel, PortalUserModel


def get_user_by_id(db: Session, user_id: int) -> PortalUserModel | None:
    return db.get(PortalUserModel, int(user_id))


def save_user(db: Session, user: PortalUserModel) -> PortalUserModel:
    db.add(user)
    return user


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
    )


def commit(db: Session) -> None:
    db.commit()


def rollback(db: Session) -> None:
    db.rollback()
