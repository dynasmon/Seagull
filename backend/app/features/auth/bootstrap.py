from __future__ import annotations

from datetime import datetime

from app.core.audit import audit_actor, write_audit_event
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.security import hash_password, verify_password
from app.core.security.identity import canonicalize_username
from app.core.security.password_policy import validate_password_policy
from app.features.auth.models import PortalUserModel


def assert_portal_secrets() -> None:
    secret = (settings.SEAGULL_JWT_SECRET or "").strip()
    if len(secret) < 32:
        raise RuntimeError("SEAGULL_JWT_SECRET is required and must be at least 32 characters.")


def bootstrap_portal_admin() -> None:

    assert_portal_secrets()

    db = SessionLocal()
    try:
        username = canonicalize_username(settings.SEAGULL_BOOTSTRAP_ADMIN_USERNAME or "admin") or "admin"
        password = (settings.SEAGULL_BOOTSTRAP_ADMIN_PASSWORD or "").strip()
        existing = db.query(PortalUserModel).count()

        current = db.query(PortalUserModel).filter(PortalUserModel.username == username).first()
        if current is not None:
            should_sync = bool(
                password
                and (
                    settings.SEAGULL_BOOTSTRAP_ADMIN_ALLOW_SYNC_ON_START
                    and (settings.SEAGULL_BOOTSTRAP_ADMIN_RESET_ON_START or settings.SEAGULL_BOOTSTRAP_ADMIN_SYNC_ON_START)
                )
            )
            if should_sync and not verify_password(password, current.password_hash):
                msg = validate_password_policy(password, username=current.username)
                if msg:
                    raise RuntimeError(f"Bootstrap admin password rejected: {msg}")
                before = {"id": current.id, "username": current.username, "role": current.role, "is_active": bool(current.is_active)}
                current.password_hash = hash_password(password)
                current.is_active = True
                current.role = "admin"
                current.token_version = int(getattr(current, "token_version", 1) or 1) + 1
                db.add(current)
                write_audit_event(
                    db,
                    request=None,
                    actor=audit_actor(None, "system"),
                    event_type="admin_action",
                    action="bootstrap.admin_password_sync",
                    resource_type="user",
                    resource_id=str(current.id),
                    outcome="success",
                    before=before,
                    after={"id": current.id, "username": current.username, "role": current.role, "is_active": bool(current.is_active)},
                    context={"bootstrap_sync": True},
                )
                db.commit()
            return

        if existing and existing > 0:
            return

        if not password:
            raise RuntimeError("No portal users found. Set SEAGULL_BOOTSTRAP_ADMIN_PASSWORD to bootstrap the admin user.")

        msg = validate_password_policy(password, username=username)
        if msg:
            raise RuntimeError(f"Bootstrap admin password rejected: {msg}")

        user = PortalUserModel(
            username=username,
            password_hash=hash_password(password),
            role="admin",
            is_active=True,
            token_version=1,
            created_at=datetime.utcnow(),
        )
        db.add(user)
        db.flush()
        write_audit_event(
            db,
            request=None,
            actor=audit_actor(None, "system"),
            event_type="admin_action",
            action="bootstrap.admin_create",
            resource_type="user",
            resource_id=str(user.id),
            outcome="success",
            before={},
            after={"id": user.id, "username": user.username, "role": user.role, "is_active": bool(user.is_active)},
            context={"bootstrap": True},
        )
        db.commit()
    finally:
        db.close()
