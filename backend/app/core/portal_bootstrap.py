from __future__ import annotations

from datetime import datetime

from app.core.config import settings
from app.core.db import SessionLocal
from app.core.security import hash_password
from app.models.portal_users import PortalUserModel


def _is_prod() -> bool:
    return settings.NETWATCH_ENV in {"prod", "production"}


def assert_portal_secrets() -> None:
    secret = (settings.NETWATCH_JWT_SECRET or "").strip()
    if len(secret) < 32:
        raise RuntimeError(
            "NETWATCH_JWT_SECRET is required and must be at least 32 characters."
        )


def bootstrap_portal_admin() -> None:
    """Create the first admin user on a fresh DB.

    For security, we do not auto-generate default credentials.
    Set NETWATCH_BOOTSTRAP_ADMIN_PASSWORD on the first run.
    """

    assert_portal_secrets()

    db = SessionLocal()
    try:
        existing = db.query(PortalUserModel).count()
        if existing and existing > 0:
            return

        username = (settings.NETWATCH_BOOTSTRAP_ADMIN_USERNAME or "admin").strip() or "admin"
        password = (settings.NETWATCH_BOOTSTRAP_ADMIN_PASSWORD or "").strip()
        if not password:
            raise RuntimeError(
                "No portal users found. Set NETWATCH_BOOTSTRAP_ADMIN_PASSWORD to bootstrap the admin user."
            )

        if len(password) < 12:
            raise RuntimeError("Bootstrap admin password must be at least 12 characters.")

        user = PortalUserModel(
            username=username,
            password_hash=hash_password(password),
            role="admin",
            is_active=True,
            created_at=datetime.utcnow(),
        )
        db.add(user)
        db.commit()
    finally:
        db.close()
