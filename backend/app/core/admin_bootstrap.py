from __future__ import annotations

from app.core.config import settings
from app.core.db import SessionLocal
from app.core.security import hash_password
from app.models.admin import AdminUserModel


def bootstrap_admin_user() -> None:
    """Create the initial admin user if none exists.

    Uses:
      - NETWATCH_BOOTSTRAP_ADMIN_USERNAME (default: admin)
      - NETWATCH_BOOTSTRAP_ADMIN_PASSWORD (required to bootstrap)

    This is intentionally idempotent.
    """

    password = (settings.NETWATCH_BOOTSTRAP_ADMIN_PASSWORD or "").strip()
    if not password:
        return

    username = (settings.NETWATCH_BOOTSTRAP_ADMIN_USERNAME or "admin").strip() or "admin"

    db = SessionLocal()
    try:
        any_user = db.query(AdminUserModel).first()
        if any_user:
            return

        u = AdminUserModel(
            username=username,
            password_hash=hash_password(password),
        )
        db.add(u)
        db.commit()
    finally:
        db.close()
