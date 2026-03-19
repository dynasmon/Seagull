from __future__ import annotations

import argparse
from datetime import datetime

from app.core.config import settings
from app.core.db import SessionLocal
from app.core.security import hash_password, verify_password
from app.models.portal_users import PortalUserModel


def admin_reset() -> int:
    username = (settings.NETWATCH_BOOTSTRAP_ADMIN_USERNAME or "admin").strip() or "admin"
    password = (settings.NETWATCH_BOOTSTRAP_ADMIN_PASSWORD or "").strip()

    if len(password) < 12:
        print("error: NETWATCH_BOOTSTRAP_ADMIN_PASSWORD must be at least 12 characters")
        return 2

    db = SessionLocal()
    try:
        row = db.query(PortalUserModel).filter(PortalUserModel.username == username).first()
        created = False
        if row is None:
            row = PortalUserModel(
                username=username,
                role="admin",
                is_active=True,
                created_at=datetime.utcnow(),
                password_hash=hash_password(password),
                failed_login_count=0,
            )
            created = True
        else:
            row.password_hash = hash_password(password)
            row.role = "admin"
            row.is_active = True
            row.failed_login_count = 0

        db.add(row)
        db.commit()
        db.refresh(row)
        ok = bool(verify_password(password, row.password_hash))
        print(f"admin_reset_ok username={row.username} created={created} verify={ok}")
        return 0 if ok else 3
    finally:
        db.close()


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("admin-reset", help="Reset/sync bootstrap admin password into database")
    args = parser.parse_args()

    if args.command == "admin-reset":
        return admin_reset()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
