from __future__ import annotations

from datetime import datetime

from app.core.audit import audit_actor, write_audit_event
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.identity import canonicalize_username
from app.core.password_policy import validate_password_policy
from app.core.security import hash_password, verify_password
from app.models.correlation_rules import CorrelationRuleModel
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
        username = canonicalize_username(settings.NETWATCH_BOOTSTRAP_ADMIN_USERNAME or "admin") or "admin"
        password = (settings.NETWATCH_BOOTSTRAP_ADMIN_PASSWORD or "").strip()
        existing = db.query(PortalUserModel).count()

        # Existing admin user path: startup password sync is disabled by default.
        # If explicitly enabled as a break-glass operation, it requires both flags.
        current = db.query(PortalUserModel).filter(PortalUserModel.username == username).first()
        if current is not None:
            should_sync = bool(
                password
                and (
                    settings.NETWATCH_BOOTSTRAP_ADMIN_ALLOW_SYNC_ON_START
                    and (settings.NETWATCH_BOOTSTRAP_ADMIN_RESET_ON_START or settings.NETWATCH_BOOTSTRAP_ADMIN_SYNC_ON_START)
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
            raise RuntimeError(
                "No portal users found. Set NETWATCH_BOOTSTRAP_ADMIN_PASSWORD to bootstrap the admin user."
            )

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


def bootstrap_correlation_rules() -> None:
    """Seed a minimal set of correlation rules on a fresh install.

    Without at least one correlation rule, the Correlations → Findings screen will
    always be empty (because correlations are computed from portal-managed rules).

    This seed is intentionally conservative and idempotent:
    - Only inserts when there are zero correlation rules.
    - Uses wildcard patterns that match the baseline alert rule IDs.
    """

    db = SessionLocal()
    try:
        existing = db.query(CorrelationRuleModel).count()
        if existing and existing > 0:
            return

        now = datetime.utcnow()

        seeds = [
            CorrelationRuleModel(
                name="SSH brute force + DDoS impact (chain)",
                description=(
                    "Multi-step chain: SSH brute force activity followed by DDoS/DoS/L7 flood "
                    "against the same destination within the correlation window."
                ),
                enabled=True,
                severity="critical",
                strategy="chain",
                group_by="dst_ip",
                window_seconds=600,
                min_alerts=2,
                include_patterns=["ssh_bruteforce_*", "ddos_*", "dos_*", "l7_*"],
                exclude_patterns=[],
                stages=[
                    {"name": "Credential access", "patterns": ["ssh_bruteforce_*"], "min_count": 1},
                    {"name": "Impact", "patterns": ["ddos_*", "dos_*", "l7_*"], "min_count": 1},
                ],
                created_at=now,
                updated_at=now,
            ),
            CorrelationRuleModel(
                name="Recon + credential access (burst)",
                description="Burst of recon/scan alerts and SSH brute force from the same source within the window.",
                enabled=True,
                severity="high",
                strategy="burst",
                group_by="src_ip",
                window_seconds=300,
                min_alerts=2,
                include_patterns=["*scan*", "port_scan_*", "horizontal_scan_*", "ssh_bruteforce_*"],
                exclude_patterns=[],
                stages=[],
                created_at=now,
                updated_at=now,
            ),
            CorrelationRuleModel(
                name="Scan → brute force (chain)",
                description="Multi-step chain: scanning activity followed by SSH brute force from the same source.",
                enabled=True,
                severity="high",
                strategy="chain",
                group_by="src_ip",
                window_seconds=600,
                min_alerts=2,
                include_patterns=["*scan*", "port_scan_*", "horizontal_scan_*", "ssh_bruteforce_*"],
                exclude_patterns=[],
                stages=[
                    {"name": "Recon", "patterns": ["*scan*", "port_scan_*", "horizontal_scan_*"], "min_count": 1},
                    {"name": "Credential access", "patterns": ["ssh_bruteforce_*"], "min_count": 1},
                ],
                created_at=now,
                updated_at=now,
            ),
        ]

        db.add_all(seeds)
        db.commit()
    finally:
        db.close()
