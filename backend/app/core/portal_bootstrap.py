from __future__ import annotations

from datetime import datetime

from app.core.config import settings
from app.core.db import SessionLocal
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
        username = (settings.NETWATCH_BOOTSTRAP_ADMIN_USERNAME or "admin").strip() or "admin"
        password = (settings.NETWATCH_BOOTSTRAP_ADMIN_PASSWORD or "").strip()
        existing = db.query(PortalUserModel).count()

        # Existing admin user path: in dev, allow controlled password sync from bootstrap env.
        current = db.query(PortalUserModel).filter(PortalUserModel.username == username).first()
        if current is not None:
            should_sync = bool(settings.NETWATCH_BOOTSTRAP_ADMIN_RESET_ON_START and password)
            if should_sync and len(password) >= 12 and not verify_password(password, current.password_hash):
                current.password_hash = hash_password(password)
                current.is_active = True
                current.role = "admin"
                db.add(current)
                db.commit()
            return

        if existing and existing > 0:
            return

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
