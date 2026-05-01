from __future__ import annotations

from datetime import datetime

from app.core.db import SessionLocal
from app.features.correlations.models import CorrelationRuleModel


def bootstrap_correlation_rules() -> None:
    """Seed a minimal set of correlation rules on a fresh install."""

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
