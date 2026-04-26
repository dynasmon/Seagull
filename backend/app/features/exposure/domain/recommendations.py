from __future__ import annotations

from app.features.exposure.domain.constants import (
    RC_ACTIVE_ALERT,
    RC_ATTACK_CHAIN_PROGRESSION,
    RC_BRUTE_FORCE_ACTIVITY,
    RC_CRITICAL_CVE,
    RC_EXPLOITABILITY_SIGNAL,
    RC_EXPOSED_SERVICE,
    RC_LATERAL_MOVEMENT_SIGNAL,
    RC_PERSISTENCE_SIGNAL,
    RC_SENSITIVE_FILE_CHANGE,
    RC_STALE_AGENT,
    RC_STALE_INVENTORY,
    RC_SUSPICIOUS_PROCESS,
    RC_VULNERABLE_PACKAGE,
    REC_TYPE_CHECK_PERSISTENCE,
    REC_TYPE_HARDEN_SERVICE,
    REC_TYPE_INVESTIGATE,
    REC_TYPE_ISOLATE,
    REC_TYPE_PATCH,
    REC_TYPE_REFRESH_INVENTORY,
    REC_TYPE_REMEDIATE_ALERT,
    REC_TYPE_REVIEW_FIM,
    REC_TYPE_REVIEW_PROCESS,
    REC_TYPE_UPDATE_AGENT,
)
from app.features.exposure.domain.types import Recommendation


_MAX_RECOMMENDATIONS = 5

# (reason_code, priority, rec_type, title, detail)
_RECOMMENDATION_MAP: list[tuple[str, int, str, str, str]] = [
    (
        RC_ATTACK_CHAIN_PROGRESSION,
        10,
        REC_TYPE_ISOLATE,
        "Isolate asset — active attack chain detected",
        "An open attack chain case is progressing on this asset. Consider network isolation until investigation is complete.",
    ),
    (
        RC_LATERAL_MOVEMENT_SIGNAL,
        15,
        REC_TYPE_ISOLATE,
        "Contain lateral movement",
        "Lateral movement signals observed from or to this asset. Isolate and investigate to prevent spread.",
    ),
    (
        RC_EXPLOITABILITY_SIGNAL,
        20,
        REC_TYPE_PATCH,
        "Apply patches for exploitable vulnerabilities",
        "At least one known-exploitable vulnerability is present. Apply vendor patches immediately.",
    ),
    (
        RC_CRITICAL_CVE,
        25,
        REC_TYPE_PATCH,
        "Remediate critical CVEs",
        "Critical CVEs are present on this asset. Prioritize patching to reduce exposure window.",
    ),
    (
        RC_VULNERABLE_PACKAGE,
        30,
        REC_TYPE_PATCH,
        "Update vulnerable packages",
        "Vulnerable software packages were detected. Apply updates as part of routine patching.",
    ),
    (
        RC_ACTIVE_ALERT,
        35,
        REC_TYPE_REMEDIATE_ALERT,
        "Investigate and close active alerts",
        "Open security alerts require attention on this asset.",
    ),
    (
        RC_BRUTE_FORCE_ACTIVITY,
        40,
        REC_TYPE_INVESTIGATE,
        "Investigate brute-force authentication attempts",
        "Repeated authentication failures indicate brute-force activity. Review access logs and strengthen authentication.",
    ),
    (
        RC_SUSPICIOUS_PROCESS,
        45,
        REC_TYPE_REVIEW_PROCESS,
        "Review suspicious process execution",
        "Processes with unusual characteristics were observed. Verify legitimacy and terminate if unauthorized.",
    ),
    (
        RC_SENSITIVE_FILE_CHANGE,
        50,
        REC_TYPE_REVIEW_FIM,
        "Review file integrity events",
        "Changes to sensitive files were detected. Validate the changes and check for unauthorized modifications.",
    ),
    (
        RC_PERSISTENCE_SIGNAL,
        55,
        REC_TYPE_CHECK_PERSISTENCE,
        "Check for persistence mechanisms",
        "Persistence artefacts were observed. Review startup scripts, cron jobs, and systemd units.",
    ),
    (
        RC_EXPOSED_SERVICE,
        60,
        REC_TYPE_HARDEN_SERVICE,
        "Harden exposed services",
        "Network-accessible services are present. Restrict access to only required sources and apply hardening.",
    ),
    (
        RC_STALE_AGENT,
        70,
        REC_TYPE_UPDATE_AGENT,
        "Reconnect or update the Seagull agent",
        "No agent telemetry is available for this asset. Reinstall or reconnect the agent to restore visibility.",
    ),
    (
        RC_STALE_INVENTORY,
        75,
        REC_TYPE_REFRESH_INVENTORY,
        "Refresh asset inventory",
        "Inventory data is stale. Trigger a rescan to obtain current asset state.",
    ),
]

_RC_TO_RECS: dict[str, list[tuple[int, str, str, str]]] = {}
for _rc, _pri, _rt, _title, _detail in _RECOMMENDATION_MAP:
    _RC_TO_RECS.setdefault(_rc, []).append((_pri, _rt, _title, _detail))


def generate_recommendations(reason_codes: list[str]) -> list[Recommendation]:
    """Return up to _MAX_RECOMMENDATIONS prioritized Recommendation objects for the given reason codes."""
    seen_types: set[str] = set()
    candidates: list[Recommendation] = []

    for rc in reason_codes:
        for priority, rec_type, title, detail in _RC_TO_RECS.get(rc, []):
            if rec_type in seen_types:
                continue
            seen_types.add(rec_type)
            candidates.append(
                Recommendation(
                    rec_type=rec_type,
                    priority=priority,
                    title=title,
                    detail=detail,
                    reason_code=rc,
                )
            )

    candidates.sort(key=lambda r: r.priority)
    return candidates[:_MAX_RECOMMENDATIONS]
