from __future__ import annotations

from typing import Any

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
    REC_TYPE_CHECK_AUTHORIZED_KEYS,
    REC_TYPE_COLLECT_TRIAGE_BUNDLE,
    REC_TYPE_HARDEN_SERVICE,
    REC_TYPE_INSPECT_SYSTEMD_UNITS,
    REC_TYPE_INVESTIGATE,
    REC_TYPE_INVESTIGATE_PERSISTENCE,
    REC_TYPE_ISOLATE,
    REC_TYPE_OPEN_INVESTIGATION,
    REC_TYPE_PATCH_VULNERABLE_PACKAGE,
    REC_TYPE_REFRESH_INVENTORY,
    REC_TYPE_REMEDIATE_ALERT,
    REC_TYPE_REVIEW_ATTACK_CHAIN,
    REC_TYPE_REVIEW_FIM,
    REC_TYPE_REVIEW_SUSPICIOUS_PROCESS,
    REC_TYPE_UPDATE_AGENT,
    REC_TYPE_VALIDATE_AGENT_HEALTH,
    REC_TYPE_VERIFY_SERVICE_EXPOSURE,
)
from app.features.exposure.domain.types import Recommendation

_MAX_RECOMMENDATIONS = 5

# (reason_code, priority, rec_type, title, detail, safety_level, requires_admin)
_RECOMMENDATION_MAP: list[tuple[str, int, str, str, str, str, bool]] = [
    (
        RC_ATTACK_CHAIN_PROGRESSION,
        10,
        REC_TYPE_ISOLATE,
        "Isolate asset — active attack chain detected",
        "An open attack chain case is progressing on this asset. Consider network isolation until investigation is complete.",
        "disruptive",
        True,
    ),
    (
        RC_ATTACK_CHAIN_PROGRESSION,
        11,
        REC_TYPE_COLLECT_TRIAGE_BUNDLE,
        "Collect forensic triage bundle",
        "Capture a forensic snapshot (memory, process list, network connections, auth logs) before the attacker can clean up.",
        "caution",
        True,
    ),
    (
        RC_ATTACK_CHAIN_PROGRESSION,
        12,
        REC_TYPE_REVIEW_ATTACK_CHAIN,
        "Review the full attack-chain timeline",
        "Open the attack-chain case to review progression stages, evidence quality, and suspect attribution.",
        "safe",
        False,
    ),
    (
        RC_LATERAL_MOVEMENT_SIGNAL,
        15,
        REC_TYPE_ISOLATE,
        "Contain lateral movement",
        "Lateral movement signals observed from or to this asset. Isolate and investigate to prevent spread.",
        "disruptive",
        True,
    ),
    (
        RC_LATERAL_MOVEMENT_SIGNAL,
        16,
        REC_TYPE_OPEN_INVESTIGATION,
        "Open investigation for lateral movement",
        "Create an investigation workspace to track the lateral movement scope and affected assets.",
        "safe",
        False,
    ),
    (
        RC_EXPLOITABILITY_SIGNAL,
        20,
        REC_TYPE_PATCH_VULNERABLE_PACKAGE,
        "Apply patches for exploitable vulnerabilities",
        "At least one known-exploitable vulnerability is present. Apply vendor patches immediately.",
        "caution",
        True,
    ),
    (
        RC_CRITICAL_CVE,
        25,
        REC_TYPE_PATCH_VULNERABLE_PACKAGE,
        "Remediate critical CVEs",
        "Critical CVEs are present on this asset. Prioritize patching to reduce exposure window.",
        "caution",
        True,
    ),
    (
        RC_VULNERABLE_PACKAGE,
        30,
        REC_TYPE_PATCH_VULNERABLE_PACKAGE,
        "Update vulnerable packages",
        "Vulnerable software packages were detected. Apply updates as part of routine patching.",
        "caution",
        True,
    ),
    (
        RC_ACTIVE_ALERT,
        35,
        REC_TYPE_REMEDIATE_ALERT,
        "Investigate and close active alerts",
        "Open security alerts require attention on this asset.",
        "safe",
        False,
    ),
    (
        RC_ACTIVE_ALERT,
        36,
        REC_TYPE_OPEN_INVESTIGATION,
        "Open investigation for active alerts",
        "Multiple alerts suggest an ongoing security incident. Open an investigation to track scope.",
        "safe",
        False,
    ),
    (
        RC_BRUTE_FORCE_ACTIVITY,
        40,
        REC_TYPE_CHECK_AUTHORIZED_KEYS,
        "Audit SSH authorized_keys files",
        "Brute-force activity was detected. Verify that no unauthorized SSH keys have been added.",
        "safe",
        False,
    ),
    (
        RC_BRUTE_FORCE_ACTIVITY,
        41,
        REC_TYPE_INVESTIGATE,
        "Investigate brute-force authentication attempts",
        "Repeated authentication failures indicate brute-force activity. Review access logs and strengthen authentication.",
        "safe",
        False,
    ),
    (
        RC_SUSPICIOUS_PROCESS,
        45,
        REC_TYPE_REVIEW_SUSPICIOUS_PROCESS,
        "Review suspicious process execution",
        "Processes with unusual characteristics were observed. Verify legitimacy and terminate if unauthorized.",
        "caution",
        True,
    ),
    (
        RC_SENSITIVE_FILE_CHANGE,
        50,
        REC_TYPE_REVIEW_FIM,
        "Review file integrity events",
        "Changes to sensitive files were detected. Validate the changes and check for unauthorized modifications.",
        "safe",
        False,
    ),
    (
        RC_PERSISTENCE_SIGNAL,
        55,
        REC_TYPE_INSPECT_SYSTEMD_UNITS,
        "Inspect systemd units for persistence",
        "Persistence artefacts were observed. Review systemd units, cron jobs, and startup scripts.",
        "safe",
        False,
    ),
    (
        RC_PERSISTENCE_SIGNAL,
        56,
        REC_TYPE_INVESTIGATE_PERSISTENCE,
        "Investigate persistence mechanisms",
        "A persistence mechanism was detected. Determine whether it was authorized and remove if not.",
        "caution",
        True,
    ),
    (
        RC_EXPOSED_SERVICE,
        60,
        REC_TYPE_VERIFY_SERVICE_EXPOSURE,
        "Verify network service exposure",
        "Network-accessible services are present. Confirm each is intentionally exposed and apply hardening.",
        "safe",
        False,
    ),
    (
        RC_EXPOSED_SERVICE,
        61,
        REC_TYPE_HARDEN_SERVICE,
        "Harden exposed services",
        "Apply security hardening to exposed services: restrict source IPs, enforce authentication, and disable unnecessary features.",
        "caution",
        True,
    ),
    (
        RC_STALE_AGENT,
        70,
        REC_TYPE_VALIDATE_AGENT_HEALTH,
        "Validate agent health",
        "No agent telemetry is available for this asset. Check agent connectivity and reinstall if needed.",
        "safe",
        True,
    ),
    (
        RC_STALE_AGENT,
        71,
        REC_TYPE_UPDATE_AGENT,
        "Reconnect or update the Seagull agent",
        "The agent has not reported in recently. Ensure the agent service is running and the credentials are valid.",
        "safe",
        True,
    ),
    (
        RC_STALE_INVENTORY,
        75,
        REC_TYPE_REFRESH_INVENTORY,
        "Refresh asset inventory",
        "Inventory data is stale. Trigger a rescan to obtain current asset state and package versions.",
        "safe",
        True,
    ),
]

_RC_TO_RECS: dict[str, list[tuple[int, str, str, str, str, bool]]] = {}
for _rc, _pri, _rt, _title, _detail, _safety, _admin in _RECOMMENDATION_MAP:
    _RC_TO_RECS.setdefault(_rc, []).append((_pri, _rt, _title, _detail, _safety, _admin))


def generate_recommendations(
    reason_codes: list[str],
    *,
    evidence_refs: list[dict[str, Any]] | None = None,
) -> list[Recommendation]:
    seen_types: set[str] = set()
    candidates: list[Recommendation] = []
    refs = evidence_refs or []

    for rc in reason_codes:
        for priority, rec_type, title, detail, safety_level, requires_admin in _RC_TO_RECS.get(rc, []):
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
                    safety_level=safety_level,
                    requires_admin=requires_admin,
                    related_evidence_refs=refs[:8],
                )
            )

    candidates.sort(key=lambda r: r.priority)
    return candidates[:_MAX_RECOMMENDATIONS]
