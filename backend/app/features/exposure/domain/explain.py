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
    RC_LOW_EVIDENCE_CONFIDENCE,
    RC_PERSISTENCE_SIGNAL,
    RC_SENSITIVE_FILE_CHANGE,
    RC_STALE_AGENT,
    RC_STALE_INVENTORY,
    RC_SUSPICIOUS_PROCESS,
    RC_VULNERABLE_PACKAGE,
)
from app.features.exposure.domain.types import ScoreBreakdown


_RC_HUMAN: dict[str, str] = {
    RC_EXPOSED_SERVICE: "Exposed network service detected",
    RC_VULNERABLE_PACKAGE: "Vulnerable software packages present",
    RC_CRITICAL_CVE: "Critical CVE found on this asset",
    RC_EXPLOITABILITY_SIGNAL: "Known exploitability signal for a vulnerability",
    RC_ACTIVE_ALERT: "Open security alert on this asset",
    RC_BRUTE_FORCE_ACTIVITY: "Brute-force authentication activity observed",
    RC_LATERAL_MOVEMENT_SIGNAL: "Lateral movement signal detected",
    RC_SUSPICIOUS_PROCESS: "Suspicious process execution observed",
    RC_SENSITIVE_FILE_CHANGE: "Sensitive file modified",
    RC_PERSISTENCE_SIGNAL: "Persistence mechanism detected",
    RC_ATTACK_CHAIN_PROGRESSION: "Active attack chain case in progress",
    RC_STALE_INVENTORY: "Asset inventory data is stale",
    RC_STALE_AGENT: "No agent telemetry available for this asset",
    RC_LOW_EVIDENCE_CONFIDENCE: "Limited evidence available — confidence is low",
}


def explain_score(
    *,
    risk_score: int,
    severity: str,
    confidence: int,
    breakdown: ScoreBreakdown,
    reason_codes: list[str],
) -> dict[str, Any]:
    """Return a structured, UI-friendly explanation of the risk score."""
    components = []
    bd = breakdown.to_dict()
    labels = {
        "exposure_score": "Exposure",
        "vulnerability_score": "Vulnerabilities",
        "active_threat_score": "Active Threats",
        "persistence_score": "Persistence",
        "attack_chain_score": "Attack Chain",
        "asset_criticality_score": "Asset Criticality",
    }
    for key, label in labels.items():
        val = bd.get(key, 0)
        if val > 0:
            components.append({"component": label, "score": val})

    penalty = bd.get("reliability_penalty", 0)
    if penalty > 0:
        components.append({"component": "Reliability Penalty", "score": -penalty})

    reasons = [
        {"code": rc, "description": _RC_HUMAN.get(rc, rc)}
        for rc in reason_codes
        if rc in _RC_HUMAN
    ]

    return {
        "risk_score": risk_score,
        "severity": severity,
        "confidence": confidence,
        "score_components": components,
        "reasons": reasons,
        "confidence_note": _confidence_note(confidence),
    }


def _confidence_note(confidence: int) -> str:
    if confidence >= 80:
        return "High confidence — based on direct, multi-source evidence."
    if confidence >= 60:
        return "Moderate confidence — supported by corroborating evidence."
    if confidence >= 40:
        return "Low confidence — limited or indirect evidence available."
    return "Very low confidence — score should be treated as indicative only."
