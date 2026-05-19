from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.features.alerts.models import AlertModel
from app.features.alerts.service import persist_generated_alerts
from app.features.ueba import lifecycle
from app.features.ueba.models import UebaFindingModel
from app.shared.taxonomy.catalog import technique_name


def persist_alert_for_finding(
    db: Session,
    *,
    finding: UebaFindingModel,
    evidence_specs: list[dict[str, Any]],
) -> AlertModel:
    alert = AlertModel(
        rule_id=str(finding.detector_id),
        severity=str(finding.severity),
        src_ip=_finding_src_ip(finding, evidence_specs),
        dst_ip=None,
        dst_port=None,
        mitre_tactic=finding.mitre_tactic,
        mitre_technique_id=finding.mitre_technique_id,
        mitre_technique=(finding.mitre_technique or technique_name(finding.mitre_technique_id)),
        confidence=int(finding.confidence or 0),
        description=str(finding.summary or "UEBA behavioral anomaly")[:255],
        detector_type="ueba",
        rule_version=int(finding.detector_version or 1),
        details={
            "type": "ueba",
            "finding_id": int(finding.id),
            "detector_id": str(finding.detector_id),
            "entity_type": str(finding.entity_type),
            "entity_value": str(finding.entity_value),
            "metric_name": str(finding.metric_name),
            "bucket_key": str(finding.bucket_key),
            "expected_value": finding.expected_value,
            "observed_value": finding.observed_value,
            "deviation_score": finding.deviation_score,
            "risk_score": int(finding.risk_score or 0),
            "reason_codes": list(finding.reason_codes or []),
            "mitre": {
                "tactic": finding.mitre_tactic,
                "technique_id": finding.mitre_technique_id,
                "technique": finding.mitre_technique or technique_name(finding.mitre_technique_id),
                "confidence": int(finding.confidence or 0),
            },
            "evidence": [_alert_evidence_payload(spec) for spec in evidence_specs[:3]],
        },
        risk_score=int(finding.risk_score or 0),
    )
    persisted = persist_generated_alerts(db, [alert])[0]
    lifecycle.link_alert_to_finding(db, finding=finding, alert_id=int(persisted.id))
    return persisted


def _finding_src_ip(finding: UebaFindingModel, evidence_specs: list[dict[str, Any]]) -> str | None:
    if finding.entity_type in {"src_ip", "ip"}:
        return str(finding.entity_value)
    for spec in evidence_specs:
        raw = spec.get("raw_context")
        if isinstance(raw, dict) and raw.get("src_ip"):
            return str(raw["src_ip"])
    return None


def _alert_evidence_payload(spec: dict[str, Any]) -> dict[str, Any]:
    raw_context = spec.get("raw_context")
    return {
        "event_id": spec.get("event_id"),
        "evidence_type": spec.get("evidence_type"),
        "evidence_role": spec.get("evidence_role"),
        "entity_type": spec.get("entity_type"),
        "entity_value": spec.get("entity_value"),
        "matched_field": spec.get("matched_field"),
        "matched_value": spec.get("matched_value"),
        "summary": spec.get("summary"),
        "raw_context": dict(raw_context or {}) if isinstance(raw_context, dict) else {},
    }
