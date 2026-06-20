from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AlertDraft:
    rule_id: str
    severity: str
    risk_score: int
    src_ip: str | None
    dst_ip: str | None
    dst_port: int | None
    mitre_tactic: str | None
    mitre_technique_id: str | None
    mitre_technique: str | None
    confidence: int
    description: str
    details: dict[str, Any]
    detector_type: str
    rule_version: int
    rule_hash: str | None
