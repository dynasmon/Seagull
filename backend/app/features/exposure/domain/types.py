from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class EvidenceRef:
    """Structured pointer to a piece of source evidence."""

    source_type: str
    source_id: str
    observed_at: datetime
    title: str
    summary: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_type": self.source_type,
            "source_id": str(self.source_id),
            "observed_at": self.observed_at.isoformat(),
            "title": self.title,
            "summary": self.summary,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class ScoreBreakdown:
    """Per-component risk score decomposition for a single asset."""

    exposure_score: int
    vulnerability_score: int
    active_threat_score: int
    persistence_score: int
    attack_chain_score: int
    asset_criticality_score: int
    reliability_penalty: int

    def to_dict(self) -> dict[str, int]:
        return {
            "exposure_score": self.exposure_score,
            "vulnerability_score": self.vulnerability_score,
            "active_threat_score": self.active_threat_score,
            "persistence_score": self.persistence_score,
            "attack_chain_score": self.attack_chain_score,
            "asset_criticality_score": self.asset_criticality_score,
            "reliability_penalty": self.reliability_penalty,
        }


@dataclass
class FindingInput:
    """Normalized finding for ingestion into the exposure engine."""

    finding_type: str
    asset_key: str
    agent_id: str | None
    severity: str
    score_delta: int
    confidence: int
    title: str
    summary: str
    status: str
    finding_key: str
    first_seen_at: datetime
    last_seen_at: datetime
    related_node_keys: list[str] = field(default_factory=list)
    evidence_refs: list[EvidenceRef] = field(default_factory=list)
    reason_codes: list[str] = field(default_factory=list)
    recommendations: list[dict[str, Any]] = field(default_factory=list)
    extra_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class NodeInput:
    """Normalized graph node for upsert."""

    node_key: str
    node_type: str
    label: str
    severity: str
    risk_score: int
    confidence: int
    asset_key: str | None
    agent_id: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    properties: dict[str, Any] = field(default_factory=dict)
    source_refs: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class EdgeInput:
    """Normalized graph edge for upsert."""

    edge_key: str
    source_node_key: str
    target_node_key: str
    edge_type: str
    weight: float
    confidence: int
    asset_key: str | None
    agent_id: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    properties: dict[str, Any] = field(default_factory=dict)
    evidence_refs: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class PostureInput:
    """Full risk posture for a single asset, ready for upsert."""

    asset_key: str
    agent_id: str | None
    asset_type: str
    display_name: str
    hostname: str | None
    environment: str | None
    criticality: str
    risk_score: int
    severity: str
    confidence: int
    breakdown: ScoreBreakdown
    status: str
    first_seen_at: datetime
    last_seen_at: datetime
    reason_codes: list[str] = field(default_factory=list)
    top_recommendations: list[dict[str, Any]] = field(default_factory=list)
    evidence_counts: dict[str, int] = field(default_factory=dict)
    extra_data: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Recommendation:
    """A single actionable recommendation surfaced for an asset."""

    rec_type: str
    priority: int
    title: str
    detail: str
    reason_code: str
    # safety_level: "safe" | "caution" | "disruptive"
    safety_level: str = "safe"
    requires_admin: bool = False
    related_evidence_refs: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.rec_type,
            "reason": self.detail,
            "rec_type": self.rec_type,
            "priority": self.priority,
            "title": self.title,
            "detail": self.detail,
            "reason_code": self.reason_code,
            "safety_level": self.safety_level,
            "requires_admin": self.requires_admin,
            "related_evidence_refs": self.related_evidence_refs,
            "metadata": self.metadata,
        }
