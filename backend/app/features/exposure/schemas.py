from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, validator


ExposureSeverity = Literal["informational", "low", "medium", "high", "critical", "unknown"]
ExposureStatus = Literal["active", "inactive", "stale", "unknown"]
ExposureFindingStatus = Literal["open", "acknowledged", "resolved", "suppressed"]
ExposureAssetSort = Literal["risk_desc", "risk_asc", "updated_desc", "last_seen_desc"]


class ExposureErrorOut(BaseModel):
    code: str
    message: str
    context: Dict[str, Any] = Field(default_factory=dict)


class EvidenceRefOut(BaseModel):
    source_type: str
    source_id: str
    observed_at: datetime
    title: str = ""
    summary: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ScoreBreakdownOut(BaseModel):
    exposure_score: int = 0
    vulnerability_score: int = 0
    active_threat_score: int = 0
    persistence_score: int = 0
    attack_chain_score: int = 0
    asset_criticality_score: int = 0
    reliability_penalty: int = 0


class ScoreExplanationComponentOut(BaseModel):
    component: str
    score: int


class ScoreReasonOut(BaseModel):
    code: str
    description: str


class ScoreExplanationOut(BaseModel):
    risk_score: int
    severity: ExposureSeverity
    confidence: int
    score_components: List[ScoreExplanationComponentOut] = Field(default_factory=list)
    reasons: List[ScoreReasonOut] = Field(default_factory=list)
    confidence_note: str = ""


class RecommendationOut(BaseModel):
    action: str
    title: str
    reason: str
    priority: int
    safety_level: str
    requires_admin: bool = False
    related_evidence_refs: List[EvidenceRefOut] = Field(default_factory=list)
    reason_code: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ExposureCountOut(BaseModel):
    key: str
    count: int


class ExposureAssetPostureOut(BaseModel):
    asset_key: str
    agent_id: Optional[str] = None
    asset_type: str
    display_name: str
    hostname: Optional[str] = None
    environment: Optional[str] = None
    criticality: str
    severity: ExposureSeverity
    risk_score: int
    confidence: int
    status: ExposureStatus
    first_seen_at: datetime
    last_seen_at: datetime
    updated_at: datetime
    score_breakdown: ScoreBreakdownOut
    reason_codes: List[str] = Field(default_factory=list)
    top_recommendations: List[RecommendationOut] = Field(default_factory=list)
    evidence_counts: Dict[str, int] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ExposureFindingOut(BaseModel):
    finding_key: str
    asset_key: str
    agent_id: Optional[str] = None
    finding_type: str
    severity: ExposureSeverity
    score_delta: int
    confidence: int
    title: str
    summary: str
    status: ExposureFindingStatus
    first_seen_at: datetime
    last_seen_at: datetime
    updated_at: datetime
    related_node_keys: List[str] = Field(default_factory=list)
    evidence_refs: List[EvidenceRefOut] = Field(default_factory=list)
    reason_codes: List[str] = Field(default_factory=list)
    recommendations: List[RecommendationOut] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ExposureGraphNodeOut(BaseModel):
    node_key: str
    node_type: str
    asset_key: Optional[str] = None
    agent_id: Optional[str] = None
    label: str
    severity: ExposureSeverity
    risk_score: int
    confidence: int
    first_seen_at: datetime
    last_seen_at: datetime
    updated_at: datetime
    properties: Dict[str, Any] = Field(default_factory=dict)
    source_refs: List[EvidenceRefOut] = Field(default_factory=list)


class ExposureGraphEdgeOut(BaseModel):
    edge_key: str
    source_node_key: str
    target_node_key: str
    edge_type: str
    asset_key: Optional[str] = None
    agent_id: Optional[str] = None
    weight: float
    confidence: int
    first_seen_at: datetime
    last_seen_at: datetime
    updated_at: datetime
    properties: Dict[str, Any] = Field(default_factory=dict)
    evidence_refs: List[EvidenceRefOut] = Field(default_factory=list)


class ExposureLegendItemOut(BaseModel):
    key: str
    label: str


class ExposureGraphLegendOut(BaseModel):
    node_types: List[ExposureLegendItemOut] = Field(default_factory=list)
    edge_types: List[ExposureLegendItemOut] = Field(default_factory=list)


class ExposureGraphHealthOut(BaseModel):
    depth_applied: int
    max_nodes_applied: int
    max_edges_applied: int
    node_count: int
    edge_count: int
    nodes_truncated: bool = False
    edges_truncated: bool = False
    posture_updated_at: Optional[datetime] = None
    stale_agent: bool = False
    stale_inventory: bool = False


class ExposureGraphOut(BaseModel):
    root_node_key: str
    recommended_focus_node_keys: List[str] = Field(default_factory=list)
    nodes: List[ExposureGraphNodeOut] = Field(default_factory=list)
    edges: List[ExposureGraphEdgeOut] = Field(default_factory=list)
    legend: ExposureGraphLegendOut
    graph_health: ExposureGraphHealthOut


class ExposureLinkedAttackChainStepOut(BaseModel):
    id: int
    case_id: int
    stage: str
    label: str
    score_delta: int
    timestamp: datetime
    event_id: Optional[int] = None
    event_type: Optional[str] = None


class ExposureLinkedAttackChainCaseOut(BaseModel):
    id: int
    status: str
    score: int
    max_stage: str
    step_count: int
    suspect_ip: Optional[str] = None
    first_seen_at: datetime
    last_seen_at: datetime
    recent_steps: List[ExposureLinkedAttackChainStepOut] = Field(default_factory=list)


class ExposureLinkedAlertOut(BaseModel):
    id: int
    created_at: datetime
    rule_id: str
    severity: ExposureSeverity
    confidence: int
    description: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ExposureLinkedVulnerabilityOut(BaseModel):
    id: int
    fingerprint: str
    cve: Optional[str] = None
    title: str
    severity: ExposureSeverity
    severity_rank: int
    confidence: int
    cvss: Optional[str] = None
    location: Optional[str] = None
    description: str = ""
    remediation: str = ""
    observation_state: str
    operator_disposition: str
    first_seen_at: datetime
    last_seen_at: datetime


class ExposureLinkedInvestigationOut(BaseModel):
    id: int
    workspace_key: str
    title: str
    status: str
    severity: str
    priority: str
    assignee: Optional[str] = None
    updated_at: datetime
    linked_attack_chain_case_id: Optional[int] = None
    summary: Dict[str, Any] = Field(default_factory=dict)


class ExposureLinkedResponseActionOut(BaseModel):
    id: int
    action_type: str
    status: str
    requested_by: str
    requested_at: datetime
    expires_at: Optional[datetime] = None
    delivered_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    cancelled_at: Optional[datetime] = None
    cancelled_by: Optional[str] = None
    last_error: Optional[str] = None
    latest_result_status: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)


class ExposureScoreHistoryPointOut(BaseModel):
    bucket_ts: datetime
    risk_score: int
    severity: ExposureSeverity
    confidence: int
    score_breakdown: ScoreBreakdownOut


class ExposureAssetDetailOut(BaseModel):
    posture: ExposureAssetPostureOut
    score_breakdown: ScoreBreakdownOut
    score_explanation: ScoreExplanationOut
    reason_codes: List[str] = Field(default_factory=list)
    top_findings: List[ExposureFindingOut] = Field(default_factory=list)
    top_recommendations: List[RecommendationOut] = Field(default_factory=list)
    linked_attack_chain_cases: List[ExposureLinkedAttackChainCaseOut] = Field(default_factory=list)
    linked_alerts: List[ExposureLinkedAlertOut] = Field(default_factory=list)
    linked_vulnerabilities: List[ExposureLinkedVulnerabilityOut] = Field(default_factory=list)
    linked_investigations: List[ExposureLinkedInvestigationOut] = Field(default_factory=list)
    linked_response_actions: List[ExposureLinkedResponseActionOut] = Field(default_factory=list)
    recent_score_history: List[ExposureScoreHistoryPointOut] = Field(default_factory=list)
    updated_at: datetime


class ExposureAttackPathStageOut(BaseModel):
    stage: str
    label: str
    source: str
    confidence: int


class ExposureAttackPathOut(BaseModel):
    path_key: str
    asset_key: str
    severity: ExposureSeverity
    risk_score: int
    confidence: int
    title: str
    summary: str
    stages: List[ExposureAttackPathStageOut] = Field(default_factory=list)
    nodes: List[ExposureGraphNodeOut] = Field(default_factory=list)
    edges: List[ExposureGraphEdgeOut] = Field(default_factory=list)
    evidence_refs: List[EvidenceRefOut] = Field(default_factory=list)
    recommendations: List[RecommendationOut] = Field(default_factory=list)


class ExposureSummaryOut(BaseModel):
    total_assets: int
    critical_assets: int
    high_assets: int
    medium_assets: int
    low_assets: int
    informational_assets: int
    avg_risk_score: float
    max_risk_score: int
    active_findings: int
    active_attack_paths: int
    stale_agents: int
    stale_inventory_assets: int
    top_reason_codes: List[ExposureCountOut] = Field(default_factory=list)
    top_recommendations: List[ExposureCountOut] = Field(default_factory=list)
    updated_at: Optional[datetime] = None


class ExposureRecalculateOut(BaseModel):
    accepted: bool = True
    mode: str
    requested_at: datetime
    replay_from_event_id: Optional[int] = None


class ExposureInvestigationResultOut(BaseModel):
    created: bool
    workspace_id: int
    workspace_key: str
    title: str
    severity: str
    priority: str
    bookmark_count_added: int = 0


class ExposureTriageResponseActionOut(BaseModel):
    action_id: int
    action_type: str
    agent_id: str
    status: str
    requested_at: datetime
    expires_at: Optional[datetime] = None


class ExposureAssetsQuery(BaseModel):
    page_size: int = Field(default=50, ge=1, le=200)
    cursor: Optional[str] = None
    q: Optional[str] = Field(default=None, max_length=128)
    severity: Optional[str] = None
    min_score: Optional[int] = Field(default=None, ge=0, le=100)
    agent_id: Optional[str] = Field(default=None, min_length=1, max_length=64)
    status: Optional[str] = None
    reason_code: Optional[str] = Field(default=None, max_length=64)
    has_attack_chain: Optional[bool] = None
    has_critical_vuln: Optional[bool] = None
    has_persistence_signal: Optional[bool] = None
    sort: ExposureAssetSort = "risk_desc"

    @validator("severity", "status", "reason_code", pre=True)
    def _normalize_lower(cls, value: Any) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip().lower()
        return text or None

    @validator("q", "agent_id", pre=True)
    def _normalize_optional_text(cls, value: Any) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip()
        return text or None


class ExposurePathsQuery(BaseModel):
    page_size: int = Field(default=25, ge=1, le=100)
    cursor: Optional[str] = None
    severity: Optional[str] = None
    agent_id: Optional[str] = Field(default=None, min_length=1, max_length=64)
    min_score: Optional[int] = Field(default=None, ge=0, le=100)
    reason_code: Optional[str] = Field(default=None, max_length=64)

    @validator("severity", "reason_code", pre=True)
    def _normalize_lower(cls, value: Any) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip().lower()
        return text or None

    @validator("agent_id", pre=True)
    def _normalize_agent(cls, value: Any) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip()
        return text or None


class ExposureFindingsQuery(BaseModel):
    page_size: int = Field(default=50, ge=1, le=200)
    cursor: Optional[str] = None
    asset_key: Optional[str] = Field(default=None, max_length=256)
    agent_id: Optional[str] = Field(default=None, min_length=1, max_length=64)
    finding_type: Optional[str] = Field(default=None, max_length=32)
    severity: Optional[str] = None
    status: Optional[str] = None
    q: Optional[str] = Field(default=None, max_length=256)

    @validator("severity", "status", "finding_type", pre=True)
    def _normalize_lower(cls, value: Any) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip().lower()
        return text or None

    @validator("asset_key", "agent_id", "q", pre=True)
    def _normalize_text(cls, value: Any) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip()
        return text or None


class ExposureGraphQuery(BaseModel):
    depth: int = Field(default=2, ge=1, le=4)
    node_types: List[str] = Field(default_factory=list)
    edge_types: List[str] = Field(default_factory=list)
    min_confidence: int = Field(default=1, ge=1, le=99)
    max_nodes: int = Field(default=80, ge=1, le=1000)
    max_edges: int = Field(default=120, ge=1, le=1000)
    include_resolved: bool = False

    @validator("node_types", "edge_types", pre=True)
    def _normalize_list(cls, value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, str):
            raw_items = [part.strip() for part in value.split(",")]
        elif isinstance(value, list):
            raw_items = [str(item or "").strip() for item in value]
        else:
            return []
        out: list[str] = []
        seen: set[str] = set()
        for raw in raw_items:
            item = raw.lower()
            if not item or item in seen:
                continue
            seen.add(item)
            out.append(item)
        return out
