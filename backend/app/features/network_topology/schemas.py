from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, validator

TopologySeverity = str
TopologyNodeType = str
TopologyEdgeType = str


class TopologyNodeOut(BaseModel):
    node_key: str
    node_type: str
    agent_id: Optional[str] = None
    label: str
    ip: Optional[str] = None
    cidr: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    severity: str
    risk_score: int
    confidence: int
    is_stale: bool
    event_count: int
    alert_count: int
    observation_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    updated_at: datetime
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TopologyEdgeOut(BaseModel):
    edge_key: str
    source_node_key: str
    target_node_key: str
    edge_type: str
    agent_id: Optional[str] = None
    weight: float
    confidence: int
    severity: str
    port: Optional[int] = None
    protocol: Optional[str] = None
    event_count: int
    alert_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    updated_at: datetime
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TopologyObservationOut(BaseModel):
    id: int
    node_key: str
    edge_key: Optional[str] = None
    agent_id: Optional[str] = None
    source_type: str
    source_id: Optional[str] = None
    observed_at: datetime
    summary: str
    confidence: int = 50
    raw_context: Dict[str, Any] = Field(default_factory=dict)


class TopologyEvidencePageMetaOut(BaseModel):
    limit: int
    total: int
    omitted: int = 0


class TopologyEvidenceSourceOut(BaseModel):
    source_type: str
    count: int
    latest_observed_at: Optional[datetime] = None


class TopologyRelatedAlertOut(BaseModel):
    id: int
    created_at: datetime
    rule_id: str
    severity: str
    status: str
    confidence: int
    description: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None


class TopologyRelatedFlowOut(BaseModel):
    id: int
    timestamp: datetime
    agent_id: str
    event_type: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    bytes: Optional[int] = None
    app_proto: Optional[str] = None


class TopologyRelatedExposureFindingOut(BaseModel):
    finding_key: str
    asset_key: str
    agent_id: Optional[str] = None
    finding_type: str
    severity: str
    status: str
    confidence: int
    title: str
    summary: str
    last_seen_at: datetime


class TopologyRelatedAttackChainCaseOut(BaseModel):
    id: int
    agent_id: str
    suspect_ip: Optional[str] = None
    status: str
    score: int
    max_stage: str
    step_count: int
    first_seen_at: datetime
    last_seen_at: datetime


class TopologyGraphHealthOut(BaseModel):
    max_nodes_applied: int
    max_edges_applied: int
    node_count: int
    edge_count: int
    nodes_truncated: bool = False
    edges_truncated: bool = False
    last_projected_at: Optional[datetime] = None
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    projected_at: Optional[datetime] = None
    data_window: Dict[str, Any] = Field(default_factory=dict)
    freshness_seconds: Optional[int] = None
    stale: bool = True
    source_coverage: Dict[str, Any] = Field(default_factory=dict)
    truncation: Dict[str, Any] = Field(default_factory=dict)


class TopologyGroupOut(BaseModel):
    group_key: str
    group_type: str
    label: str
    node_count: int = 0
    edge_count: int = 0
    alert_count: int = 0
    highest_severity: str = "unknown"
    risk_score: int = 0
    confidence: int = 0
    is_stale: bool = False
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    child_node_keys: List[str] = Field(default_factory=list)
    child_node_keys_truncated: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TopologyGroupEdgeOut(BaseModel):
    edge_key: str
    source_group_key: str
    target_group_key: str
    edge_type: str = "observed_flow"
    weight: float = 1.0
    alert_count: int = 0
    confidence: int = 0
    highest_severity: str = "unknown"
    edge_count: int = 1
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TopologyFacetsOut(BaseModel):
    node_types: Dict[str, int] = Field(default_factory=dict)
    edge_types: Dict[str, int] = Field(default_factory=dict)
    severities: Dict[str, int] = Field(default_factory=dict)
    ip_scopes: Dict[str, int] = Field(default_factory=dict)
    agents: Dict[str, int] = Field(default_factory=dict)
    group_count: int = 0
    has_alerts_count: int = 0
    has_exposure_count: int = 0
    stale_count: int = 0
    active_count: int = 0
    total_nodes: int = 0
    total_edges: int = 0


class TopologyGroupDetailOut(BaseModel):
    group_key: str
    group_type: str
    label: str
    node_count: int = 0
    edge_count: int = 0
    alert_count: int = 0
    highest_severity: str = "unknown"
    risk_score: int = 0
    confidence: int = 0
    is_stale: bool = False
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    top_member_nodes: List[TopologyNodeOut] = Field(default_factory=list)
    top_services: List[TopologyNodeOut] = Field(default_factory=list)
    related_edges: List[TopologyEdgeOut] = Field(default_factory=list)
    child_node_keys_truncated: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TopologySubnetDetailTruncationOut(BaseModel):
    member_nodes: TopologyEvidencePageMetaOut = Field(default_factory=lambda: TopologyEvidencePageMetaOut(limit=0, total=0, omitted=0))
    gateway_candidates: TopologyEvidencePageMetaOut = Field(default_factory=lambda: TopologyEvidencePageMetaOut(limit=0, total=0, omitted=0))
    exposed_or_public_nodes: TopologyEvidencePageMetaOut = Field(default_factory=lambda: TopologyEvidencePageMetaOut(limit=0, total=0, omitted=0))
    listening_services: TopologyEvidencePageMetaOut = Field(default_factory=lambda: TopologyEvidencePageMetaOut(limit=0, total=0, omitted=0))
    external_destinations: TopologyEvidencePageMetaOut = Field(default_factory=lambda: TopologyEvidencePageMetaOut(limit=0, total=0, omitted=0))
    related_edges: TopologyEvidencePageMetaOut = Field(default_factory=lambda: TopologyEvidencePageMetaOut(limit=0, total=0, omitted=0))
    recent_observations: TopologyEvidencePageMetaOut = Field(default_factory=lambda: TopologyEvidencePageMetaOut(limit=0, total=0, omitted=0))


class TopologySubnetDetailOut(BaseModel):
    cidr: str
    label: str
    ip_scope: Optional[str] = None
    node_count: int = 0
    active_node_count: int = 0
    stale_node_count: int = 0
    alert_count: int = 0
    highest_severity: str = "unknown"
    risk_score: Optional[int] = None
    confidence: Optional[int] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    gateway_candidates: List[TopologyNodeOut] = Field(default_factory=list)
    member_nodes: List[TopologyNodeOut] = Field(default_factory=list)
    exposed_or_public_nodes: List[TopologyNodeOut] = Field(default_factory=list)
    listening_services: List[TopologyNodeOut] = Field(default_factory=list)
    external_destinations: List[TopologyNodeOut] = Field(default_factory=list)
    related_edges: List[TopologyEdgeOut] = Field(default_factory=list)
    recent_observations: List[TopologyObservationOut] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    truncation: TopologySubnetDetailTruncationOut = Field(default_factory=TopologySubnetDetailTruncationOut)


class TopologyGraphOut(BaseModel):
    nodes: List[TopologyNodeOut] = Field(default_factory=list)
    edges: List[TopologyEdgeOut] = Field(default_factory=list)
    graph_health: TopologyGraphHealthOut
    groups: Optional[List[TopologyGroupOut]] = None
    group_edges: Optional[List[TopologyGroupEdgeOut]] = None
    facets: Optional[TopologyFacetsOut] = None
    group_strategy: Optional[str] = None
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    projected_at: Optional[datetime] = None
    data_window: Dict[str, Any] = Field(default_factory=dict)
    freshness_seconds: Optional[int] = None
    stale: bool = True
    source_coverage: Dict[str, Any] = Field(default_factory=dict)
    truncation: Dict[str, Any] = Field(default_factory=dict)


class TopologyNodeDetailOut(BaseModel):
    node: TopologyNodeOut
    observations: List[TopologyObservationOut] = Field(default_factory=list)
    evidence_meta: TopologyEvidencePageMetaOut = Field(default_factory=lambda: TopologyEvidencePageMetaOut(limit=0, total=0, omitted=0))
    evidence_sources: List[TopologyEvidenceSourceOut] = Field(default_factory=list)
    connected_nodes: List[TopologyNodeOut] = Field(default_factory=list)
    edges: List[TopologyEdgeOut] = Field(default_factory=list)
    related_alerts: List[TopologyRelatedAlertOut] = Field(default_factory=list)
    related_flows: List[TopologyRelatedFlowOut] = Field(default_factory=list)
    related_services: List[TopologyNodeOut] = Field(default_factory=list)
    related_exposure_findings: List[TopologyRelatedExposureFindingOut] = Field(default_factory=list)
    related_attack_chain_cases: List[TopologyRelatedAttackChainCaseOut] = Field(default_factory=list)


class TopologyEdgeDetailOut(BaseModel):
    edge: TopologyEdgeOut
    observations: List[TopologyObservationOut] = Field(default_factory=list)
    evidence_meta: TopologyEvidencePageMetaOut = Field(default_factory=lambda: TopologyEvidencePageMetaOut(limit=0, total=0, omitted=0))
    evidence_sources: List[TopologyEvidenceSourceOut] = Field(default_factory=list)
    source_node: Optional[TopologyNodeOut] = None
    target_node: Optional[TopologyNodeOut] = None
    related_alerts: List[TopologyRelatedAlertOut] = Field(default_factory=list)
    related_flows: List[TopologyRelatedFlowOut] = Field(default_factory=list)
    related_exposure_findings: List[TopologyRelatedExposureFindingOut] = Field(default_factory=list)
    related_attack_chain_cases: List[TopologyRelatedAttackChainCaseOut] = Field(default_factory=list)
    application_protocols: List[str] = Field(default_factory=list)
    total_bytes: int = 0


class TopologySubnetOut(BaseModel):
    node_key: str
    cidr: str
    label: str
    agent_id: Optional[str] = None
    host_count: int = 0
    interface_count: int = 0
    agent_count: int = 0
    severity: str
    confidence: int
    first_seen_at: datetime
    last_seen_at: datetime
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TopologyNodeTypeStat(BaseModel):
    node_type: str
    count: int


class TopologyCoverageOut(BaseModel):
    agents_projected: int = 0
    agents_with_inventory: int = 0
    interfaces_extracted: int = 0
    subnets_inferred: int = 0
    flow_edges_added: int = 0
    services_projected: int = 0
    alert_edges_added: int = 0
    exposure_edges_added: int = 0
    stale_nodes_marked: int = 0
    warnings: List[str] = Field(default_factory=list)


class TopologyInsightOut(BaseModel):
    id: str
    group: str
    severity: str
    title: str
    detail: str
    count: Optional[int] = None


class TopologyVisibilityOut(BaseModel):
    inventory_coverage: float = 0.0
    flow_coverage: bool = False
    alert_coverage: bool = False
    protocol_coverage: bool = False
    exposure_coverage: bool = False
    last_inventory_at: Optional[datetime] = None
    last_event_at: Optional[datetime] = None
    last_alert_at: Optional[datetime] = None
    known_limitations: List[str] = Field(default_factory=list)


class TopologySummaryOut(BaseModel):
    total_nodes: int
    total_edges: int
    agent_count: int
    host_count: int
    subnet_count: int
    external_ip_count: int
    service_count: int
    docker_network_count: int
    unknown_count: int
    stale_node_count: int
    alert_edge_count: int
    exposure_edge_count: int
    node_type_breakdown: List[TopologyNodeTypeStat] = Field(default_factory=list)
    insights: List[TopologyInsightOut] = Field(default_factory=list)
    visibility: Optional[TopologyVisibilityOut] = None
    last_projected_at: Optional[datetime] = None
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    projected_at: Optional[datetime] = None
    data_window: Dict[str, Any] = Field(default_factory=dict)
    freshness_seconds: Optional[int] = None
    stale: bool = True
    source_coverage: Dict[str, Any] = Field(default_factory=dict)
    truncation: Dict[str, Any] = Field(default_factory=dict)


class TopologyRecalculateOut(BaseModel):
    accepted: bool = True
    projected_nodes: int
    projected_edges: int
    duration_ms: float
    requested_at: datetime
    coverage: TopologyCoverageOut


class TopologyErrorOut(BaseModel):
    code: str
    message: str
    context: Dict[str, Any] = Field(default_factory=dict)


class NetworkTopologyInvalidatePayload(BaseModel):
    reason: str = Field(..., min_length=1, max_length=64)
    scope: str = Field(default="network_topology", min_length=1, max_length=64)
    source: Optional[str] = Field(default=None, max_length=64)
    agent_id: Optional[str] = Field(default=None, max_length=64)
    alert_id: Optional[int] = None
    batch_size: Optional[int] = None
    event_types: List[str] = Field(default_factory=list)
    degraded: bool = False
    sampled: bool = False
    high_priority: bool = False
    requested_at: Optional[str] = None
    projected_at: Optional[str] = None


class NetworkTopologySummaryPatchPayload(BaseModel):
    generated_at: str
    projected_at: Optional[str] = None
    total_nodes: int
    total_edges: int
    agent_count: int
    subnet_count: int
    external_ip_count: int
    freshness_seconds: Optional[int] = None
    stale: bool
    source_coverage: Dict[str, Any] = Field(default_factory=dict)
    truncation: Dict[str, Any] = Field(default_factory=dict)


class NetworkTopologyGraphPatchPayload(BaseModel):
    generated_at: str
    projected_at: Optional[str] = None
    nodes: List[Dict[str, Any]] = Field(default_factory=list)
    edges: List[Dict[str, Any]] = Field(default_factory=list)
    graph_health: Dict[str, Any] = Field(default_factory=dict)
    requires_reconcile: bool = False


class TopologyGraphQuery(BaseModel):
    max_nodes: int = Field(default=200, ge=1, le=2000)
    max_edges: int = Field(default=300, ge=1, le=3000)
    min_confidence: int = Field(default=1, ge=1, le=99)
    agent_id: Optional[str] = Field(default=None, min_length=1, max_length=64)
    node_types: List[str] = Field(default_factory=list)
    edge_types: List[str] = Field(default_factory=list)
    ip_scope: Optional[str] = Field(default=None, max_length=32)
    since: Optional[datetime] = None
    until: Optional[datetime] = None
    include_stale: bool = False
    view_mode: Optional[str] = Field(default=None, max_length=16)
    group_by: Optional[str] = Field(default=None, max_length=16)
    focused_group_key: Optional[str] = Field(default=None, max_length=256)
    exclusive_focus: bool = False

    @validator("node_types", "edge_types", pre=True)
    def _normalize_list(cls, v: Any) -> List[str]:
        if v is None:
            return []
        if isinstance(v, str):
            parts = [x.strip() for x in v.split(",")]
        elif isinstance(v, list):
            parts = [str(x or "").strip() for x in v]
        else:
            return []
        seen: set[str] = set()
        out: list[str] = []
        for item in parts:
            low = item.lower()
            if low and low not in seen:
                seen.add(low)
                out.append(low)
        return out

    @validator("agent_id", "ip_scope", pre=True)
    def _normalize_optional(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        s = str(v).strip()
        return s or None


class TopologySubnetQuery(BaseModel):
    page_size: int = Field(default=50, ge=1, le=200)
    cursor: Optional[str] = None
    agent_id: Optional[str] = Field(default=None, min_length=1, max_length=64)
    since: Optional[datetime] = None
    until: Optional[datetime] = None

    @validator("agent_id", pre=True)
    def _normalize_agent(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        s = str(v).strip()
        return s or None


class TopologyObservationQuery(BaseModel):
    page_size: int = Field(default=50, ge=1, le=200)
    cursor: Optional[str] = None
    node_key: Optional[str] = Field(default=None, max_length=256)
    agent_id: Optional[str] = Field(default=None, min_length=1, max_length=64)
    source_type: Optional[str] = Field(default=None, max_length=32)
    since: Optional[datetime] = None
    until: Optional[datetime] = None

    @validator("source_type", pre=True)
    def _normalize_lower(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        s = str(v).strip().lower()
        return s or None

    @validator("node_key", "agent_id", pre=True)
    def _normalize_text(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        s = str(v).strip()
        return s or None
