from __future__ import annotations

from datetime import datetime
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
    raw_context: Dict[str, Any] = Field(default_factory=dict)


class TopologyGraphHealthOut(BaseModel):
    max_nodes_applied: int
    max_edges_applied: int
    node_count: int
    edge_count: int
    nodes_truncated: bool = False
    edges_truncated: bool = False
    last_projected_at: Optional[datetime] = None


class TopologyGraphOut(BaseModel):
    nodes: List[TopologyNodeOut] = Field(default_factory=list)
    edges: List[TopologyEdgeOut] = Field(default_factory=list)
    graph_health: TopologyGraphHealthOut


class TopologyNodeDetailOut(BaseModel):
    node: TopologyNodeOut
    observations: List[TopologyObservationOut] = Field(default_factory=list)
    connected_nodes: List[TopologyNodeOut] = Field(default_factory=list)
    edges: List[TopologyEdgeOut] = Field(default_factory=list)


class TopologyEdgeDetailOut(BaseModel):
    edge: TopologyEdgeOut
    observations: List[TopologyObservationOut] = Field(default_factory=list)
    source_node: Optional[TopologyNodeOut] = None
    target_node: Optional[TopologyNodeOut] = None


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
    last_projected_at: Optional[datetime] = None


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
