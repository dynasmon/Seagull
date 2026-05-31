from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, conint


class CorrelationStage(BaseModel):
    id: Optional[str] = Field(default=None, min_length=1, max_length=64)
    name: str = Field(..., min_length=1, max_length=64)
    patterns: List[str] = Field(default_factory=list)
    include_patterns: List[str] = Field(default_factory=list)
    exclude_patterns: List[str] = Field(default_factory=list)
    min_count: conint(ge=1, le=100000) = 1
    after: Optional[str] = Field(default=None, max_length=64)
    within_seconds: Optional[conint(ge=1, le=7 * 24 * 3600)] = None
    required: bool = True
    maxspan_seconds: Optional[conint(ge=1, le=7 * 24 * 3600)] = None


class CorrelationRuleIn(BaseModel):
    name: str = Field(..., min_length=2, max_length=96)
    description: Optional[str] = Field(default=None, max_length=255)

    enabled: bool = True
    severity: str = Field(default="high", max_length=16)

    strategy: str = Field(default="burst", max_length=16)
    group_by: str = Field(default="src_ip", max_length=32)
    window_seconds: conint(ge=30, le=7 * 24 * 3600) = 600
    min_alerts: conint(ge=1, le=100000) = 2

    include_patterns: List[str] = Field(default_factory=list)
    exclude_patterns: List[str] = Field(default_factory=list)
    stages: List[CorrelationStage] = Field(default_factory=list)
    entity: Optional[Dict[str, Any]] = None
    strategy_config: Optional[Dict[str, Any]] = None
    risk_config: Optional[Dict[str, Any]] = None
    evidence_config: Optional[Dict[str, Any]] = None
    lifecycle_config: Optional[Dict[str, Any]] = None


class CorrelationRuleOut(CorrelationRuleIn):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CorrelationAlertRef(BaseModel):
    id: int
    created_at: datetime
    rule_id: str
    severity: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    description: str


class CorrelationEvidenceMatch(BaseModel):
    evidence_type: str
    timestamp: datetime
    alert_id: Optional[int] = None
    net_event_id: Optional[int] = None
    rule_id: Optional[str] = None
    stage: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class CorrelationIncidentOut(BaseModel):
    id: str
    correlation_rule_id: int
    correlation_rule_name: str
    severity: str

    group_by: str
    group_value: str
    entity_type: Optional[str] = None
    entity_value: Optional[str] = None

    started_at: datetime
    ended_at: datetime

    alert_count: int
    unique_rules: List[str] = Field(default_factory=list)
    stage_hits: Dict[str, int] = Field(default_factory=dict)
    risk_score: Optional[int] = None
    confidence: Optional[int] = None
    summary: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)

    sample_alerts: List[CorrelationAlertRef] = Field(default_factory=list)
    evidence_items: List[CorrelationEvidenceMatch] = Field(default_factory=list)

    # Populated after persistence
    db_id: Optional[int] = None
    status: str = "open"


class CorrelationRunOut(BaseModel):
    rules_evaluated: int
    alerts_scanned: int
    incidents: List[CorrelationIncidentOut] = Field(default_factory=list)


# Durable incident schemas

class CorrelationEvidenceOut(BaseModel):
    id: int
    incident_id: int
    alert_id: Optional[int] = None
    net_event_id: Optional[int] = None
    evidence_type: str
    rule_id: Optional[str] = None
    stage: Optional[str] = None
    timestamp: datetime
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    details: Dict = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class CorrelationIncidentListItemOut(BaseModel):
    id: int
    correlation_rule_id: Optional[int] = None
    correlation_rule_name: str
    status: str
    severity: str
    risk_score: Optional[int] = None
    confidence: Optional[int] = None
    entity_type: Optional[str] = None
    entity_value: Optional[str] = None
    group_by: str
    group_value: str
    dedup_key: str
    started_at: datetime
    last_seen_at: datetime
    closed_at: Optional[datetime] = None
    alert_count: int
    unique_rules: List[str] = Field(default_factory=list)
    stage_hits: Dict[str, int] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CorrelationIncidentDetailOut(CorrelationIncidentListItemOut):
    summary: Optional[str] = None
    context: Dict = Field(default_factory=dict)
    evidence: List[CorrelationEvidenceOut] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class CorrelationIncidentStatusIn(BaseModel):
    status: str = Field(..., description="open | triaged | closed | suppressed")
    summary: Optional[str] = Field(default=None, max_length=2000)


class CorrelationRuleRunOut(BaseModel):
    id: int
    correlation_rule_id: Optional[int] = None
    started_at: datetime
    finished_at: Optional[datetime] = None
    status: str
    scanned_alerts: int
    incidents_created: int
    incidents_updated: int
    error: Optional[str] = None
    context: Dict = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)
