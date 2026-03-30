from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, Field, conint


class CorrelationStage(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    patterns: List[str] = Field(default_factory=list)
    min_count: conint(ge=1, le=100000) = 1


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


class CorrelationRuleOut(CorrelationRuleIn):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class CorrelationAlertRef(BaseModel):
    id: int
    created_at: datetime
    rule_id: str
    severity: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    description: str


class CorrelationIncidentOut(BaseModel):
    id: str
    correlation_rule_id: int
    correlation_rule_name: str
    severity: str

    group_by: str
    group_value: str

    started_at: datetime
    ended_at: datetime

    alert_count: int
    unique_rules: List[str] = Field(default_factory=list)
    stage_hits: Dict[str, int] = Field(default_factory=dict)

    sample_alerts: List[CorrelationAlertRef] = Field(default_factory=list)


class CorrelationRunOut(BaseModel):
    rules_evaluated: int
    alerts_scanned: int
    incidents: List[CorrelationIncidentOut] = Field(default_factory=list)
