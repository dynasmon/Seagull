from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, validator


class EvidenceRefSchema(BaseModel):
    source_type: str
    source_id: str
    observed_at: datetime
    title: str = ""
    summary: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        from_attributes = True


class ScoreBreakdownSchema(BaseModel):
    exposure_score: int = 0
    vulnerability_score: int = 0
    active_threat_score: int = 0
    persistence_score: int = 0
    attack_chain_score: int = 0
    asset_criticality_score: int = 0
    reliability_penalty: int = 0

    class Config:
        from_attributes = True


class RecommendationSchema(BaseModel):
    rec_type: str
    priority: int
    title: str
    detail: str
    reason_code: str
    metadata: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        from_attributes = True


class ExposureAssetPostureDB(BaseModel):
    id: int
    asset_key: str
    agent_id: Optional[str] = None

    asset_type: str
    display_name: str
    hostname: Optional[str] = None
    environment: Optional[str] = None
    criticality: str

    severity: str
    risk_score: int
    confidence: int

    exposure_score: int
    vulnerability_score: int
    active_threat_score: int
    persistence_score: int
    attack_chain_score: int
    asset_criticality_score: int
    reliability_penalty: int

    status: str

    first_seen_at: datetime
    last_seen_at: datetime
    updated_at: datetime

    score_breakdown: Dict[str, Any] = Field(default_factory=dict)
    reason_codes: List[str] = Field(default_factory=list)
    top_recommendations: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_counts: Dict[str, int] = Field(default_factory=dict)
    extra_data: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        from_attributes = True


class ExposureNodeDB(BaseModel):
    id: int
    node_key: str
    node_type: str
    asset_key: Optional[str] = None
    agent_id: Optional[str] = None
    label: str
    severity: str
    risk_score: int
    confidence: int
    first_seen_at: datetime
    last_seen_at: datetime
    updated_at: datetime
    properties: Dict[str, Any] = Field(default_factory=dict)
    source_refs: List[Dict[str, Any]] = Field(default_factory=list)

    class Config:
        from_attributes = True


class ExposureEdgeDB(BaseModel):
    id: int
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
    evidence_refs: List[Dict[str, Any]] = Field(default_factory=list)

    class Config:
        from_attributes = True


class ExposureFindingDB(BaseModel):
    id: int
    finding_key: str
    asset_key: str
    agent_id: Optional[str] = None
    finding_type: str
    severity: str
    score_delta: int
    confidence: int
    title: str
    summary: str
    status: str
    first_seen_at: datetime
    last_seen_at: datetime
    updated_at: datetime
    related_node_keys: List[str] = Field(default_factory=list)
    evidence_refs: List[Dict[str, Any]] = Field(default_factory=list)
    reason_codes: List[str] = Field(default_factory=list)
    recommendations: List[Dict[str, Any]] = Field(default_factory=list)
    extra_data: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        from_attributes = True


class ExposureScoreHistoryDB(BaseModel):
    id: int
    asset_key: str
    agent_id: Optional[str] = None
    bucket_ts: datetime
    risk_score: int
    severity: str
    confidence: int
    score_breakdown: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        from_attributes = True


class ExposurePostureListParams(BaseModel):
    agent_id: Optional[str] = None
    min_score: Optional[int] = Field(None, ge=0, le=100)
    severity: Optional[str] = None
    status: Optional[str] = None
    page_size: int = Field(50, ge=1, le=200)
    cursor: Optional[str] = None

    @validator("severity", pre=True)
    def _lower_severity(cls, v: Optional[str]) -> Optional[str]:
        return str(v).strip().lower() if v else None

    @validator("status", pre=True)
    def _lower_status(cls, v: Optional[str]) -> Optional[str]:
        return str(v).strip().lower() if v else None


class ExposureFindingListParams(BaseModel):
    asset_key: Optional[str] = None
    agent_id: Optional[str] = None
    finding_type: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    page_size: int = Field(50, ge=1, le=200)
    cursor: Optional[str] = None

    @validator("severity", "status", "finding_type", pre=True)
    def _lower(cls, v: Optional[str]) -> Optional[str]:
        return str(v).strip().lower() if v else None
