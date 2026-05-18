from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

UebaBaselineStatus = Literal["warmup", "mature", "stale"]
UebaFindingStatus = Literal["open", "closed", "suppressed"]
UebaSeverity = Literal["informational", "low", "medium", "high", "critical"]
UebaDetectorStatus = Literal["idle", "healthy", "degraded", "failing", "disabled"]
UebaRunStatus = Literal["running", "completed", "failed"]


class UebaBaselineOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    baseline_key: str
    detector_id: str
    detector_version: int
    agent_id: Optional[str] = None
    entity_type: str
    entity_value: str
    metric_name: str
    bucket_key: str
    status: UebaBaselineStatus
    sample_count: int
    warmup_started_at: datetime
    matured_at: Optional[datetime] = None
    window_started_at: datetime
    window_ended_at: datetime
    last_observed_at: datetime
    expected_value: Optional[float] = None
    dispersion: Optional[float] = None
    lower_bound: Optional[float] = None
    upper_bound: Optional[float] = None
    confidence: int
    state: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime

class UebaFindingEvidenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    finding_id: int
    event_id: Optional[int] = None
    alert_id: Optional[int] = None
    evidence_type: str
    evidence_role: str
    observed_at: datetime
    entity_type: Optional[str] = None
    entity_value: Optional[str] = None
    matched_field: Optional[str] = None
    matched_value: Optional[str] = None
    summary: Optional[str] = None
    raw_context: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime

class UebaFindingListItemOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    finding_key: str
    dedup_key: str
    detector_id: str
    detector_version: int
    baseline_id: Optional[int] = None
    agent_id: Optional[str] = None
    entity_type: str
    entity_value: str
    metric_name: str
    bucket_key: str
    status: UebaFindingStatus
    severity: UebaSeverity
    confidence: int
    risk_score: int
    expected_value: Optional[float] = None
    observed_value: Optional[float] = None
    deviation_score: Optional[float] = None
    first_seen_at: datetime
    last_seen_at: datetime
    window_started_at: datetime
    window_ended_at: datetime
    cooldown_until: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    occurrence_count: int
    summary: str
    reason_codes: List[str] = Field(default_factory=list)
    explanation: Dict[str, Any] = Field(default_factory=dict)
    alert_id: Optional[int] = None
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique: Optional[str] = None
    created_at: datetime
    updated_at: datetime

class UebaFindingDetailOut(UebaFindingListItemOut):
    baseline: Optional[UebaBaselineOut] = None
    evidence: List[UebaFindingEvidenceOut] = Field(default_factory=list)


class UebaDetectorStateOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    detector_id: str
    detector_version: Optional[int] = None
    enabled: bool
    status: UebaDetectorStatus
    consecutive_failures: int
    baseline_count: int
    mature_baseline_count: int
    open_findings: int
    last_run_at: Optional[datetime] = None
    last_success_at: Optional[datetime] = None
    last_error_at: Optional[datetime] = None
    last_window_started_at: Optional[datetime] = None
    last_window_ended_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime

class UebaDetectorRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    detector_id: str
    detector_version: Optional[int] = None
    started_at: datetime
    finished_at: Optional[datetime] = None
    status: UebaRunStatus
    window_started_at: Optional[datetime] = None
    window_ended_at: Optional[datetime] = None
    scanned_events: int
    evaluated_entities: int
    baselines_created: int
    baselines_updated: int
    findings_created: int
    findings_updated: int
    alerts_created: int
    suppressions_applied: int
    duration_ms: Optional[int] = None
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)

class UebaSummaryOut(BaseModel):
    enabled: bool
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_baselines: int = 0
    warming_baselines: int = 0
    mature_baselines: int = 0
    stale_baselines: int = 0
    open_findings: int = 0
    high_or_critical_open_findings: int = 0
    linked_alerts: int = 0
    detectors_total: int = 0
    detectors_healthy: int = 0
    detectors_degraded: int = 0
    detectors_failing: int = 0
    latest_run_at: Optional[datetime] = None
    latest_finding_at: Optional[datetime] = None


class UebaFindingsQuery(BaseModel):
    page_size: int = Field(default=50, ge=1, le=200)
    cursor: Optional[str] = None
    detector_id: Optional[str] = Field(default=None, min_length=1, max_length=96)
    agent_id: Optional[str] = Field(default=None, min_length=1, max_length=64)
    entity_type: Optional[str] = Field(default=None, min_length=1, max_length=64)
    entity_value: Optional[str] = Field(default=None, min_length=1, max_length=256)
    metric_name: Optional[str] = Field(default=None, min_length=1, max_length=96)
    status: Optional[UebaFindingStatus] = None
    severity: Optional[UebaSeverity] = None
    min_risk_score: Optional[int] = Field(default=None, ge=0, le=100)

    @field_validator("detector_id", "agent_id", "entity_type", "entity_value", "metric_name", mode="before")
    @classmethod
    def _normalize_optional_text(cls, value: Any) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip()
        return text or None


class UebaBaselinesQuery(BaseModel):
    page_size: int = Field(default=50, ge=1, le=200)
    cursor: Optional[str] = None
    detector_id: Optional[str] = Field(default=None, min_length=1, max_length=96)
    agent_id: Optional[str] = Field(default=None, min_length=1, max_length=64)
    entity_type: Optional[str] = Field(default=None, min_length=1, max_length=64)
    entity_value: Optional[str] = Field(default=None, min_length=1, max_length=256)
    metric_name: Optional[str] = Field(default=None, min_length=1, max_length=96)
    status: Optional[UebaBaselineStatus] = None

    @field_validator("detector_id", "agent_id", "entity_type", "entity_value", "metric_name", mode="before")
    @classmethod
    def _normalize_optional_text(cls, value: Any) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip()
        return text or None


class UebaRunsQuery(BaseModel):
    page_size: int = Field(default=50, ge=1, le=200)
    cursor: Optional[str] = None
    detector_id: Optional[str] = Field(default=None, min_length=1, max_length=96)
    status: Optional[UebaRunStatus] = None

    @field_validator("detector_id", mode="before")
    @classmethod
    def _normalize_detector_id(cls, value: Any) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip()
        return text or None
