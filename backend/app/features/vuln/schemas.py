from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, validator

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _norm(s: Optional[str]) -> Optional[str]:
    if s is None:
        return None
    s2 = str(s).strip()
    return s2 if s2 else None


class VulnScanIn(BaseModel):
    scan_uuid: Optional[str] = Field(None, min_length=8, max_length=36, description="Client scan id (UUID recommended)")
    target: Optional[str] = Field(None, max_length=1024, description="Human label (CIDR/host/url)")

    tool: str = Field("unknown", min_length=1, max_length=64)
    tool_version: Optional[str] = Field(None, max_length=64)

    status: Optional[str] = Field(None, min_length=1, max_length=24, description="Legacy lifecycle state")
    lifecycle_state: Optional[str] = Field(None, min_length=1, max_length=24)
    current_phase: Optional[str] = Field(None, min_length=1, max_length=32)

    queued_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    last_progress_at: Optional[datetime] = None

    trigger_source: Optional[str] = Field(None, min_length=1, max_length=24)
    error_summary: Optional[str] = Field(None, max_length=512)

    scope: Dict[str, Any] = Field(default_factory=dict)
    config: Dict[str, Any] = Field(default_factory=dict)
    stats: Dict[str, Any] = Field(default_factory=dict)
    phase_timestamps: Dict[str, str] = Field(default_factory=dict)

    @validator("scan_uuid", pre=True)
    def _v_scan_uuid(cls, v):
        return _norm(v)

    @validator("tool", "status", "lifecycle_state", "current_phase", "trigger_source", pre=True)
    def _v_lower_trim(cls, v):
        v = _norm(v) or ""
        return v.lower() if v else None

    @validator("error_summary", pre=True)
    def _v_error_summary(cls, v):
        return _norm(v)


class VulnFindingIn(BaseModel):
    asset_key: str = Field(..., min_length=3, max_length=256, description="Stable asset identity key")
    asset_agent_id: Optional[str] = Field(None, min_length=1, max_length=64, description="Agent id when the asset is enrolled")
    target: Optional[str] = Field(None, max_length=2048, description="Human label (ip/host/url)")
    asset: Dict[str, Any] = Field(default_factory=dict, description="Structured asset metadata (ip/hostname/port/url/etc)")

    source: str = Field("unknown", min_length=1, max_length=32, description="Scanner source (e.g., nuclei, osv, cve)")
    external_id: Optional[str] = Field(None, max_length=128, description="Template/OSV id/etc")
    fingerprint: Optional[str] = Field(None, min_length=16, max_length=64, description="Optional dedup fingerprint")

    severity: str = Field("unknown", min_length=1, max_length=16)
    confidence: int = Field(50, ge=0, le=100, description="Confidence (0-100)")

    title: str = Field(..., min_length=3, max_length=4096)
    description: Optional[str] = Field(None, max_length=65535)
    remediation: Optional[str] = Field(None, max_length=65535)

    cve: Optional[str] = Field(None, max_length=32)
    cwe: Optional[str] = Field(None, max_length=32)
    cvss: Optional[str] = Field(None, max_length=16, description="CVSS vector or numeric string")

    location: Optional[str] = Field(None, max_length=4096)
    tags: List[str] = Field(default_factory=list, description="Tags (max 50)")
    evidence: Dict[str, Any] = Field(default_factory=dict)

    last_seen_at: Optional[datetime] = None

    @validator("asset_key", "asset_agent_id", "target", "external_id", "fingerprint", "cve", "cwe", "location", pre=True)
    def _v_trim(cls, v):
        return _norm(v)

    @validator("source", "severity", pre=True)
    def _v_lower(cls, v):
        v = _norm(v) or ""
        return v.lower() if v else v

    @validator("tags")
    def _v_tags(cls, v: List[str]):
        if v is None:
            return []
        out: List[str] = []
        for t in v[:50]:
            t2 = _norm(t)
            if not t2:
                continue
            if len(t2) > 64:
                t2 = t2[:64]
            out.append(t2)
        return out

    @validator("cve")
    def _v_cve(cls, v: Optional[str]):
        v2 = _norm(v)
        if not v2:
            return None
        if not _CVE_RE.match(v2):
            return v2
        return v2.upper()


class VulnIngestBatch(BaseModel):
    scan: Optional[VulnScanIn] = None
    findings: List[VulnFindingIn] = Field(default_factory=list, description="Findings (max 2000 by default)")


class VulnScanOut(BaseModel):
    id: int
    scan_uuid: str
    reporter_agent_id: Optional[str] = None
    target: Optional[str] = None
    tool: str
    tool_version: Optional[str] = None

    status: str
    lifecycle_state: str
    current_phase: str

    queued_at: datetime
    acknowledged_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    last_progress_at: datetime
    duration_ms: Optional[int] = None

    trigger_source: str
    error_summary: Optional[str] = None

    scope: Dict[str, Any]
    config: Dict[str, Any]
    stats: Dict[str, Any]
    phase_timestamps: Dict[str, str]
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class VulnFindingOut(BaseModel):
    id: int
    scan_id: Optional[int] = None

    asset_key: str
    asset_agent_id: Optional[str] = None
    reporter_agent_id: Optional[str] = None
    target: Optional[str] = None
    asset: Dict[str, Any]

    source: str
    external_id: Optional[str] = None
    fingerprint: str

    severity: str
    severity_rank: int
    confidence: int

    title: str
    description: Optional[str] = None
    remediation: Optional[str] = None

    cve: Optional[str] = None
    cwe: Optional[str] = None
    cvss: Optional[str] = None

    location: Optional[str] = None
    tags: List[str]
    evidence: Dict[str, Any]

    status: str
    is_suppressed: bool
    observation_state: str
    operator_disposition: str

    first_seen_at: datetime
    last_seen_at: datetime
    occurrences: int
    updated_at: datetime

    component: "VulnFindingComponentOut"
    exposure: "VulnFindingExposureOut"
    asset_display: str
    asset_context: List[str]
    risk_summary: Optional[str] = None
    remediation_guidance: Optional[str] = None
    repeated_observation: bool = False
    priority: "VulnFindingPriorityOut"

    model_config = ConfigDict(from_attributes=True)


class VulnFindingPatchIn(BaseModel):
    status: Optional[str] = Field(None, min_length=1, max_length=24, description="Legacy compatibility status")
    is_suppressed: Optional[bool] = None
    observation_state: Optional[str] = Field(None, min_length=1, max_length=32)
    operator_disposition: Optional[str] = Field(None, min_length=1, max_length=32)

    @validator("status", "observation_state", "operator_disposition", pre=True)
    def _v_status(cls, v):
        v2 = _norm(v)
        return v2.lower() if v2 else None


class VulnIngestResult(BaseModel):
    scan_id: Optional[int] = None
    scan_uuid: Optional[str] = None
    lifecycle_state: Optional[str] = None
    current_phase: Optional[str] = None
    received_findings: int
    stored_findings: int


class VulnSummaryOut(BaseModel):
    generated_at: datetime
    total_open: int
    total_observed: int
    total_awaiting_verification: int
    total_resolved: int
    total_suppressed: int
    by_severity: Dict[str, int]
    by_status: Dict[str, int]
    by_observation_state: Dict[str, int]
    by_disposition: Dict[str, int]


class VulnRiskItemOut(BaseModel):
    id: int
    asset_key: str
    asset_agent_id: Optional[str] = None
    target: Optional[str] = None
    title: str
    cve: Optional[str] = None
    severity: str
    confidence: int
    occurrences: int
    last_seen_at: datetime
    remediation: Optional[str] = None
    cvss: Optional[str] = None
    cvss_score: float
    has_fix: bool
    internet_exposed: bool
    exploit_likely: bool
    risk_score: float
    component_name: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    asset_display: str
    risk_summary: Optional[str] = None
    priority_factors: List[str] = Field(default_factory=list)
    exposure_source: str = "none"
    service_hints: List[str] = Field(default_factory=list)


class VulnAssetRiskOut(BaseModel):
    asset_key: str
    asset_agent_id: Optional[str] = None
    open_findings: int
    critical_high: int
    max_risk: float
    avg_risk: float
    last_seen_at: datetime


class VulnPostureOut(BaseModel):
    generated_at: datetime
    active_within_days: int
    total_open: int
    critical_open: int
    high_open: int
    exploitable_open: int
    fixable_open: int
    stale_open: int
    mean_risk: float
    p95_risk: float
    top_risks: List[VulnRiskItemOut]
    top_assets: List[VulnAssetRiskOut]


class VulnManualScanIn(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=64)

    @validator("agent_id", pre=True)
    def _v_agent_id(cls, v):
        return _norm(v) or ""


class VulnManualScanOut(BaseModel):
    agent_id: str
    request_token: str
    trigger_token: str
    scan_uuid: str
    request_state: str
    status: str
    lifecycle_state: str
    current_phase: str
    queued_at: datetime
    scan: Optional[VulnScanOut] = None


class VulnFindingComponentOut(BaseModel):
    kind: str = "package"
    name: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    ecosystem: Optional[str] = None
    manager: Optional[str] = None
    purl: Optional[str] = None


class VulnFindingExposureOut(BaseModel):
    source: str = "none"
    observed: bool = False
    inferred: bool = False
    externally_exposed: bool = False
    package_relevant: bool = False
    surface_score: int = 0
    service_hints: List[str] = Field(default_factory=list)
    exposed_ports: List[int] = Field(default_factory=list)


class VulnFindingPriorityOut(BaseModel):
    score: float = 0.0
    factors: List[str] = Field(default_factory=list)


VulnFindingOut.model_rebuild()
