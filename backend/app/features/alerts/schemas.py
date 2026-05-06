from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class AlertOut(BaseModel):
    id: int
    created_at: datetime
    rule_id: str
    severity: str

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None

    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique: Optional[str] = None
    confidence: int = 50

    description: str
    details: Dict[str, Any] = Field(default_factory=dict)

    status: str = "open"
    disposition: Optional[str] = None
    priority: Optional[int] = None
    assigned_to: Optional[str] = None
    investigation_id: Optional[int] = None
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None
    closed_at: Optional[datetime] = None
    closed_by: Optional[str] = None
    triage_notes: Optional[str] = None
    risk_score: Optional[int] = None

    class Config:
        orm_mode = True


class AlertTriageIn(BaseModel):
    status: Optional[str] = None
    disposition: Optional[str] = None
    priority: Optional[int] = None
    assigned_to: Optional[str] = None
    investigation_id: Optional[int] = None
    triage_notes: Optional[str] = None
    risk_score: Optional[int] = None


from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class RuleSchedule(BaseModel):
    """Simple schedule window.

    - enabled: if false or omitted, the rule is always active.
    - timezone: IANA tz name, e.g. "America/Fortaleza".
    - days: subset of [mon,tue,wed,thu,fri,sat,sun]. Empty means all days.
    - start/end: "HH:MM" 24h.
      If start > end, window crosses midnight.
    """

    enabled: bool = False
    timezone: str = "UTC"
    days: List[str] = Field(default_factory=list)
    start: str = "00:00"
    end: str = "23:59"


class RuleCondition(BaseModel):
    field: Optional[str] = None
    operator: str = ">="
    value: int = 0


class RuleOverrideIn(BaseModel):
    enabled: Optional[bool] = None
    severity: Optional[str] = None
    window: Optional[str] = None
    cooldown: Optional[str] = None
    min_events: Optional[int] = None
    condition: Optional[Dict[str, Any]] = None
    schedule: Optional[Dict[str, Any]] = None
    tuning: Optional[Dict[str, Any]] = None
    suppressions: Optional[List[Dict[str, Any]]] = None
    patch: Optional[Dict[str, Any]] = None


class RuleOut(BaseModel):
    id: str
    name: Optional[str] = None
    description: Optional[str] = None
    source_file: Optional[str] = None
    pack: Optional[str] = None
    category: Optional[str] = None
    rule_version: int = 1

    # Convenience fields (from effective)
    enabled: bool
    severity: str
    type: Optional[str] = None
    window: Optional[str] = None
    cooldown: Optional[str] = None

    has_override: bool
    updated_at: Optional[datetime] = None

    base: Dict[str, Any] = Field(default_factory=dict)
    override: Optional[Dict[str, Any]] = None
    effective: Dict[str, Any] = Field(default_factory=dict)


class RuleGovernanceHistoryOut(BaseModel):
    id: int
    rule_id: str
    kind: str  # tuning | suppression
    action: str
    created_at: datetime
    actor_user_id: Optional[int] = None
    actor_username: Optional[str] = None
    snapshot: Dict[str, Any] = Field(default_factory=dict)
