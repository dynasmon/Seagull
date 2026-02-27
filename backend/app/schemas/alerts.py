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

    # MITRE ATT&CK metadata (optional but first-class)
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique: Optional[str] = None
    confidence: int = 50

    description: str
    details: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        orm_mode = True
