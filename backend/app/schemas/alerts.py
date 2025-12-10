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

    description: str
    details: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        orm_mode = True
