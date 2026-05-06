from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class RuleHealthOut(BaseModel):
    rule_id: str
    rule_version: Optional[int] = None
    content_hash: Optional[str] = None
    status: str
    consecutive_failures: int = 0
    last_run_at: Optional[datetime] = None
    last_success_at: Optional[datetime] = None
    last_error_at: Optional[datetime] = None
    duration_ms: Optional[int] = None
    events_scanned: Optional[int] = None
    alerts_created: int = 0
    suppressions_applied: int = 0
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    updated_at: datetime

    class Config:
        orm_mode = True
