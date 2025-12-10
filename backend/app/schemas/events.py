from datetime import datetime
from typing import Optional, Dict, Any

from pydantic import BaseModel, Field


class NetEvent(BaseModel):
    agent_id: str = Field(..., description="Agent identifier")
    event_type: str = Field(
        ...,
        description="Event type (flow, conn, dns, http, alert, etc.)",
    )
    timestamp: datetime

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    proto: Optional[str] = None
    bytes: Optional[int] = None

    extra: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata about the event",
    )


class NetEventDB(NetEvent):
    id: int = Field(..., description="Database event identifier")

    class Config:
        orm_mode = True
