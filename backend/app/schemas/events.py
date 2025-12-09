from datetime import datetime
from pydantic import BaseModel, Field
from typing import Optional


class NetEvent(BaseModel):
    agent_id: str = Field(..., description="Identificador do agente")
    event_type: str = Field(..., description="Tipo de evento (flow, conn, dns, http, alert, etc.)")
    timestamp: datetime
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    proto: Optional[str] = None
    bytes: Optional[int] = None
    extra: dict = Field(default_factory=dict)
