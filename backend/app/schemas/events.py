from datetime import datetime
from typing import Optional, Dict, Any

from pydantic import BaseModel, Field


class NetEvent(BaseModel):
    agent_id: str = Field(..., description="Agent identifier")
    event_type: str = Field(
        ...,
        description="Event type (flow, conn, dns, http, alert, etc.)",
    )
    schema_version: int = Field(1, ge=1, le=16, description="Schema version")
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


class SshIpStat(BaseModel):
    src_ip: str
    count: int
    geo_country: Optional[str] = None
    geo_org: Optional[str] = None
    asn: Optional[str] = None
    asn_org: Optional[str] = None


class SshUserStat(BaseModel):
    username: str
    count: int


class SshLoginEvent(BaseModel):
    timestamp: datetime
    agent_id: str
    src_ip: Optional[str] = None
    username: Optional[str] = None
    geo_country: Optional[str] = None
    geo_org: Optional[str] = None
    asn: Optional[str] = None
    asn_org: Optional[str] = None


class SudoEventSummary(BaseModel):
    timestamp: datetime
    agent_id: str
    username: Optional[str] = None
    target_user: Optional[str] = None
    command: Optional[str] = None
    tty: Optional[str] = None
    pwd: Optional[str] = None


class SshSummaryResponse(BaseModel):
    generated_at: datetime
    since_minutes: int
    agent_id: Optional[str] = None
    successful_logins: list[SshIpStat]
    failed_attempts: list[SshIpStat]
    invalid_user_attempts: list[SshIpStat]
    most_active_ips: list[SshIpStat]
    root_logins: list[SshLoginEvent]
    users_attempted: list[SshUserStat]
    sudo_recent: list[SudoEventSummary]


class TopValueStat(BaseModel):
    value: str
    count: int


class DnsQnameStat(BaseModel):
    qname: str
    count: int
    max_risk: Optional[int] = None


class TlsJa4Stat(BaseModel):
    ja4: str
    count: int
    ptype: Optional[str] = None


class NetworkSummaryTotals(BaseModel):
    total_events: int
    proto_intel_events: int
    dns_events: int
    http_events: int
    tls_events: int


class NetworkSummaryResponse(BaseModel):
    generated_at: datetime
    since_minutes: int
    limit: int
    agent_id: Optional[str] = None
    totals: NetworkSummaryTotals

    app_proto: list[TopValueStat]
    dns_qnames: list[DnsQnameStat]
    http_hosts: list[TopValueStat]
    http_methods: list[TopValueStat]
    tls_sni: list[TopValueStat]
    tls_alpn: list[TopValueStat]
    tls_ja4: list[TlsJa4Stat]
    tls_ja3: list[TopValueStat]
    ja4_ptype: list[TopValueStat]
