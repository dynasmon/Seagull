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


class NetEventRollup1s(BaseModel):
    bucket_ts: datetime
    agent_id: str
    event_type: str
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    proto: Optional[str] = None
    count: int
    bytes_sum: int


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


class ProtoCount(BaseModel):
    key: str
    count: int


class ProtoDnsQueryStat(BaseModel):
    qname: str
    risk: int = 0
    count: int


class ProtoJa4Stat(BaseModel):
    ja4: str
    ptype: str = "t"
    count: int


class ProtocolIntelSummaryResponse(BaseModel):
    generated_at: datetime
    since_minutes: int
    agent_id: Optional[str] = None

    total_events: int
    with_proto_metadata: int
    dns_events: int
    http_events: int
    tls_events: int

    app_protocols: list[ProtoCount]
    transport_protocols: list[ProtoCount]
    top_dst_ports: list[ProtoCount]
    top_src_ports: list[ProtoCount]
    app_proto_reasons: list[ProtoCount]
    app_proto_conf_bands: list[ProtoCount]
    ja4_ptypes: list[ProtoCount]
    http_methods: list[ProtoCount]

    top_dns_queries: list[ProtoDnsQueryStat]
    top_http_hosts: list[ProtoCount]
    top_tls_sni: list[ProtoCount]
    top_alpn: list[ProtoCount]
    top_ja4: list[ProtoJa4Stat]
    top_ja3: list[ProtoCount]
