from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

QuerySource = Literal["clickhouse", "elasticsearch", "postgres", "recent_feed", "rollup_1s", "live_1s"]


class QueryProvenanceMeta(BaseModel):
    source: QuerySource
    fallback_chain: List[str] = Field(default_factory=list)
    degraded_reason: Optional[str] = None
    source_freshness_seconds: Optional[int] = None
    query_latency_ms: Optional[float] = None
    cache_hit: bool = False
    approximate: bool = False
    query_window_start: Optional[datetime] = None
    query_window_end: Optional[datetime] = None


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

    model_config = ConfigDict(from_attributes=True)


class EventHuntResponse(BaseModel):
    items: List[NetEventDB] = Field(default_factory=list)
    next_cursor: Optional[str] = None
    has_more: bool = False
    meta: QueryProvenanceMeta


class EventStreamSnapshotResponse(BaseModel):
    generated_at: datetime
    window_minutes: int
    agent_id: Optional[str] = None
    event_type: Optional[str] = None
    search: Optional[str] = None
    items: List[NetEventDB] = Field(default_factory=list)
    next_cursor: Optional[str] = None
    has_more: bool = False
    meta: QueryProvenanceMeta


class DdosLiveSnapshotResponse(BaseModel):
    generated_at: datetime
    since_minutes: int
    agent_id: Optional[str] = None
    items: List[NetEventDB] = Field(default_factory=list)
    next_cursor: Optional[str] = None
    has_more: bool = False
    meta: QueryProvenanceMeta
    live_summary: Dict[str, Any] = Field(default_factory=dict)
    pressure: Dict[str, Any] = Field(default_factory=dict)


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
    src_ip_scope: Optional[str] = None
    src_ip_label: Optional[str] = None
    src_is_internal: Optional[bool] = None
    src_is_public: Optional[bool] = None


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
    src_ip_scope: Optional[str] = None
    src_ip_label: Optional[str] = None
    src_is_internal: Optional[bool] = None
    src_is_public: Optional[bool] = None


class SshAuthEvent(BaseModel):
    timestamp: datetime
    agent_id: str
    action: Optional[str] = None
    src_ip: Optional[str] = None
    username: Optional[str] = None
    geo_country: Optional[str] = None
    geo_org: Optional[str] = None
    asn: Optional[str] = None
    asn_org: Optional[str] = None
    src_ip_scope: Optional[str] = None
    src_ip_label: Optional[str] = None
    src_is_internal: Optional[bool] = None
    src_is_public: Optional[bool] = None


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
    total_accepted: int = 0
    total_failed_password: int = 0
    total_invalid_user: int = 0
    total_actions: int = 0
    unique_source_ips: int = 0
    enriched_source_ips: int = 0
    recent_auth_events: list[SshAuthEvent]
    successful_logins: list[SshIpStat]
    failed_attempts: list[SshIpStat]
    invalid_user_attempts: list[SshIpStat]
    most_active_ips: list[SshIpStat]
    root_logins: list[SshLoginEvent]
    users_attempted: list[SshUserStat]
    sudo_recent: list[SudoEventSummary]
    meta: Optional[QueryProvenanceMeta] = None


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
    effective_since_minutes: Optional[int] = None
    meta: Optional[QueryProvenanceMeta] = None
