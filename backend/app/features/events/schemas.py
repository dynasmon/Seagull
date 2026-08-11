from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.features.events.storage_contract import (
    AGENT_ID_MAX_CHARS,
    AGENT_ID_PATTERN,
    BYTE_COUNT_MAX,
    BYTE_COUNT_MIN,
    EVENT_ID_CHARS,
    EVENT_ID_PATTERN,
    EVENT_TYPE_MAX_CHARS,
    EVENT_TYPE_PATTERN,
    IP_MAX_CHARS,
    PORT_MAX,
    PORT_MIN,
    PROTO_MAX_CHARS,
    SCHEMA_VERSION_MAX,
    SCHEMA_VERSION_MIN,
    VIOLATION_NOT_AN_IP,
    clean_text,
    extra_violation,
    is_ip_address,
)

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
    event_id: Optional[str] = Field(
        None,
        min_length=EVENT_ID_CHARS,
        max_length=EVENT_ID_CHARS,
        pattern=EVENT_ID_PATTERN,
    )
    agent_id: str = Field(
        ...,
        min_length=1,
        max_length=AGENT_ID_MAX_CHARS,
        pattern=AGENT_ID_PATTERN,
        description="Agent identifier",
    )
    event_type: str = Field(
        ...,
        min_length=1,
        max_length=EVENT_TYPE_MAX_CHARS,
        pattern=EVENT_TYPE_PATTERN,
        description="Event type (flow, conn, dns, http, alert, etc.)",
    )
    schema_version: int = Field(
        1,
        ge=SCHEMA_VERSION_MIN,
        le=SCHEMA_VERSION_MAX,
        description="Schema version",
    )
    timestamp: datetime

    src_ip: Optional[str] = Field(None, max_length=IP_MAX_CHARS)
    dst_ip: Optional[str] = Field(None, max_length=IP_MAX_CHARS)
    src_port: Optional[int] = Field(None, ge=PORT_MIN, le=PORT_MAX)
    dst_port: Optional[int] = Field(None, ge=PORT_MIN, le=PORT_MAX)
    proto: Optional[str] = Field(None, max_length=PROTO_MAX_CHARS)
    bytes: Optional[int] = Field(None, ge=BYTE_COUNT_MIN, le=BYTE_COUNT_MAX)

    extra: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata about the event",
    )

    @field_validator("src_ip", "dst_ip", "proto", mode="before")
    @classmethod
    def _absent_when_blank(cls, value: Any) -> Any:
        return clean_text(value) if isinstance(value, str) else value

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def _reject_non_ip(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and not is_ip_address(value):
            raise ValueError(VIOLATION_NOT_AN_IP)
        return value

    @field_validator("extra")
    @classmethod
    def _reject_oversized_extra(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        reason = extra_violation(value)
        if reason is not None:
            raise ValueError(reason)
        return value


class NetEventDB(BaseModel):
    id: int = Field(..., description="Database event identifier")
    event_id: Optional[str] = None
    agent_id: str = ""
    event_type: str = ""
    schema_version: int = 1
    timestamp: datetime

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    proto: Optional[str] = None
    bytes: Optional[int] = None

    extra: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class EventHuntResponse(BaseModel):
    items: List[NetEventDB] = Field(default_factory=list)
    next_cursor: Optional[str] = None
    has_more: bool = False
    meta: QueryProvenanceMeta


class HuntRouteSignals(BaseModel):
    has_search: bool = False
    has_wildcard: bool = False
    filter_clauses: int = 0
    window_minutes: Optional[int] = None
    aggregate: bool = False
    transactional_join: bool = False
    dialect: Literal["simple", "kql", "eql"] = "simple"


class HuntRouteCircuitState(BaseModel):
    state: Literal["closed", "open", "half_open"]
    recent_failures: int = 0
    open_remaining_seconds: float = 0.0
    probe_in_flight: bool = False


class HuntRouteExplainResponse(BaseModel):
    generated_at: datetime
    decision_backend: str
    decision_reason: str
    chain: List[str] = Field(default_factory=list)
    attempt_plan: List[str] = Field(default_factory=list)
    signals: HuntRouteSignals
    timeouts_seconds: Dict[str, float] = Field(default_factory=dict)
    circuit: Dict[str, HuntRouteCircuitState] = Field(default_factory=dict)
    trust_es: bool = False
    search_backend_mode: str = "auto"
    query_window_start: Optional[datetime] = None
    query_window_end: Optional[datetime] = None


class EqlHuntRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=2048, description="EQL query (sequence or event query)")
    since_minutes: Optional[int] = Field(None, ge=1, le=60 * 24 * 30)
    start_ts: Optional[str] = None
    end_ts: Optional[str] = None
    agent_id: Optional[str] = Field(None, min_length=1, max_length=64)
    event_type: Optional[str] = Field(None, min_length=1, max_length=32)
    size: Optional[int] = Field(None, ge=1, le=100)


class EqlSequence(BaseModel):
    join_keys: List[Any] = Field(default_factory=list)
    events: List[NetEventDB] = Field(default_factory=list)


class EqlHuntResponse(BaseModel):
    generated_at: datetime
    total: int = 0
    sequences: List[EqlSequence] = Field(default_factory=list)
    meta: QueryProvenanceMeta


class HuntFieldSpec(BaseModel):
    name: str
    type: str


class HuntFieldsResponse(BaseModel):
    generated_at: datetime
    fields: List[HuntFieldSpec] = Field(default_factory=list)


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
    effective_since_minutes: Optional[int] = None
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
