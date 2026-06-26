from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class ThreatGeoIp(BaseModel):
    ip: str
    count: int
    severity: str = "unknown"
    scope: Optional[str] = None
    label: Optional[str] = None
    is_public: Optional[bool] = None
    asn: Optional[str] = None
    asn_org: Optional[str] = None
    org: Optional[str] = None
    provenance: str = "alert"
    role: Optional[str] = None


class ThreatGeoRuleCount(BaseModel):
    rule_id: str
    count: int


class ThreatGeoPoint(BaseModel):
    lat: float
    lon: float
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    org: Optional[str] = None
    asn_org: Optional[str] = None
    count: int
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    severity: str = "unknown"
    unique_ips: int = 0
    last_seen: Optional[datetime] = None
    top_ips: List[ThreatGeoIp] = Field(default_factory=list)
    top_rules: List[ThreatGeoRuleCount] = Field(default_factory=list)
    provenance: str = "alert"
    direction: str = "inbound"
    alert_count: int = 0
    event_count: int = 0


class ThreatGeoEndpoint(BaseModel):
    lat: float
    lon: float
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    label: Optional[str] = None
    scope: Optional[str] = None


class ThreatGeoFlow(BaseModel):
    id: str
    origin: Optional[ThreatGeoEndpoint] = None
    target: Optional[ThreatGeoEndpoint] = None
    direction: str = "inbound"
    provenance: str = "event"
    severity: str = "unknown"
    weight: int = 0
    count: int = 0
    unique_ips: int = 0
    last_seen: Optional[datetime] = None


class ThreatGeoRankCountry(BaseModel):
    country: str
    count: int
    unique_ips: int = 0
    severity: str = "unknown"
    provenance: str = "event"


class ThreatGeoRankIp(BaseModel):
    ip: str
    count: int
    severity: str = "unknown"
    country: Optional[str] = None
    org: Optional[str] = None
    asn_org: Optional[str] = None
    scope: Optional[str] = None
    label: Optional[str] = None
    is_public: Optional[bool] = None
    provenance: str = "event"
    role: Optional[str] = None


class ThreatGeoMeta(BaseModel):
    source: str = "postgres"
    cache_hit: bool = False
    query_latency_ms: Optional[float] = None
    query_window_start: Optional[datetime] = None
    query_window_end: Optional[datetime] = None


class ThreatGeoResponse(BaseModel):
    generated_at: datetime
    since_minutes: int
    severity: Optional[str] = None
    source: str = "both"
    home: Optional[ThreatGeoEndpoint] = None
    total_alerts: int = 0
    total_events: int = 0
    located_ips: int = 0
    unlocated_ips: int = 0
    ddos_attacks: int = 0
    ddos_located_sources: int = 0
    ddos_unlocated_sources: int = 0
    points: List[ThreatGeoPoint] = Field(default_factory=list)
    flows: List[ThreatGeoFlow] = Field(default_factory=list)
    top_source_countries: List[ThreatGeoRankCountry] = Field(default_factory=list)
    top_destination_countries: List[ThreatGeoRankCountry] = Field(default_factory=list)
    top_source_ips: List[ThreatGeoRankIp] = Field(default_factory=list)
    top_destination_ips: List[ThreatGeoRankIp] = Field(default_factory=list)
    meta: ThreatGeoMeta
