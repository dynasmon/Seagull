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
    total_alerts: int = 0
    total_events: int = 0
    located_ips: int = 0
    unlocated_ips: int = 0
    ddos_attacks: int = 0
    ddos_located_sources: int = 0
    ddos_unlocated_sources: int = 0
    points: List[ThreatGeoPoint] = Field(default_factory=list)
    meta: ThreatGeoMeta
