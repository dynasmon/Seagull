from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

from app.features.threat_map import service as threat_map_service


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def mappings(self):
        return self

    def all(self):
        return self._rows


class _FakeDB:
    def __init__(self, responses):
        self._responses = list(responses)

    def execute(self, stmt):
        if not self._responses:
            raise AssertionError("unexpected extra query execution")
        return _FakeResult(self._responses.pop(0))

    def close(self):
        return None


def _disable_cache(monkeypatch):
    monkeypatch.setattr(threat_map_service, "_cache_get_json", lambda key: None)
    monkeypatch.setattr(threat_map_service, "_cache_set_json", lambda key, payload, ttl: None)
    monkeypatch.setattr(threat_map_service, "_resolve_home_endpoint", lambda: None)


def test_threat_geo_clusters_public_sources_and_skips_private_and_unlocated(monkeypatch):
    _disable_cache(monkeypatch)
    now = datetime.now(timezone.utc)

    sources = [
        {"src_ip": "8.8.8.8", "count": 10, "critical": 2, "high": 3, "medium": 5, "low": 0, "last_seen": now},
        {"src_ip": "8.8.4.4", "count": 6, "critical": 0, "high": 2, "medium": 4, "low": 0, "last_seen": now},
        {"src_ip": "1.1.1.1", "count": 4, "critical": 0, "high": 1, "medium": 0, "low": 3, "last_seen": now},
        {"src_ip": "9.9.9.9", "count": 2, "critical": 0, "high": 0, "medium": 2, "low": 0, "last_seen": now},
        {"src_ip": "192.168.1.50", "count": 8, "critical": 4, "high": 4, "medium": 0, "low": 0, "last_seen": now},
    ]
    geo_rows = [
        {"ip": "8.8.8.8", "country": "US", "region": "California", "city": "Mountain View", "loc": "37.42,-122.08", "org": "Google LLC", "asn": "AS15169", "asn_org": "Google LLC"},
        {"ip": "8.8.4.4", "country": "US", "region": "California", "city": "Mountain View", "loc": "37.40,-122.10", "org": "Google LLC", "asn": "AS15169", "asn_org": "Google LLC"},
        {"ip": "1.1.1.1", "country": "AU", "region": "New South Wales", "city": "Sydney", "loc": "-33.87,151.21", "org": "Cloudflare, Inc.", "asn": "AS13335", "asn_org": "Cloudflare, Inc."},
    ]
    rule_rows = [
        {"src_ip": "8.8.8.8", "rule_id": "ssh-bruteforce", "count": 6},
        {"src_ip": "8.8.8.8", "rule_id": "port-scan", "count": 4},
        {"src_ip": "8.8.4.4", "rule_id": "ssh-bruteforce", "count": 6},
        {"src_ip": "1.1.1.1", "rule_id": "ssh-bruteforce", "count": 4},
    ]

    db = _FakeDB([sources, geo_rows, rule_rows, []])
    payload = threat_map_service.get_threat_geo(db, since_minutes=60, limit=200, severity=None, source="alerts")

    assert payload.located_ips == 3
    assert payload.unlocated_ips == 1
    assert payload.total_alerts == 20
    assert payload.total_events == 0
    assert payload.source == "alerts"
    assert payload.flows == []
    assert payload.meta.source == "postgres"
    assert payload.meta.cache_hit is False
    assert len(payload.points) == 2
    assert all(point.provenance == "alert" and point.direction == "inbound" for point in payload.points)

    google, cloudflare = payload.points

    assert google.count == 16
    assert google.unique_ips == 2
    assert google.severity == "critical"
    assert google.critical == 2
    assert google.high == 5
    assert google.medium == 9
    assert google.country == "US"
    assert google.city == "Mountain View"
    assert google.lat == pytest.approx(37.4125)
    assert google.lon == pytest.approx(-122.0875)

    assert [ip.ip for ip in google.top_ips] == ["8.8.8.8", "8.8.4.4"]
    assert google.top_ips[0].is_public is True
    assert google.top_ips[0].scope == "public_internet"
    assert google.top_ips[0].asn == "AS15169"
    assert google.top_rules[0].rule_id == "ssh-bruteforce"
    assert google.top_rules[0].count == 12

    assert cloudflare.count == 4
    assert cloudflare.severity == "high"
    assert cloudflare.country == "AU"
    assert cloudflare.city == "Sydney"
    assert cloudflare.unique_ips == 1


def test_threat_geo_without_public_sources_returns_empty_without_geo_or_rule_queries(monkeypatch):
    _disable_cache(monkeypatch)
    now = datetime.now(timezone.utc)

    sources = [
        {"src_ip": "10.0.0.5", "count": 12, "critical": 3, "high": 9, "medium": 0, "low": 0, "last_seen": now},
        {"src_ip": "192.168.1.50", "count": 4, "critical": 0, "high": 0, "medium": 4, "low": 0, "last_seen": now},
    ]

    db = _FakeDB([sources])
    payload = threat_map_service.get_threat_geo(db, since_minutes=60, limit=200, severity=None, source="alerts")

    assert payload.points == []
    assert payload.flows == []
    assert payload.located_ips == 0
    assert payload.unlocated_ips == 0
    assert payload.total_alerts == 0
    assert payload.ddos_attacks == 0


def test_threat_geo_serves_cached_payload_without_touching_db(monkeypatch):
    now = datetime.now(timezone.utc)
    cached = threat_map_service.ThreatGeoResponse(
        generated_at=now,
        since_minutes=60,
        severity=None,
        total_alerts=7,
        located_ips=1,
        unlocated_ips=0,
        points=[
            threat_map_service.ThreatGeoPoint(
                lat=37.4,
                lon=-122.1,
                country="US",
                count=7,
                critical=1,
                severity="critical",
                unique_ips=1,
            )
        ],
        meta=threat_map_service.ThreatGeoMeta(source="postgres", cache_hit=False),
    ).dict()

    monkeypatch.setattr(threat_map_service, "_cache_get_json", lambda key: cached)

    def _explode(*_args, **_kwargs):
        raise AssertionError("cache hit must not query the database")

    db = _FakeDB([])
    monkeypatch.setattr(db, "execute", _explode)

    payload = threat_map_service.get_threat_geo(db, since_minutes=60, limit=200, severity=None)

    assert payload.meta.cache_hit is True
    assert payload.total_alerts == 7
    assert len(payload.points) == 1
    assert payload.points[0].country == "US"


def test_threat_geo_events_place_inbound_sources_and_outbound_destinations(monkeypatch):
    _disable_cache(monkeypatch)
    now = datetime.now(timezone.utc)

    event_sources = [
        {
            "src_ip": "8.8.8.8", "count": 10, "high": 10, "medium": 0, "last_seen": now,
            "geo_loc": "37.42,-122.08", "country": "US", "region": "California",
            "city": "Mountain View", "org": "Google LLC", "asn": "AS15169", "asn_org": "Google LLC",
        },
        {
            "src_ip": "1.1.1.1", "count": 4, "high": 0, "medium": 4, "last_seen": now,
            "geo_loc": None, "country": None, "region": None, "city": None, "org": None, "asn": None, "asn_org": None,
        },
        {
            "src_ip": "10.0.0.5", "count": 7, "high": 7, "medium": 0, "last_seen": now,
            "geo_loc": None, "country": None, "region": None, "city": None, "org": None, "asn": None, "asn_org": None,
        },
    ]
    event_destinations = [
        {"src_ip": "45.83.12.7", "count": 6, "high": 6, "medium": 0, "last_seen": now},
    ]
    geo_rows = [
        {"ip": "1.1.1.1", "country": "AU", "region": "New South Wales", "city": "Sydney", "loc": "-33.87,151.21", "org": "Cloudflare, Inc.", "asn": "AS13335", "asn_org": "Cloudflare, Inc."},
        {"ip": "45.83.12.7", "country": "NL", "region": "North Holland", "city": "Amsterdam", "loc": "52.37,4.89", "org": "EvilHost", "asn": "AS9999", "asn_org": "EvilHost"},
    ]

    db = _FakeDB([event_sources, event_destinations, [], geo_rows, []])
    payload = threat_map_service.get_threat_geo(db, since_minutes=60, limit=200, severity=None, source="events")

    assert payload.source == "events"
    assert payload.total_events == 20
    assert payload.total_alerts == 0
    assert payload.located_ips == 3
    assert payload.unlocated_ips == 0
    assert len(payload.points) == 3
    assert all(point.provenance == "event" for point in payload.points)

    by_country = {point.country: point for point in payload.points}
    assert by_country["US"].direction == "inbound"
    assert by_country["US"].city == "Mountain View"
    assert by_country["US"].severity == "high"
    assert by_country["AU"].city == "Sydney"
    assert by_country["NL"].direction == "outbound"
    assert by_country["NL"].severity == "high"

    assert [ip.ip for ip in payload.top_source_ips] == ["8.8.8.8", "1.1.1.1"]
    assert all(ip.role == "source" for ip in payload.top_source_ips)
    assert [ip.ip for ip in payload.top_destination_ips] == ["45.83.12.7"]
    assert payload.top_destination_ips[0].role == "destination"
    assert {c.country for c in payload.top_source_countries} == {"US", "AU"}
    assert [c.country for c in payload.top_destination_countries] == ["NL"]


def test_threat_geo_both_merges_alert_and_event_into_promoted_point(monkeypatch):
    _disable_cache(monkeypatch)
    now = datetime.now(timezone.utc)

    alert_sources = [
        {"src_ip": "8.8.8.8", "count": 5, "critical": 2, "high": 3, "medium": 0, "low": 0, "last_seen": now},
    ]
    event_sources = [
        {
            "src_ip": "8.8.8.8", "count": 10, "high": 10, "medium": 0, "last_seen": now,
            "geo_loc": "37.42,-122.08", "country": "US", "region": "California",
            "city": "Mountain View", "org": "Google LLC", "asn": "AS15169", "asn_org": "Google LLC",
        },
    ]
    event_destinations: list = []

    db = _FakeDB([alert_sources, event_sources, event_destinations, [], [], [], []])
    payload = threat_map_service.get_threat_geo(db, since_minutes=60, limit=200, severity=None, source="both")

    assert payload.source == "both"
    assert payload.total_alerts == 5
    assert payload.total_events == 10
    assert payload.located_ips == 1
    assert len(payload.points) == 1

    point = payload.points[0]
    assert point.count == 15
    assert point.alert_count == 5
    assert point.event_count == 10
    assert point.provenance == "mixed"
    assert point.severity == "critical"


def test_threat_geo_events_emit_directed_flow_when_both_endpoints_geolocate(monkeypatch):
    _disable_cache(monkeypatch)
    now = datetime.now(timezone.utc)

    event_sources = [
        {
            "src_ip": "8.8.8.8", "count": 10, "high": 10, "medium": 0, "last_seen": now,
            "geo_loc": "37.42,-122.08", "country": "US", "region": "California",
            "city": "Mountain View", "org": "Google LLC", "asn": "AS15169", "asn_org": "Google LLC",
        },
    ]
    event_destinations: list = []
    event_flows = [
        {
            "src_ip": "8.8.8.8", "dst_ip": "45.83.12.7", "count": 8, "high": 8, "medium": 0, "last_seen": now,
            "src_geo_loc": "37.42,-122.08", "src_country": "US", "src_region": "California", "src_city": "Mountain View",
        },
    ]
    flow_geo_rows = [
        {"ip": "45.83.12.7", "country": "NL", "region": "North Holland", "city": "Amsterdam", "loc": "52.37,4.89", "org": "EvilHost", "asn": "AS9999", "asn_org": "EvilHost"},
    ]

    db = _FakeDB([event_sources, event_destinations, [], event_flows, flow_geo_rows])
    payload = threat_map_service.get_threat_geo(db, since_minutes=60, limit=200, severity=None, source="events")

    assert len(payload.points) == 1
    assert len(payload.flows) == 1

    flow = payload.flows[0]
    assert flow.provenance == "event"
    assert flow.weight == 8
    assert flow.severity == "high"
    assert flow.origin is not None and flow.target is not None
    assert flow.origin.lat == pytest.approx(37.42)
    assert flow.target.lat == pytest.approx(52.37)
    assert flow.target.country == "NL"


def test_threat_geo_includes_home_endpoint_when_resolved(monkeypatch):
    monkeypatch.setattr(threat_map_service, "_cache_get_json", lambda key: None)
    monkeypatch.setattr(threat_map_service, "_cache_set_json", lambda key, payload, ttl: None)
    home = threat_map_service.ThreatGeoEndpoint(
        lat=-3.71, lon=-38.54, city="Fortaleza", country="BR", label="Fortaleza · BR", scope="home"
    )
    monkeypatch.setattr(threat_map_service, "_resolve_home_endpoint", lambda: home)

    db = _FakeDB([[], [], []])
    payload = threat_map_service.get_threat_geo(db, since_minutes=60, limit=200, severity=None, source="events")

    assert payload.points == []
    assert payload.home is not None
    assert payload.home.scope == "home"
    assert payload.home.label == "Fortaleza · BR"
    assert payload.home.lat == pytest.approx(-3.71)


def test_threat_geo_events_plot_ddos_top_src_and_recon_sources(monkeypatch):
    _disable_cache(monkeypatch)
    now = datetime.now(timezone.utc)

    event_sources = [
        {
            "src_ip": "5.45.207.1", "count": 3, "high": 0, "medium": 0, "low": 3, "last_seen": now,
            "geo_loc": None, "country": None, "region": None, "city": None, "org": None, "asn": None, "asn_org": None,
        },
    ]
    event_destinations: list = []
    dos_events = [
        {
            "dst_ip": "192.168.1.10",
            "vector": "udp_flood",
            "last_seen": now,
            "top_src": [
                {"ip": "45.83.12.7", "packets": 1000},
                {"ip": "80.66.76.10", "packets": 500},
                {"ip": "10.0.0.9", "packets": 999},
                {"ip": "254.228.246.123", "packets": 800},
            ],
        },
    ]
    geo_rows = [
        {"ip": "45.83.12.7", "country": "NL", "region": "North Holland", "city": "Amsterdam", "loc": "52.37,4.89", "org": "EvilHost", "asn": "AS9999", "asn_org": "EvilHost"},
        {"ip": "80.66.76.10", "country": "RU", "region": "Moscow", "city": "Moscow", "loc": "55.75,37.62", "org": "BadNet", "asn": "AS6666", "asn_org": "BadNet"},
        {"ip": "5.45.207.1", "country": "DE", "region": "Hesse", "city": "Frankfurt", "loc": "50.11,8.68", "org": "ScanCorp", "asn": "AS3333", "asn_org": "ScanCorp"},
    ]

    db = _FakeDB([event_sources, event_destinations, dos_events, geo_rows, []])
    payload = threat_map_service.get_threat_geo(db, since_minutes=60, limit=200, severity=None, source="events")

    assert payload.source == "events"
    assert payload.located_ips == 3
    assert payload.total_events == 1503

    by_country = {point.country: point for point in payload.points}
    assert set(by_country) == {"NL", "RU", "DE"}
    assert all(point.provenance == "event" and point.direction == "inbound" for point in payload.points)

    assert by_country["NL"].severity == "high"
    assert by_country["NL"].count == 1000
    assert by_country["RU"].severity == "high"
    assert by_country["DE"].severity == "low"
    assert by_country["DE"].count == 3

    plotted_ips = {ip.ip for point in payload.points for ip in point.top_ips}
    assert {"45.83.12.7", "80.66.76.10", "5.45.207.1"} <= plotted_ips
    assert "10.0.0.9" not in plotted_ips
    assert "254.228.246.123" not in plotted_ips

    assert payload.ddos_attacks == 1
    assert payload.ddos_located_sources == 2
    assert payload.ddos_unlocated_sources == 2


def test_threat_geo_reports_unlocated_ddos_when_sources_private(monkeypatch):
    _disable_cache(monkeypatch)
    now = datetime.now(timezone.utc)

    dos_events = [
        {
            "dst_ip": "10.0.0.9",
            "vector": "udp_flood",
            "last_seen": now,
            "top_src": [{"ip": "192.168.1.10", "packets": 500}, {"ip": "10.5.5.5", "packets": 300}],
        },
    ]

    db = _FakeDB([[], [], dos_events])
    payload = threat_map_service.get_threat_geo(db, since_minutes=60, limit=200, severity=None, source="events")

    assert payload.points == []
    assert payload.ddos_attacks == 1
    assert payload.ddos_located_sources == 0
    assert payload.ddos_unlocated_sources == 2
    assert payload.located_ips == 0
    assert payload.unlocated_ips == 0


def test_threat_geo_reports_unlocated_ddos_when_public_source_cache_cold(monkeypatch):
    _disable_cache(monkeypatch)
    now = datetime.now(timezone.utc)

    dos_events = [
        {
            "dst_ip": "10.0.0.9",
            "vector": "tcp_syn_flood",
            "last_seen": now,
            "top_src": [{"ip": "8.8.8.8", "packets": 9000}],
        },
    ]

    db = _FakeDB([[], [], dos_events, []])
    payload = threat_map_service.get_threat_geo(db, since_minutes=60, limit=200, severity=None, source="events")

    assert payload.points == []
    assert payload.ddos_attacks == 1
    assert payload.ddos_located_sources == 0
    assert payload.ddos_unlocated_sources == 1
    assert payload.located_ips == 0
    assert payload.unlocated_ips == 1
