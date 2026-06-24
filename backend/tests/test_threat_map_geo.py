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

    db = _FakeDB([sources, geo_rows, rule_rows])
    payload = threat_map_service.get_threat_geo(db, since_minutes=60, limit=200, severity=None)

    assert payload.located_ips == 3
    assert payload.unlocated_ips == 1
    assert payload.total_alerts == 20
    assert payload.meta.source == "postgres"
    assert payload.meta.cache_hit is False
    assert len(payload.points) == 2

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
    payload = threat_map_service.get_threat_geo(db, since_minutes=60, limit=200, severity=None)

    assert payload.points == []
    assert payload.located_ips == 0
    assert payload.unlocated_ips == 0
    assert payload.total_alerts == 0


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
