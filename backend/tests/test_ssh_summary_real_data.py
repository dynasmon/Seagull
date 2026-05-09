from __future__ import annotations

import os
from datetime import datetime, timezone

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

from app.features.events import api as events_api


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def mappings(self):
        return self

    def all(self):
        return self._rows

    def one(self):
        if isinstance(self._rows, list):
            return self._rows[0]
        return self._rows


class _FakeDB:
    def __init__(self):
        now = datetime.now(timezone.utc)
        self._responses = [
            {"total_accepted": 3, "total_failed_password": 7, "total_invalid_user": 2, "unique_source_ips": 4, "enriched_source_ips": 3},
            [
                {
                    "timestamp": now,
                    "agent_id": "agent-1",
                    "action": "failed_password",
                    "src_ip": "203.0.113.10",
                    "username": "root",
                    "geo_country": "BR",
                    "geo_org": "Example ISP",
                    "asn": "AS64500",
                    "asn_org": "Example ISP",
                }
            ],
            [{"src_ip": "198.51.100.1", "count": 3, "geo_country": "BR", "geo_org": "Org A", "asn": "AS1", "asn_org": "Org A"}],
            [{"src_ip": "203.0.113.10", "count": 7, "geo_country": "BR", "geo_org": "Example ISP", "asn": "AS64500", "asn_org": "Example ISP"}],
            [{"src_ip": "198.51.100.77", "count": 2, "geo_country": None, "geo_org": None, "asn": None, "asn_org": None}],
            [{"src_ip": "203.0.113.10", "count": 7, "geo_country": "BR", "geo_org": "Example ISP", "asn": "AS64500", "asn_org": "Example ISP"}],
            [
                {
                    "timestamp": now,
                    "agent_id": "agent-1",
                    "src_ip": "198.51.100.2",
                    "username": "root",
                    "geo_country": "BR",
                    "geo_org": "Org B",
                    "asn": "AS2",
                    "asn_org": "Org B",
                }
            ],
            [{"username": "root", "count": 5}],
            [{"timestamp": now, "agent_id": "agent-1", "username": "ubuntu", "target_user": "root", "command": "systemctl restart ssh", "tty": "pts/0", "pwd": "/root"}],
        ]

    def execute(self, stmt):
        if not self._responses:
            raise AssertionError("unexpected extra query execution")
        return _FakeResult(self._responses.pop(0))

    def close(self):
        return None


class _FakeDBInternalIP:
    def __init__(self):
        now = datetime.now(timezone.utc)
        self._responses = [
            {"total_accepted": 0, "total_failed_password": 1, "total_invalid_user": 0, "unique_source_ips": 1, "enriched_source_ips": 0},
            [
                {
                    "timestamp": now,
                    "agent_id": "agent-1",
                    "action": "failed_password",
                    "src_ip": "192.168.1.100",
                    "username": "root",
                    "geo_country": None,
                    "geo_org": None,
                    "asn": None,
                    "asn_org": None,
                }
            ],
            [],
            [{"src_ip": "192.168.1.100", "count": 1, "geo_country": None, "geo_org": None, "asn": None, "asn_org": None}],
            [],
            [{"src_ip": "192.168.1.100", "count": 1, "geo_country": None, "geo_org": None, "asn": None, "asn_org": None}],
            [],
            [],
            [],
        ]

    def execute(self, stmt):
        if not self._responses:
            raise AssertionError("unexpected extra query execution")
        return _FakeResult(self._responses.pop(0))

    def close(self):
        return None


def test_ssh_summary_internal_ip_has_classification_fields(monkeypatch):
    monkeypatch.setattr(events_api, "_cache_get_json", lambda key: None)
    monkeypatch.setattr(events_api, "_cache_set_json", lambda key, payload, ttl: None)
    monkeypatch.setattr(events_api, "_ch_client_or_none", lambda: None)
    monkeypatch.setattr(events_api, "_es_client_or_none", lambda: None)
    monkeypatch.setattr(events_api, "SessionLocal", lambda: _FakeDBInternalIP())

    payload = events_api.get_ssh_summary(since_minutes=60, limit=50, agent_id=None)

    assert len(payload.recent_auth_events) == 1
    evt = payload.recent_auth_events[0]
    assert evt.src_ip == "192.168.1.100"
    assert evt.src_ip_scope == "private_address"
    assert evt.src_ip_label == "Private"
    assert evt.src_is_internal is True
    assert evt.src_is_public is False

    assert len(payload.failed_attempts) == 1
    stat = payload.failed_attempts[0]
    assert stat.src_ip_scope == "private_address"
    assert stat.src_is_internal is True
    assert stat.src_is_public is False

    assert len(payload.most_active_ips) == 1
    active = payload.most_active_ips[0]
    assert active.src_ip_scope == "private_address"


def test_ssh_summary_returns_real_totals_and_recent_events(monkeypatch):
    monkeypatch.setattr(events_api, "_cache_get_json", lambda key: None)
    monkeypatch.setattr(events_api, "_cache_set_json", lambda key, payload, ttl: None)
    monkeypatch.setattr(events_api, "_ch_client_or_none", lambda: None)
    monkeypatch.setattr(events_api, "_es_client_or_none", lambda: None)
    monkeypatch.setattr(events_api, "SessionLocal", lambda: _FakeDB())

    payload = events_api.get_ssh_summary(since_minutes=60, limit=50, agent_id=None)

    assert payload.total_accepted == 3
    assert payload.total_failed_password == 7
    assert payload.total_invalid_user == 2
    assert payload.total_actions == 12
    assert payload.unique_source_ips == 4
    assert payload.enriched_source_ips == 3
    assert len(payload.recent_auth_events) == 1
    assert payload.recent_auth_events[0].src_ip == "203.0.113.10"
    assert payload.recent_auth_events[0].action == "failed_password"
    assert payload.failed_attempts[0].count == 7
