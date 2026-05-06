from __future__ import annotations

import os
from datetime import datetime, timezone
from types import SimpleNamespace

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

from app.features.events import service
from app.features.events.models import NetEventModel
from app.features.events.schemas import NetEventDB
from app.workers.indexing import elasticsearch as es_indexer


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class _MappingsOneResult:
    def __init__(self, row):
        self._row = row

    def mappings(self):
        return self

    def one(self):
        return self._row


class _AllResult:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


def test_row_to_event_safe_merges_protocol_fields_into_extra() -> None:
    row = {
        "id": 42,
        "agent_id": "agent-a",
        "event_type": "l7_flow",
        "schema_version": 1,
        "timestamp": _utc_now().isoformat(),
        "src_ip": "10.0.0.10",
        "dst_ip": "203.0.113.10",
        "src_port": 53000,
        "dst_port": 443,
        "proto": "tcp",
        "bytes": 123,
        "extra": {},
        "app_proto": "tls",
        "app_proto_reason": "parsed_tls",
        "app_proto_conf_band": "80-100",
        "tls_sni": "login.example.net",
        "tls_alpn_first": "h2",
        "ja3": "ja3v",
        "ja4": "ja4v",
        "ja4_ptype": "q",
    }

    out = service._row_to_event_safe(row)

    assert out is not None
    assert out.extra["app_proto"] == "tls"
    assert out.extra["app_proto_reason"] == "parsed_tls"
    assert out.extra["app_proto_conf_band"] == "80-100"
    assert out.extra["tls_sni"] == "login.example.net"
    assert out.extra["tls_alpn_first"] == "h2"
    assert out.extra["ja3"] == "ja3v"
    assert out.extra["ja4"] == "ja4v"
    assert out.extra["ja4_ptype"] == "q"


def test_hit_to_event_merges_protocol_fields_into_extra() -> None:
    hit = {
        "_id": "99",
        "_source": {
            "id": 99,
            "agent_id": "agent-b",
            "event_type": "l7_flow",
            "schema_version": 1,
            "timestamp": _utc_now().isoformat(),
            "src_ip": "10.0.0.20",
            "dst_ip": "198.51.100.20",
            "src_port": 53111,
            "dst_port": 80,
            "proto": "tcp",
            "bytes": 321,
            "extra": {},
            "app_proto": "http",
            "app_proto_reason": "parsed_http",
            "http_host": "api.example.org",
            "http_method": "GET",
        },
    }

    out = service._hit_to_event(hit)

    assert out.extra["app_proto"] == "http"
    assert out.extra["app_proto_reason"] == "parsed_http"
    assert out.extra["http_host"] == "api.example.org"
    assert out.extra["http_method"] == "GET"


def test_ch_row_to_event_merges_protocol_fields_into_extra() -> None:
    row = {
        "pg_event_id": 123,
        "agent_id": "agent-ch",
        "event_type": "l7_flow",
        "schema_version": 1,
        "timestamp": _utc_now().isoformat(),
        "src_ip": "10.0.0.40",
        "dst_ip": "203.0.113.40",
        "src_port": 54001,
        "dst_port": 443,
        "proto": "udp",
        "bytes": 256,
        "extra_json": "{}",
        "app_proto": "quic",
        "app_proto_reason": "agent_evidence",
        "tls_sni": "cdn.example.net",
        "tls_alpn_first": "h3",
        "ja4": "ja4-quic",
        "ja4_ptype": "q",
    }

    out = service._ch_row_to_event(row)

    assert out is not None
    assert out.extra["app_proto"] == "quic"
    assert out.extra["app_proto_reason"] == "agent_evidence"
    assert out.extra["tls_sni"] == "cdn.example.net"
    assert out.extra["tls_alpn_first"] == "h3"
    assert out.extra["ja4"] == "ja4-quic"
    assert out.extra["ja4_ptype"] == "q"


def test_es_to_doc_includes_protocol_summary_fields() -> None:
    doc = es_indexer._to_doc(
        {
            "id": 7,
            "agent_id": "agent-c",
            "event_type": "l7_flow",
            "schema_version": 1,
            "timestamp": _utc_now(),
            "src_ip": "10.0.0.30",
            "dst_ip": "192.0.2.30",
            "src_port": 54000,
            "dst_port": 443,
            "proto": "tcp",
            "bytes": 512,
            "extra": {
                "app_proto": "tls",
                "app_proto_reason": "parsed_tls",
                "app_proto_conf_band": "80-100",
                "tls_sni": "login.example.net",
                "tls_alpn_first": "h2",
                "ja3": "ja3v",
                "ja4": "ja4v",
                "ja4_ptype": "t",
            },
        }
    )

    assert doc["app_proto"] == "tls"
    assert doc["app_proto_reason"] == "parsed_tls"
    assert doc["app_proto_conf_band"] == "80-100"
    assert doc["tls_sni"] == "login.example.net"
    assert doc["tls_alpn_first"] == "h2"
    assert doc["ja3"] == "ja3v"
    assert doc["ja4"] == "ja4v"
    assert doc["ja4_ptype"] == "t"


def test_network_summary_falls_back_to_postgres_when_clickhouse_protocol_metadata_is_partial(monkeypatch) -> None:
    monkeypatch.setattr(service, "_cache_get_json", lambda _k: None)
    monkeypatch.setattr(service, "_cache_set_json", lambda *_a, **_k: None)
    monkeypatch.setattr(service, "observe_hist", lambda *_a, **_k: None)
    monkeypatch.setattr(service, "_ch_client_or_none", lambda: object())
    monkeypatch.setattr(service, "_es_client_or_none", lambda: None)
    monkeypatch.setattr(service, "_pg_has_newer_event", lambda *args, **kwargs: False)
    monkeypatch.setattr(service, "clickhouse_events_table_ref", lambda: "seagull.events")
    monkeypatch.setattr(service, "_missing_protocol_summary_field", lambda *_a, **kwargs: "app_proto_reason" if "app_proto_reason" in kwargs["field_presence"] else None)

    def fake_ch_query_dicts(_ch, sql, params=None):
        if "count() AS total_events" in sql:
            return [{"total_events": 5, "with_proto_metadata": 5, "dns_events": 1, "http_events": 0, "tls_events": 4}]
        if "max(timestamp) AS last_ts" in sql:
            return [{"last_ts": _utc_now().isoformat()}]
        if "GROUP BY ja4" in sql:
            return [{"ja4": "ja4v", "ptype": "q", "c": 2}]
        return []

    def fake_ch_top_counts(_ch, *, key_expr, **_kwargs):
        if "app_proto_reason" in key_expr:
            return []
        if "app_proto_conf_band" in key_expr:
            return [service.ProtoCount(key="80-100", count=5)]
        if "ifNull(d.app_proto" in key_expr:
            return [service.ProtoCount(key="quic", count=5)]
        if "http_method" in key_expr:
            return []
        if "dns_qname" in key_expr:
            return [service.ProtoCount(key="example.org", count=1)]
        if "http_host" in key_expr:
            return []
        if "tls_sni" in key_expr:
            return [service.ProtoCount(key="login.example.net", count=4)]
        if "tls_alpn_first" in key_expr:
            return [service.ProtoCount(key="h2", count=4)]
        if "ja4_ptype" in key_expr:
            return [service.ProtoCount(key="q", count=5)]
        if "ifNull(d.ja3" in key_expr:
            return [service.ProtoCount(key="ja3v", count=3)]
        if "lowerUTF8(ifNull(d.proto" in key_expr:
            return [service.ProtoCount(key="udp", count=5)]
        if "toString(d.dst_port)" in key_expr:
            return [service.ProtoCount(key="443", count=5)]
        if "toString(d.src_port)" in key_expr:
            return [service.ProtoCount(key="53000", count=5)]
        return []

    pg_results = iter(
        [
            _MappingsOneResult({"total_events": 5, "with_proto_metadata": 5, "dns_events": 1, "http_events": 0, "tls_events": 4}),
            _AllResult([SimpleNamespace(key="quic", count=5)]),
            _AllResult([SimpleNamespace(key="udp", count=5)]),
            _AllResult([SimpleNamespace(key="443", count=5)]),
            _AllResult([SimpleNamespace(key="53000", count=5)]),
            _AllResult([SimpleNamespace(key="parsed_tls", count=4)]),
            _AllResult([SimpleNamespace(key="80-100", count=5)]),
            _AllResult([SimpleNamespace(key="q", count=5)]),
            _AllResult([]),
            _AllResult([SimpleNamespace(qname="example.org", risk=5, count=1)]),
            _AllResult([]),
            _AllResult([SimpleNamespace(key="login.example.net", count=4)]),
            _AllResult([SimpleNamespace(key="h2", count=4)]),
            _AllResult([SimpleNamespace(ja4="ja4v", ptype="q", count=2)]),
            _AllResult([SimpleNamespace(key="ja3v", count=3)]),
        ]
    )

    monkeypatch.setattr(service, "_ch_query_dicts", fake_ch_query_dicts)
    monkeypatch.setattr(service, "_ch_top_counts", fake_ch_top_counts)
    monkeypatch.setattr(service.repository, "run", lambda db, stmt: next(pg_results))

    out = service.get_protocol_intel_summary(db=object(), since_minutes=60, limit=10, agent_id="agent-z")

    assert out.meta is not None
    assert out.meta.source == "postgres"
    assert out.app_protocols[0].key == "quic"
    assert out.app_proto_reasons[0].key == "parsed_tls"
    assert out.top_tls_sni[0].key == "login.example.net"
    assert out.top_alpn[0].key == "h2"
    assert out.top_ja4[0].ja4 == "ja4v"


class _ScalarRows:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)


def test_event_stream_snapshot_normalizes_postgres_rows(monkeypatch) -> None:
    now = _utc_now()
    pg_row = NetEventModel(
        id=77,
        agent_id="agent-pg",
        event_type="l7_flow",
        schema_version=1,
        timestamp=now,
        src_ip="10.0.0.5",
        dst_ip="203.0.113.50",
        src_port=55000,
        dst_port=443,
        proto="tcp",
        bytes=2048,
        extra={},
        app_proto="tls",
        app_proto_reason="parsed_tls",
        tls_sni="console.example.net",
    )

    monkeypatch.setattr(service, "fetch_recent_feed_events", lambda **_kwargs: [])
    monkeypatch.setattr(service, "_ch_client_or_none", lambda: None)
    monkeypatch.setattr(service, "_es_client_or_none", lambda: None)
    monkeypatch.setattr(service, "recent_feed_health", lambda **_kwargs: {"freshness_seconds": 2})
    monkeypatch.setattr(service.repository, "run", lambda _db, _stmt: _ScalarRows([pg_row]))

    out = service.get_event_stream_snapshot(db=object(), limit=10, since_minutes=60)

    assert len(out.items) == 1
    assert isinstance(out.items[0], NetEventDB)
    assert out.items[0].id == 77
    assert out.items[0].extra["app_proto"] == "tls"
    assert out.items[0].extra["app_proto_reason"] == "parsed_tls"
    assert out.items[0].extra["tls_sni"] == "console.example.net"


def test_get_recent_events_postgres_fallback_honors_since_minutes(monkeypatch) -> None:
    now = _utc_now()
    stale = NetEventModel(
        id=10,
        agent_id="agent-pg",
        event_type="ssh_auth",
        schema_version=1,
        timestamp=now - service.timedelta(minutes=90),
        src_ip="10.0.0.10",
        dst_ip="203.0.113.10",
        src_port=50000,
        dst_port=22,
        proto="tcp",
        bytes=128,
        extra={"action": "failed_password"},
    )
    fresh = NetEventModel(
        id=11,
        agent_id="agent-pg",
        event_type="ssh_auth",
        schema_version=1,
        timestamp=now - service.timedelta(minutes=5),
        src_ip="10.0.0.11",
        dst_ip="203.0.113.11",
        src_port=50001,
        dst_port=22,
        proto="tcp",
        bytes=256,
        extra={"action": "accepted"},
    )

    captured: dict[str, object] = {}

    def _fake_run(_db, stmt):
        captured["stmt"] = stmt
        return _ScalarRows([fresh, stale])

    monkeypatch.setattr(service, "fetch_recent_feed_events", lambda **_kwargs: [])
    monkeypatch.setattr(service, "_ch_client_or_none", lambda: None)
    monkeypatch.setattr(service, "_es_client_or_none", lambda: None)
    monkeypatch.setattr(service.repository, "run", _fake_run)

    out = service.get_recent_events(db=object(), limit=10, since_minutes=30)

    assert [item.id for item in out] == [11]
    assert "timestamp" in str(captured["stmt"])
