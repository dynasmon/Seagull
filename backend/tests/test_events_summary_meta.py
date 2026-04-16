from __future__ import annotations

import os
from datetime import datetime, timezone

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

from app.features.events import service


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def test_ssh_summary_cache_hit_marks_meta(monkeypatch) -> None:
    cached = {
        "generated_at": _iso_now(),
        "since_minutes": 60,
        "agent_id": "agent-a",
        "total_accepted": 1,
        "total_failed_password": 2,
        "total_invalid_user": 0,
        "total_actions": 3,
        "unique_source_ips": 1,
        "enriched_source_ips": 1,
        "recent_auth_events": [],
        "successful_logins": [],
        "failed_attempts": [],
        "invalid_user_attempts": [],
        "most_active_ips": [],
        "root_logins": [],
        "users_attempted": [],
        "sudo_recent": [],
        "meta": {
            "source": "clickhouse",
            "fallback_chain": ["clickhouse"],
            "degraded_reason": None,
            "source_freshness_seconds": 2,
            "query_latency_ms": 12.5,
            "cache_hit": False,
            "approximate": False,
            "query_window_start": _iso_now(),
            "query_window_end": _iso_now(),
        },
    }
    monkeypatch.setattr(service, "_cache_get_json", lambda _k: dict(cached))

    out = service.get_ssh_summary(db=object(), since_minutes=60, limit=20, agent_id="agent-a")
    assert out.meta is not None
    assert out.meta.source == "clickhouse"
    assert out.meta.cache_hit is True


def test_network_summary_cache_hit_marks_meta(monkeypatch) -> None:
    cached = {
        "generated_at": _iso_now(),
        "since_minutes": 60,
        "agent_id": "agent-a",
        "total_events": 5,
        "with_proto_metadata": 5,
        "dns_events": 3,
        "http_events": 1,
        "tls_events": 1,
        "app_protocols": [],
        "transport_protocols": [],
        "top_dst_ports": [],
        "top_src_ports": [],
        "app_proto_reasons": [],
        "app_proto_conf_bands": [],
        "ja4_ptypes": [],
        "http_methods": [],
        "top_dns_queries": [],
        "top_http_hosts": [],
        "top_tls_sni": [],
        "top_alpn": [],
        "top_ja4": [],
        "top_ja3": [],
        "meta": {
            "source": "elasticsearch",
            "fallback_chain": ["clickhouse", "elasticsearch"],
            "degraded_reason": "clickhouse_fallback:LookupError",
            "source_freshness_seconds": 4,
            "query_latency_ms": 18.0,
            "cache_hit": False,
            "approximate": False,
            "query_window_start": _iso_now(),
            "query_window_end": _iso_now(),
        },
    }
    monkeypatch.setattr(service, "_cache_get_json", lambda _k: dict(cached))

    out = service.get_protocol_intel_summary(db=object(), since_minutes=60, limit=25, agent_id="agent-a")
    assert out.meta is not None
    assert out.meta.source == "elasticsearch"
    assert out.meta.cache_hit is True
