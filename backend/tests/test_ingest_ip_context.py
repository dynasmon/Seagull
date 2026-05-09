from __future__ import annotations

import json
import os

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

from app.shared.network.ip_enrichment import attach_ip_context
from app.features.events.domain.normalizers import (
    _ch_row_to_event,
    _hit_to_event,
    _row_to_event_safe,
)
from app.features.events.recent_feed import _compact_extra


# ---- attach_ip_context ----------------------------------------------------------

def test_attach_ip_context_adds_key() -> None:
    extra: dict = {}
    attach_ip_context(extra, "10.0.0.1", "8.8.8.8")
    assert "ip_context" in extra


def test_attach_ip_context_correct_shape() -> None:
    extra: dict = {}
    attach_ip_context(extra, "10.0.0.1", "8.8.8.8")
    ctx = extra["ip_context"]
    assert "src" in ctx and "dst" in ctx and "flow" in ctx
    assert ctx["flow"]["locality"] == "internal_to_public"
    assert ctx["src"]["scope"] == "private_address"
    assert ctx["dst"]["scope"] == "public_internet"
    assert ctx["src"]["is_internal"] is True
    assert ctx["dst"]["is_public"] is True


def test_attach_ip_context_does_not_overwrite_existing() -> None:
    sentinel: dict = {"already": "classified"}
    extra: dict = {"ip_context": sentinel}
    attach_ip_context(extra, "10.0.0.1", "8.8.8.8")
    assert extra["ip_context"] is sentinel


def test_attach_ip_context_none_ips_returns_unknown_locality() -> None:
    extra: dict = {}
    attach_ip_context(extra, None, None)
    assert extra["ip_context"]["flow"]["locality"] == "unknown"


def test_attach_ip_context_both_public() -> None:
    extra: dict = {}
    attach_ip_context(extra, "8.8.8.8", "1.1.1.1")
    assert extra["ip_context"]["flow"]["locality"] == "public_to_public"


def test_attach_ip_context_both_private() -> None:
    extra: dict = {}
    attach_ip_context(extra, "10.0.0.1", "192.168.1.1")
    assert extra["ip_context"]["flow"]["locality"] == "internal_to_internal"


def test_attach_ip_context_external_to_internal() -> None:
    extra: dict = {}
    attach_ip_context(extra, "8.8.8.8", "10.0.0.5")
    ctx = extra["ip_context"]
    assert ctx["flow"]["locality"] == "public_to_internal"
    assert ctx["flow"]["external_to_internal"] is True
    assert ctx["flow"]["internal_to_public"] is False


# ---- Ingest row building (both enqueue and fallback paths get the same extra) ---

def test_ingest_row_extra_contains_ip_context() -> None:
    # Mirrors the row-building pattern in ingest/service.py.
    # Both the Redis-enqueue and fallback direct-insert paths
    # reference the same row objects, so ip_context is present in both.
    extra: dict = {"severity": "high"}
    src_ip = "10.0.0.5"
    dst_ip = "8.8.8.8"

    attach_ip_context(extra, src_ip, dst_ip)

    row = [
        "agent-1",
        "dos_attack",
        1,
        "2026-05-09T00:00:00+00:00",
        src_ip,
        dst_ip,
        None,
        None,
        "tcp",
        0,
        extra,
    ]

    assert "ip_context" in row[10]
    assert row[10]["ip_context"]["flow"]["locality"] == "internal_to_public"


# ---- Read-time fallback: old rows without ip_context are classified on read -----

def _old_row(src_ip: str | None, dst_ip: str | None) -> dict:
    return {
        "id": 1,
        "agent_id": "agent-1",
        "event_type": "flow",
        "schema_version": 1,
        "timestamp": "2026-01-01T00:00:00+00:00",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": 12345,
        "dst_port": 443,
        "proto": "tcp",
        "bytes": 1024,
        "extra": {},
    }


def test_row_to_event_safe_classifies_old_row() -> None:
    ev = _row_to_event_safe(_old_row("192.168.1.5", "8.8.8.8"))
    assert ev is not None
    ctx = ev.extra.get("ip_context")
    assert ctx is not None
    assert ctx["flow"]["locality"] == "internal_to_public"
    assert ctx["src"]["scope"] == "private_address"
    assert ctx["dst"]["scope"] == "public_internet"


def test_row_to_event_safe_preserves_existing_ip_context() -> None:
    row = _old_row("10.0.0.1", "8.8.8.8")
    row["extra"] = {"ip_context": {"already": "present"}}
    ev = _row_to_event_safe(row)
    assert ev is not None
    assert ev.extra["ip_context"] == {"already": "present"}


def test_row_to_event_safe_classifies_public_to_internal() -> None:
    ev = _row_to_event_safe(_old_row("1.2.3.4", "10.0.0.5"))
    assert ev is not None
    ctx = ev.extra.get("ip_context")
    assert ctx is not None
    assert ctx["flow"]["locality"] == "public_to_internal"
    assert ctx["flow"]["external_to_internal"] is True


def test_ch_row_to_event_classifies_old_row() -> None:
    row = {
        "pg_event_id": 99,
        "agent_id": "agent-2",
        "event_type": "dns",
        "schema_version": 1,
        "timestamp": "2026-01-01T00:00:00+00:00",
        "src_ip": "172.16.0.5",
        "dst_ip": "8.8.8.8",
        "src_port": 55000,
        "dst_port": 53,
        "proto": "udp",
        "bytes": 100,
        "extra_json": json.dumps({"dns_qname": "example.com"}),
    }
    ev = _ch_row_to_event(row)
    assert ev is not None
    ctx = ev.extra.get("ip_context")
    assert ctx is not None
    assert ctx["src"]["scope"] == "private_address"
    assert ctx["dst"]["scope"] == "public_internet"
    assert ctx["flow"]["locality"] == "internal_to_public"


def test_ch_row_to_event_preserves_existing_ip_context() -> None:
    pre = {"src": {"scope": "public_internet"}, "dst": {}, "flow": {"locality": "public_to_public"}}
    row = {
        "pg_event_id": 1,
        "agent_id": "agent-2",
        "event_type": "flow",
        "schema_version": 1,
        "timestamp": "2026-01-01T00:00:00+00:00",
        "src_ip": "1.2.3.4",
        "dst_ip": "5.6.7.8",
        "extra_json": json.dumps({"ip_context": pre}),
    }
    ev = _ch_row_to_event(row)
    assert ev is not None
    assert ev.extra["ip_context"] == pre


def test_hit_to_event_classifies_old_row() -> None:
    hit = {
        "_id": "abc123",
        "_source": {
            "id": 0,
            "agent_id": "agent-3",
            "event_type": "ssh_auth",
            "schema_version": 1,
            "timestamp": "2026-01-01T00:00:00+00:00",
            "src_ip": "1.2.3.4",
            "dst_ip": "10.0.0.1",
            "src_port": 22222,
            "dst_port": 22,
            "proto": "tcp",
            "bytes": 512,
            "extra": {},
        },
    }
    ev = _hit_to_event(hit)
    assert ev is not None
    ctx = ev.extra.get("ip_context")
    assert ctx is not None
    assert ctx["flow"]["locality"] == "public_to_internal"
    assert ctx["dst"]["is_internal"] is True


def test_hit_to_event_preserves_existing_ip_context() -> None:
    pre = {"already": "classified"}
    hit = {
        "_id": "xyz",
        "_source": {
            "id": 0,
            "agent_id": "agent-3",
            "event_type": "flow",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "src_ip": "1.2.3.4",
            "dst_ip": "5.6.7.8",
            "extra": {"ip_context": pre},
        },
    }
    ev = _hit_to_event(hit)
    assert ev is not None
    assert ev.extra["ip_context"] == pre


# ---- Recent feed compaction preserves ip_context --------------------------------

def test_compact_extra_preserves_ip_context() -> None:
    ip_ctx = {
        "src": {"scope": "private_address", "label": "Private"},
        "dst": {"scope": "public_internet", "label": "Public"},
        "flow": {"locality": "internal_to_public"},
    }
    extra = {
        "severity": "high",
        "ip_context": ip_ctx,
        "irrelevant_large_field": "x" * 10000,
    }
    out = _compact_extra(extra)
    assert "ip_context" in out
    assert out["ip_context"] == ip_ctx
    assert "irrelevant_large_field" not in out


def test_compact_extra_without_ip_context_unchanged() -> None:
    extra = {"severity": "medium", "confidence": 90}
    out = _compact_extra(extra)
    assert out.get("severity") == "medium"
    assert "ip_context" not in out


def test_compact_extra_ip_context_survives_roundtrip() -> None:
    ip_ctx = {
        "src": {"scope": "private_address", "is_internal": True, "is_public": False},
        "dst": {"scope": "public_internet", "is_internal": False, "is_public": True},
        "flow": {"locality": "internal_to_public", "internal_to_public": True},
    }
    extra = {"ip_context": ip_ctx, "severity": "low"}
    out = _compact_extra(extra)
    serialized = json.dumps({"extra": out}, separators=(",", ":"))
    recovered = json.loads(serialized)
    assert recovered["extra"]["ip_context"]["flow"]["locality"] == "internal_to_public"
