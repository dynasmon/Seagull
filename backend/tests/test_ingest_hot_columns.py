from __future__ import annotations

import os

os.environ.setdefault("NETWATCH_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("NETWATCH_JWT_SECRET", "x" * 40)

from app.workers.ingest_worker import _event_hot_columns


def test_event_hot_columns_normalizes_protocol_fields() -> None:
    out = _event_hot_columns(
        event_type="dns",
        extra={
            "app_proto": "dns",
            "app_proto_reason": "payload_signature",
            "app_proto_conf_band": "high",
            "dns_qname": "EXAMPLE.ORG",
            "http_host": "WWW.EXAMPLE.ORG",
            "http_method": "get",
            "tls_sni": "API.EXAMPLE.ORG",
            "tls_alpn_first": "H2",
            "ja3": "ja3v",
            "ja4": "ja4v",
            "ja4_ptype": "u",
        },
    )

    assert out["dns_qname"] == "example.org"
    assert out["http_host"] == "www.example.org"
    assert out["http_method"] == "GET"
    assert out["tls_sni"] == "api.example.org"
    assert out["tls_alpn_first"] == "h2"
    assert out["ja4_ptype"] == "u"
    assert out["ssh_action"] is None
    assert out["ssh_username"] is None


def test_event_hot_columns_sets_ssh_fields_when_event_is_ssh_auth() -> None:
    out = _event_hot_columns(
        event_type="ssh_auth",
        extra={
            "action": "failed_password",
            "username": "root",
            "ja4": "ja4x",
        },
    )

    assert out["ssh_action"] == "failed_password"
    assert out["ssh_username"] == "root"
    assert out["ja4"] == "ja4x"
    assert out["ja4_ptype"] == "t"
