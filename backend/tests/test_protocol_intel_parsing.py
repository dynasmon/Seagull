from __future__ import annotations

import base64

from app.shared.protocol_intel import analyzer
from app.shared.protocol_intel.analyzer import analyze_event, extract_l7_bytes


def test_extract_l7_bytes_from_nested_payload() -> None:
    payload = b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\n"
    extra = {"l7": {"payload_b64": base64.b64encode(payload).decode("ascii")}}
    out = extract_l7_bytes(extra, max_bytes=1024)
    assert out == payload


def test_analyze_event_prefers_agent_dns_evidence() -> None:
    patch = analyze_event(
        event_type="l7_flow",
        proto="udp",
        src_port=53000,
        dst_port=53,
        extra={
            "l7_protocol": "dns",
            "l7": {
                "protocol": "dns",
                "dns": {"qname": "malicious.example", "qtype": 1, "rcode": 3, "answers": ["203.0.113.9"]},
            },
        },
    )
    assert patch["app_proto"] == "dns"
    assert patch["app_proto_reason"] == "agent_evidence"
    assert patch["dns_qname"] == "malicious.example"
    assert patch["dns_qtype"] == 1
    assert patch["dns_rcode"] == 3
    assert patch["dns_answers"] == ["203.0.113.9"]


def test_analyze_event_http_response_status_and_direction() -> None:
    payload = b"HTTP/1.1 404 Not Found\r\nServer: nginx\r\n\r\n"
    patch = analyze_event(
        event_type="l7_flow",
        proto="tcp",
        src_port=80,
        dst_port=54000,
        extra={
            "l7_protocol": "http",
            "l7": {"payload_b64": base64.b64encode(payload).decode("ascii")},
        },
    )
    assert patch["app_proto"] == "http"
    assert patch["http_status"] == "404"
    assert patch["http_direction"] == "response"


def test_analyze_event_quic_hint_sets_ptype() -> None:
    patch = analyze_event(
        event_type="l7_flow",
        proto="udp",
        src_port=53000,
        dst_port=443,
        extra={"is_quic": True, "l7_protocol": "quic"},
    )
    assert patch["app_proto"] == "quic"
    assert patch["ja4_ptype"] == "q"


def test_analyze_event_does_not_guess_http_from_port_only() -> None:
    patch = analyze_event(
        event_type="l7_flow",
        proto="tcp",
        src_port=53000,
        dst_port=80,
        extra={},
    )
    assert "app_proto" not in patch
    assert "http_method" not in patch


def test_analyze_event_sets_http_only_from_real_http_evidence() -> None:
    payload = b"GET /health HTTP/1.1\r\nHost: api.example.org\r\nUser-Agent: curl/8.5\r\n\r\n"
    patch = analyze_event(
        event_type="l7_flow",
        proto="tcp",
        src_port=53000,
        dst_port=80,
        extra={"l7": {"payload_b64": base64.b64encode(payload).decode("ascii")}},
    )
    assert patch["app_proto"] == "http"
    assert patch["app_proto_reason"] == "parsed_http"
    assert patch["http_host"] == "api.example.org"
    assert patch["http_method"] == "GET"


def test_analyze_event_sets_tls_fields_from_real_tls_evidence(monkeypatch) -> None:
    monkeypatch.setattr(
        analyzer,
        "parse_tls_client_hello",
        lambda payload, extra=None: {
            "tls_sni": "login.example.net",
            "tls_alpn_first": "h2",
            "ja3": "ja3-value",
            "ja4": "ja4-value",
            "ja4_ptype": "q",
        },
    )

    patch = analyze_event(
        event_type="l7_flow",
        proto="udp",
        src_port=53000,
        dst_port=443,
        extra={
            "is_quic": True,
            "l7": {"payload_b64": base64.b64encode(b"clienthello").decode("ascii")},
        },
    )
    assert patch["app_proto"] == "quic"
    assert patch["app_proto_reason"] == "parsed_tls"
    assert patch["tls_sni"] == "login.example.net"
    assert patch["tls_alpn_first"] == "h2"
    assert patch["ja3"] == "ja3-value"
    assert patch["ja4"] == "ja4-value"
    assert patch["ja4_ptype"] == "q"
