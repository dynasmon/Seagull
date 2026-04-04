from __future__ import annotations

import base64

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
