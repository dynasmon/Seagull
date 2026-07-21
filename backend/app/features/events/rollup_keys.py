from __future__ import annotations

from typing import Any

ROLLUP_NO_IP = ""
ROLLUP_NO_PORT = 0
ROLLUP_NO_PROTO = ""

ROLLUP_AGENT_ID_MAX_CHARS = 64
ROLLUP_EVENT_TYPE_MAX_CHARS = 32
ROLLUP_DST_IP_MAX_CHARS = 45
ROLLUP_PROTO_MAX_CHARS = 16


def rollup_agent_id(value: Any) -> str:
    return str(value or "").strip()[:ROLLUP_AGENT_ID_MAX_CHARS]


def rollup_event_type(value: Any) -> str:
    return str(value or "").strip()[:ROLLUP_EVENT_TYPE_MAX_CHARS] or "unknown"


def rollup_dst_ip(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ROLLUP_NO_IP
    return text[:ROLLUP_DST_IP_MAX_CHARS]


def rollup_dst_port(value: Any) -> int:
    if value is None:
        return ROLLUP_NO_PORT
    try:
        port = int(value)
    except (TypeError, ValueError):
        return ROLLUP_NO_PORT
    if port < 0 or port > 65535:
        return ROLLUP_NO_PORT
    return port


def rollup_proto(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ROLLUP_NO_PROTO
    return text[:ROLLUP_PROTO_MAX_CHARS]
