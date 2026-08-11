from __future__ import annotations

from typing import Any

from app.features.events.storage_contract import fit_agent_id, fit_event_type, fit_ip, fit_port, fit_proto

ROLLUP_NO_IP = ""
ROLLUP_NO_PORT = 0
ROLLUP_NO_PROTO = ""
ROLLUP_UNKNOWN_EVENT_TYPE = "unknown"


def rollup_agent_id(value: Any) -> str:
    return fit_agent_id(value)


def rollup_event_type(value: Any) -> str:
    return fit_event_type(value) or ROLLUP_UNKNOWN_EVENT_TYPE


def rollup_dst_ip(value: Any) -> str:
    return fit_ip(value) or ROLLUP_NO_IP


def rollup_dst_port(value: Any) -> int:
    port = fit_port(value)
    return ROLLUP_NO_PORT if port is None else port


def rollup_proto(value: Any) -> str:
    return fit_proto(value) or ROLLUP_NO_PROTO
