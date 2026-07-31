from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import HTTPException, status

from app.core.observability import incr_counter

_CONTRACTS_DIR = Path(__file__).with_name("contracts")


def _load_json(name: str) -> Dict[str, Any]:
    path = _CONTRACTS_DIR / name
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"unable to load agent contract {path}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"agent contract {path} must contain an object")
    return value


def _required_int(source: Dict[str, Any], name: str) -> int:
    value = source.get(name)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise RuntimeError(f"agent contract field {name} must be a positive integer")
    return value


CONTRACT = _load_json("protocol-v1.json")
COMPATIBILITY = _load_json("compatibility.json")
SERVER_COMPATIBILITY = COMPATIBILITY.get("server")
if not isinstance(SERVER_COMPATIBILITY, dict):
    raise RuntimeError("agent compatibility contract must define the server window")

PROTOCOL_VERSION = _required_int(CONTRACT, "protocol_version")
EVENT_SCHEMA_VERSION = _required_int(CONTRACT, "event_schema_version")
MIN_EVENT_SCHEMA = _required_int(SERVER_COMPATIBILITY.get("accepts_event_schema", {}), "min")
MAX_EVENT_SCHEMA = _required_int(SERVER_COMPATIBILITY.get("accepts_event_schema", {}), "max")
MIN_SUPPORTED_PROTOCOL = _required_int(SERVER_COMPATIBILITY, "oldest_supported_agent_protocol")
MAX_SUPPORTED_PROTOCOL = _required_int(SERVER_COMPATIBILITY, "newest_supported_agent_protocol")


def descriptor() -> Dict[str, Any]:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "min_supported": MIN_SUPPORTED_PROTOCOL,
        "max_supported": MAX_SUPPORTED_PROTOCOL,
        "event_schema_version": EVENT_SCHEMA_VERSION,
        "min_event_schema": MIN_EVENT_SCHEMA,
        "max_event_schema": MAX_EVENT_SCHEMA,
        "server_time": datetime.now(timezone.utc).isoformat(),
    }


def _unsupported_detail(
    *,
    kind: str,
    message: str,
    agent_protocol_version: int = 0,
    agent_event_schema_version: int = 0,
) -> Dict[str, Any]:
    return {
        "error": "unsupported_protocol",
        "kind": kind,
        "agent_protocol_version": agent_protocol_version,
        "server_protocol_version": PROTOCOL_VERSION,
        "min_supported": MIN_SUPPORTED_PROTOCOL,
        "max_supported": MAX_SUPPORTED_PROTOCOL,
        "agent_event_schema_version": agent_event_schema_version,
        "event_schema_version": EVENT_SCHEMA_VERSION,
        "min_event_schema": MIN_EVENT_SCHEMA,
        "max_event_schema": MAX_EVENT_SCHEMA,
        "message": message,
    }


def ensure_supported(agent_protocol: Optional[int], *, context: str) -> None:
    version = PROTOCOL_VERSION if agent_protocol is None else int(agent_protocol)
    if MIN_SUPPORTED_PROTOCOL <= version <= MAX_SUPPORTED_PROTOCOL:
        return
    kind = "protocol_version_too_old" if version < MIN_SUPPORTED_PROTOCOL else "protocol_version_too_new"
    incr_counter("agent_protocol_unsupported_total", context=context, kind=kind)
    raise HTTPException(
        status_code=status.HTTP_426_UPGRADE_REQUIRED,
        detail=_unsupported_detail(
            kind=kind,
            message=(
                f"agent protocol {version} is outside the supported "
                f"window {MIN_SUPPORTED_PROTOCOL}-{MAX_SUPPORTED_PROTOCOL}"
            ),
            agent_protocol_version=version,
        ),
    )


def ensure_event_schema(agent_event_schema: Optional[int], *, context: str) -> None:
    version = EVENT_SCHEMA_VERSION if agent_event_schema is None else int(agent_event_schema)
    if MIN_EVENT_SCHEMA <= version <= MAX_EVENT_SCHEMA:
        return
    incr_counter("agent_event_schema_unsupported_total", context=context)
    raise HTTPException(
        status_code=status.HTTP_426_UPGRADE_REQUIRED,
        detail=_unsupported_detail(
            kind="event_schema_unsupported",
            message=f"event schema {version} is outside the supported window {MIN_EVENT_SCHEMA}-{MAX_EVENT_SCHEMA}",
            agent_event_schema_version=version,
        ),
    )
