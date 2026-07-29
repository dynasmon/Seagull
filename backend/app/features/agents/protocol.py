from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import HTTPException, status

from app.core.observability import incr_counter

PROTOCOL_VERSION = 1
MIN_SUPPORTED_PROTOCOL = 1
MAX_SUPPORTED_PROTOCOL = 1
EVENT_SCHEMA_VERSION = 1


def descriptor() -> Dict[str, Any]:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "min_supported": MIN_SUPPORTED_PROTOCOL,
        "max_supported": MAX_SUPPORTED_PROTOCOL,
        "event_schema_version": EVENT_SCHEMA_VERSION,
        "server_time": datetime.now(timezone.utc).isoformat(),
    }


def ensure_supported(agent_protocol: Optional[int], *, context: str) -> None:
    if agent_protocol is None or int(agent_protocol) == 0:
        return
    version = int(agent_protocol)
    if MIN_SUPPORTED_PROTOCOL <= version <= MAX_SUPPORTED_PROTOCOL:
        return
    incr_counter("agent_protocol_unsupported_total", context=context)
    raise HTTPException(
        status_code=status.HTTP_426_UPGRADE_REQUIRED,
        detail={
            "error": "unsupported_protocol",
            "agent_protocol_version": version,
            "min_supported": MIN_SUPPORTED_PROTOCOL,
            "max_supported": MAX_SUPPORTED_PROTOCOL,
        },
    )
