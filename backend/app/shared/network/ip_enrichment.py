from __future__ import annotations

from typing import Any, Dict

from app.core.config import settings
from app.shared.network.ip_classification import classify_flow


def attach_ip_context(extra: Dict[str, Any], src_ip: Any, dst_ip: Any) -> None:
    """Inject ip_context into extra if not already present. Mutates extra in place."""
    if extra.get("ip_context"):
        return
    try:
        cidrs = settings.SEAGULL_INTERNAL_NETWORK_CIDRS or None
        extra["ip_context"] = classify_flow(src_ip, dst_ip, internal_cidrs=cidrs)
    except Exception:
        pass
