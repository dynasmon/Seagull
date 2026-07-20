from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Mapping

from app.core.cache import get_redis
from app.core.config import settings
from app.core.observability import incr_counter, log_event
from app.features.realtime.schemas import RealtimeEnvelope
from app.features.realtime.service import publish_realtime

logger = logging.getLogger("seagull.api.realtime.dashboards")

DASHBOARD_INVALIDATE_GATE_PREFIX = "seagull:realtime:dashboard:gate:"
DASHBOARD_INVALIDATE_REASON = "content_changed"

DashboardInvalidateOutcome = Literal["emitted", "throttled", "dropped", "disabled", "unmapped"]

_MAX_SCOPE_FIELDS = 12
_MAX_SCOPE_KEY_LENGTH = 48
_MAX_SCOPE_VALUE_LENGTH = 96


@dataclass(frozen=True)
class DashboardChannel:
    page: str
    topic: str
    event_type: str


DASHBOARD_CHANNELS: dict[str, DashboardChannel] = {
    channel.page: channel
    for channel in (
        DashboardChannel(page="overview", topic="overview", event_type="ui.overview.invalidate"),
        DashboardChannel(page="exposure_summary", topic="exposure", event_type="ui.exposure.invalidate"),
        DashboardChannel(
            page="network_topology_summary",
            topic="network_topology",
            event_type="ui.network_topology.invalidate",
        ),
        DashboardChannel(page="threat_map", topic="threat_map", event_type="ui.threat_map.invalidate"),
        DashboardChannel(page="vuln_summary", topic="vulnerabilities", event_type="ui.vulnerabilities.invalidate"),
        DashboardChannel(page="vuln_posture", topic="vulnerabilities", event_type="ui.vulnerabilities.invalidate"),
    )
}


def dashboard_channel(page: str) -> DashboardChannel | None:
    return DASHBOARD_CHANNELS.get(str(page or "").strip())


def dashboard_invalidate_enabled() -> bool:
    return bool(getattr(settings, "SEAGULL_REALTIME_DASHBOARD_INVALIDATE_ENABLED", True))


def dashboard_invalidate_min_interval_seconds() -> int:
    configured = int(getattr(settings, "SEAGULL_REALTIME_DASHBOARD_INVALIDATE_MIN_INTERVAL_SECONDS", 5) or 5)
    if configured < 1:
        return 1
    if configured > 300:
        return 300
    return configured


def _gate_key(page: str, scope_key: str) -> str:
    digest = hashlib.sha1(f"{page}:{scope_key}".encode("utf-8")).hexdigest()[:24]
    return f"{DASHBOARD_INVALIDATE_GATE_PREFIX}{page}:{digest}"


def _claim_gate(page: str, scope_key: str) -> bool:
    redis_client = get_redis()
    if redis_client is None:
        return True
    try:
        return bool(
            redis_client.set(
                _gate_key(page, scope_key),
                "1",
                ex=dashboard_invalidate_min_interval_seconds(),
                nx=True,
            )
        )
    except Exception:
        return True


def _normalize_scope(scope: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(scope, Mapping):
        return {}

    out: dict[str, Any] = {}
    for key, value in scope.items():
        if len(out) >= _MAX_SCOPE_FIELDS:
            break
        name = str(key or "").strip()[:_MAX_SCOPE_KEY_LENGTH]
        if not name:
            continue
        if value is None or isinstance(value, (bool, int, float)):
            out[name] = value
            continue
        out[name] = str(value)[:_MAX_SCOPE_VALUE_LENGTH]
    return out


def publish_dashboard_invalidate(
    *,
    page: str,
    version: str,
    scope_key: str,
    scope: Mapping[str, Any] | None = None,
    scope_label: str = "global",
    reason: str = DASHBOARD_INVALIDATE_REASON,
) -> DashboardInvalidateOutcome:
    channel = dashboard_channel(page)
    if channel is None:
        return "unmapped"

    if not dashboard_invalidate_enabled():
        return "disabled"

    if not _claim_gate(channel.page, scope_key):
        incr_counter("dashboard_invalidate_throttled_total", page=channel.page, reason="min_interval")
        return "throttled"

    payload: dict[str, Any] = {
        "reason": str(reason or DASHBOARD_INVALIDATE_REASON)[:64],
        "page": channel.page,
        "scope": channel.topic,
        "scope_params": _normalize_scope(scope),
        "version": str(version or "")[:96],
        "emitted_at": datetime.now(timezone.utc).isoformat(),
    }

    if not publish_realtime(channel.event_type, payload, topic=channel.topic):
        incr_counter("dashboard_invalidate_throttled_total", page=channel.page, reason="publish_failed")
        return "dropped"

    incr_counter("dashboard_invalidate_emitted_total", page=channel.page, scope=str(scope_label or "global"))
    log_event(
        logger,
        "info",
        "dashboard_invalidate_emitted",
        page=channel.page,
        topic=channel.topic,
        scope=str(scope_label or "global"),
        version=payload["version"],
    )
    return "emitted"


def record_dashboard_invalidate_delivery(envelope: RealtimeEnvelope) -> None:
    if envelope.mode != "invalidate":
        return
    payload = envelope.payload if isinstance(envelope.payload, dict) else {}
    page = str(payload.get("page") or "").strip()
    if not page or page not in DASHBOARD_CHANNELS:
        return
    incr_counter("dashboard_invalidate_delivered_total", page=page)
