from __future__ import annotations

from typing import Any, Dict

from app.core.realtime import publish_portal_realtime_message
from app.features.realtime.schemas import RealtimeEnvelope


def build_realtime_envelope(*, event_type: str, payload: Dict[str, Any]) -> RealtimeEnvelope:
    return RealtimeEnvelope(type=event_type, payload=payload)


def publish_realtime(event_type: str, payload: Dict[str, Any]) -> bool:
    envelope = build_realtime_envelope(event_type=event_type, payload=payload)
    return publish_portal_realtime_message(envelope.as_json())
