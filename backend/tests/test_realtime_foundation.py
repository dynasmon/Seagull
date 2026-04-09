from __future__ import annotations

import json
import os

import pytest

os.environ.setdefault("NETWATCH_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("NETWATCH_JWT_SECRET", "x" * 40)

from app.core import realtime as core_realtime
from app.features.realtime import service
from app.features.realtime.schemas import RealtimeEnvelope


class _FakeRedis:
    def __init__(self) -> None:
        self.published: list[tuple[str, str]] = []

    def publish(self, channel: str, message: str) -> int:
        self.published.append((channel, message))
        return 0


def test_realtime_envelope_serialization_contract() -> None:
    envelope = RealtimeEnvelope(type="overview.updated", payload={"alerts": 3, "healthy": True})

    payload = json.loads(envelope.as_json())

    assert payload == {
        "version": 1,
        "type": "overview.updated",
        "timestamp": payload["timestamp"],
        "payload": {"alerts": 3, "healthy": True},
    }
    assert isinstance(payload["timestamp"], str)


def test_publish_portal_realtime_message_uses_single_channel(monkeypatch) -> None:
    fake = _FakeRedis()
    monkeypatch.setattr(core_realtime, "get_redis", lambda **kwargs: fake)

    raw_message = '{"version":1,"type":"x","timestamp":"2026-01-01T00:00:00+00:00","payload":{}}'
    ok = core_realtime.publish_portal_realtime_message(raw_message)

    assert ok is True
    assert fake.published == [
        (
            core_realtime.portal_realtime_channel(),
            raw_message,
        )
    ]


def test_publish_realtime_rejects_non_json_payload() -> None:
    with pytest.raises(ValueError, match="JSON-serializable"):
        service.publish_realtime("overview.updated", {"bad": {1, 2, 3}})


def test_publish_realtime_rejects_non_object_payload() -> None:
    with pytest.raises(ValueError, match="payload must be an object"):
        service.publish_realtime("overview.updated", ["bad"])  # type: ignore[arg-type]
