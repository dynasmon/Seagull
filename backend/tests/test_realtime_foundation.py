from __future__ import annotations

import json
import os

import pytest

os.environ.setdefault("NETWATCH_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("NETWATCH_JWT_SECRET", "x" * 40)

from app.core import realtime as core_realtime
from app.features.realtime import service


class _FakeRedis:
    def __init__(self) -> None:
        self.cursor = 0
        self.published: list[tuple[str, str]] = []
        self.replay: list[tuple[str, str]] = []

    def incr(self, _key: str) -> int:
        self.cursor += 1
        return self.cursor

    def pipeline(self):
        parent = self

        class _Pipe:
            def __init__(self) -> None:
                self.ops: list[tuple[str, tuple]] = []

            def rpush(self, key: str, value: str):
                self.ops.append(("rpush", (key, value)))
                return self

            def ltrim(self, key: str, start: int, end: int):
                self.ops.append(("ltrim", (key, start, end)))
                return self

            def publish(self, channel: str, message: str):
                self.ops.append(("publish", (channel, message)))
                return self

            def execute(self):
                for op, args in self.ops:
                    if op == "rpush":
                        parent.replay.append((args[0], args[1]))
                    elif op == "publish":
                        parent.published.append((args[0], args[1]))
                return [1] * len(self.ops)

        return _Pipe()

    def publish(self, channel: str, message: str) -> int:
        self.published.append((channel, message))
        return 0


def test_realtime_envelope_serialization_contract() -> None:
    envelope = service.build_realtime_envelope(
        event_type="overview.patch",
        payload={"alerts": 3, "healthy": True},
        cursor="7",
    )

    payload = json.loads(envelope.as_json())

    assert payload == {
        "version": 2,
        "topic": "overview",
        "type": "overview.patch",
        "cursor": "7",
        "timestamp": payload["timestamp"],
        "scope": "portal:realtime",
        "mode": "patch",
        "payload": {"alerts": 3, "healthy": True},
    }
    assert isinstance(payload["timestamp"], str)


def test_publish_portal_realtime_message_uses_topic_channel_and_cursor(monkeypatch) -> None:
    fake = _FakeRedis()
    monkeypatch.setattr(core_realtime, "get_redis", lambda **kwargs: fake)

    raw_message = (
        '{"version":2,"topic":"overview","type":"overview.patch","cursor":"0",'
        '"timestamp":"2026-01-01T00:00:00+00:00","scope":"portal:realtime","mode":"patch","payload":{}}'
    )
    ok = core_realtime.publish_portal_realtime_message(raw_message)

    assert ok is True
    assert len(fake.published) == 1
    published = json.loads(fake.published[0][1])
    assert published["cursor"] == "1"
    assert fake.published == [
        (
            core_realtime.portal_realtime_channel("overview"),
            fake.published[0][1],
        )
    ]


def test_publish_realtime_rejects_non_json_payload() -> None:
    with pytest.raises(ValueError, match="JSON-serializable"):
        service.publish_realtime("overview.updated", {"bad": {1, 2, 3}})


def test_publish_realtime_rejects_non_object_payload() -> None:
    with pytest.raises(ValueError, match="payload must be an object"):
        service.publish_realtime("overview.updated", ["bad"])  # type: ignore[arg-type]
