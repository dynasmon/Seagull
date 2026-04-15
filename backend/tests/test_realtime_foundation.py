from __future__ import annotations

import json
import os

import pytest

os.environ.setdefault("NETWATCH_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("NETWATCH_JWT_SECRET", "x" * 40)

from app.core import realtime as core_realtime
from app.core.observability import snapshot_metrics
from app.features.realtime import service


class _FakeRedis:
    def __init__(self) -> None:
        self.cursor = 0
        self.stream_entries: list[tuple[str, dict[str, str]]] = []

    def incr(self, _key: str) -> int:
        self.cursor += 1
        return self.cursor

    def xadd(self, _key: str, fields: dict[str, str], maxlen: int | None = None, approximate: bool = True) -> str:
        _ = (maxlen, approximate)
        stream_id = f"{len(self.stream_entries) + 1}-0"
        self.stream_entries.append((stream_id, dict(fields)))
        return stream_id


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


def test_publish_portal_realtime_message_writes_stream_entry(monkeypatch) -> None:
    fake = _FakeRedis()
    monkeypatch.setattr(core_realtime, "get_redis", lambda **kwargs: fake)

    raw_message = (
        '{"version":2,"topic":"overview","type":"overview.patch","cursor":"0",'
        '"timestamp":"2026-01-01T00:00:00+00:00","scope":"portal:realtime","mode":"patch","payload":{}}'
    )
    ok = core_realtime.publish_portal_realtime_message(raw_message)

    assert ok is True
    assert len(fake.stream_entries) == 1
    _entry_id, fields = fake.stream_entries[0]
    assert fields["cursor"] == "1"
    assert fields["topic"] == "overview"

    envelope = json.loads(fields["envelope"])
    assert envelope["cursor"] == "1"
    assert envelope["topic"] == "overview"

    metrics = snapshot_metrics()
    assert any(item["name"] == "realtime_publish_topic_total" and item["labels"].get("topic") == "overview" for item in metrics["counters"])


def test_publish_realtime_rejects_non_json_payload() -> None:
    with pytest.raises(ValueError, match="JSON-serializable"):
        service.publish_realtime("overview.updated", {"bad": {1, 2, 3}})


def test_publish_realtime_rejects_non_object_payload() -> None:
    with pytest.raises(ValueError, match="payload must be an object"):
        service.publish_realtime("overview.updated", ["bad"])  # type: ignore[arg-type]


def test_coalesce_realtime_envelopes_records_counter() -> None:
    first = service.build_realtime_envelope(
        event_type="ui.overview.invalidate",
        payload={"reason": "cursor_gap"},
        cursor="10",
    )
    second = service.build_realtime_envelope(
        event_type="ui.overview.invalidate",
        payload={"reason": "replay_overflow"},
        cursor="11",
    )

    out = service.coalesce_realtime_envelopes([first, second])
    assert len(out) == 1
    assert out[0].payload["reason"] == "replay_overflow"

    metrics = snapshot_metrics()
    assert any(item["name"] == "realtime_delivery_coalesced_total" for item in metrics["counters"])
