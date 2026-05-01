from __future__ import annotations

import json
import os

import pytest

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

from app.core import realtime as core_realtime
from app.core.realtime import portal as realtime_portal
from app.core.observability import snapshot_metrics
from app.features.realtime import service


class _XRevrangeFailRedis:
    """Redis stub where xrevrange always raises but xrange succeeds — lets us verify the fallback."""

    def __init__(self, entries: list[tuple[str, dict[str, str]]]) -> None:
        self._entries = list(entries)

    def xrevrange(self, *args, **kwargs) -> list:
        raise RuntimeError("xrevrange unavailable")

    def xrange(
        self, _key: str, min: str = "-", max: str = "+", count: int | None = None
    ) -> list[tuple[str, dict[str, str]]]:
        _ = (min, max)
        if count is not None:
            return list(self._entries[:int(count)])
        return list(self._entries)


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
    monkeypatch.setattr(realtime_portal, "get_redis", lambda **kwargs: fake)

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


def test_coalesce_realtime_envelopes_preserves_cursor_ascending_order() -> None:
    """When an invalidate is coalesced, intermediate patches must not end up after it."""
    inv_5 = service.build_realtime_envelope(
        event_type="ui.overview.invalidate",
        payload={"reason": "first"},
        cursor="5",
    )
    patch_6 = service.build_realtime_envelope(
        event_type="ui.overview.kpi.patch",
        payload={"events_5m_delta": 3},
        cursor="6",
    )
    inv_7 = service.build_realtime_envelope(
        event_type="ui.overview.invalidate",
        payload={"reason": "second"},
        cursor="7",
    )

    out = service.coalesce_realtime_envelopes([inv_5, patch_6, inv_7])

    # Two envelopes must survive: the patch and the newer invalidate.
    assert len(out) == 2
    cursors = [int(e.cursor) for e in out]
    # Output must be cursor-ascending so consumers apply patch before invalidate.
    assert cursors == sorted(cursors), f"Output is not cursor-ascending: {cursors}"
    # The surviving invalidate must carry the higher cursor.
    inv_envelopes = [e for e in out if e.mode == "invalidate"]
    assert len(inv_envelopes) == 1
    assert inv_envelopes[0].cursor == "7"


def test_load_portal_realtime_replay_fallback_returns_newest_entries() -> None:
    """When xrevrange fails, the xrange fallback must return the NEWEST N entries, not the oldest."""
    all_entries = [
        (f"{i}-0", {"cursor": str(i), "topic": "overview", "envelope": json.dumps({
            "version": 2, "topic": "overview", "type": "overview.patch",
            "cursor": str(i), "timestamp": "2026-01-01T00:00:00+00:00",
            "scope": "portal:realtime", "mode": "patch", "payload": {},
        })})
        for i in range(1, 6)  # cursors 1..5
    ]

    redis_client = _XRevrangeFailRedis(all_entries)
    entries = core_realtime.load_portal_realtime_replay(redis_client, max_events=2)

    assert len(entries) == 2
    returned_cursors = sorted(e.cursor for e in entries)
    # Must be the newest two (cursors 4 and 5), not the oldest (1 and 2).
    assert returned_cursors == [4, 5], f"Expected newest [4,5], got {returned_cursors}"
