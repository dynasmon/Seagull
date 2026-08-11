from __future__ import annotations

import os

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

import json
from dataclasses import asdict
from typing import Any, Dict, List

import pytest

from app.features.ingest.control import deadletter
from app.features.ingest.control.queue_keys import backlog_events_key, deadletter_key, queue_key


class _FakeRedis:
    def __init__(self) -> None:
        self.lists: Dict[str, List[str]] = {}
        self.counters: Dict[str, int] = {}

    def rpush(self, key: str, value: str) -> int:
        self.lists.setdefault(key, []).append(value)
        return len(self.lists[key])

    def lpush(self, key: str, value: str) -> int:
        self.lists.setdefault(key, []).insert(0, value)
        return len(self.lists[key])

    def lpop(self, key: str) -> Any:
        items = self.lists.get(key) or []
        return items.pop(0) if items else None

    def llen(self, key: str) -> int:
        return len(self.lists.get(key) or [])

    def lrange(self, key: str, start: int, end: int) -> List[str]:
        items = self.lists.get(key) or []
        return items[start : end + 1]

    def ltrim(self, key: str, start: int, end: int) -> None:
        items = self.lists.get(key) or []
        self.lists[key] = items[start:] if end == -1 else items[start : end + 1]

    def expire(self, key: str, seconds: int) -> None:
        return None

    def delete(self, key: str) -> int:
        return 1 if self.lists.pop(key, None) is not None else 0

    def incrby(self, key: str, amount: int) -> int:
        self.counters[key] = self.counters.get(key, 0) + int(amount)
        return self.counters[key]

    def pipeline(self) -> "_FakePipeline":
        return _FakePipeline(self)


class _FakePipeline:
    def __init__(self, client: _FakeRedis) -> None:
        self._client = client
        self._calls: List[Any] = []

    def __getattr__(self, name: str) -> Any:
        def _record(*args: Any, **kwargs: Any) -> "_FakePipeline":
            self._calls.append((name, args, kwargs))
            return self

        return _record

    def execute(self) -> List[Any]:
        results = [getattr(self._client, name)(*args, **kwargs) for name, args, kwargs in self._calls]
        self._calls.clear()
        return results


def _message(*, agent_id: str = "agent-a", received: int = 3, retries: int = 4) -> str:
    return json.dumps(
        {
            "v": 1,
            "received_at": "2026-08-11T12:00:00+00:00",
            "agent_id": agent_id,
            "mode": "normal",
            "storm_reason": "ok",
            "received": received,
            "_retry_count": retries,
            "hot_events": [["agent-a", "flow", 1, "2026-08-11T12:00:00+00:00"]] * received,
            "analytics_events": [],
            "warm_events": [],
            "rollups": [[]],
        },
        separators=(",", ":"),
    )


@pytest.fixture()
def redis(monkeypatch: pytest.MonkeyPatch) -> _FakeRedis:
    client = _FakeRedis()
    monkeypatch.setattr(deadletter, "get_redis", lambda: client)
    return client


def test_the_worker_write_and_the_operator_view_share_one_list(redis: _FakeRedis) -> None:
    deadletter.push(redis, _message())

    assert redis.llen(deadletter_key()) == 1
    assert deadletter.depth() == 1


def test_summaries_describe_the_batch_without_returning_its_events(redis: _FakeRedis) -> None:
    deadletter.push(redis, _message(agent_id="agent-b", received=7))

    page = deadletter.page(offset=0, limit=10)
    item = page.items[0]

    assert page.messages == 1
    assert item.agent_id == "agent-b"
    assert item.received == 7
    assert item.retries == 4
    assert item.hot_events == 7
    assert item.readable is True
    assert item.payload_bytes > 0
    assert not any(isinstance(value, (list, dict)) for value in asdict(item).values())


def test_redrive_returns_messages_to_the_queue_with_a_fresh_retry_budget(redis: _FakeRedis) -> None:
    deadletter.push(redis, _message(received=3))
    deadletter.push(redis, _message(received=5))

    outcome = deadletter.redrive(limit=10)

    assert outcome.requeued_messages == 2
    assert outcome.requeued_events == 8
    assert outcome.remaining_messages == 0
    assert redis.counters[backlog_events_key()] == 8

    requeued = [json.loads(raw) for raw in redis.lists[queue_key()]]
    assert all("_retry_count" not in message for message in requeued)
    assert {message["received"] for message in requeued} == {3, 5}


def test_redrive_honours_its_budget_and_keeps_the_rest(redis: _FakeRedis) -> None:
    for _ in range(3):
        deadletter.push(redis, _message(received=1))

    outcome = deadletter.redrive(limit=2)

    assert outcome.requeued_messages == 2
    assert outcome.remaining_messages == 1


def test_unreadable_messages_are_kept_instead_of_being_silently_dropped(redis: _FakeRedis) -> None:
    deadletter.push(redis, "{not json")
    deadletter.push(redis, _message(received=2))

    outcome = deadletter.redrive(limit=10)

    assert outcome.skipped_messages == 1
    assert outcome.requeued_messages == 1
    assert outcome.remaining_messages == 1
    assert redis.lists[deadletter_key()] == ["{not json"]

    page = deadletter.page(offset=0, limit=10)
    assert page.items[0].readable is False


def test_purge_drops_only_what_the_operator_asked_for(redis: _FakeRedis) -> None:
    for _ in range(3):
        deadletter.push(redis, _message())

    partial = deadletter.purge(limit=1)
    assert partial.purged_messages == 1
    assert partial.remaining_messages == 2

    everything = deadletter.purge()
    assert everything.purged_messages == 2
    assert everything.remaining_messages == 0


def test_the_list_never_grows_past_its_cap(redis: _FakeRedis) -> None:
    for _ in range(deadletter.DEADLETTER_MAX_MESSAGES + 25):
        deadletter.push(redis, _message())

    assert deadletter.depth() == deadletter.DEADLETTER_MAX_MESSAGES


def test_operations_report_an_outage_instead_of_an_empty_queue(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(deadletter, "get_redis", lambda: None)

    with pytest.raises(deadletter.DeadLetterUnavailable):
        deadletter.page(offset=0, limit=5)
    with pytest.raises(deadletter.DeadLetterUnavailable):
        deadletter.redrive(limit=5)
    with pytest.raises(deadletter.DeadLetterUnavailable):
        deadletter.purge()


def test_the_worker_write_never_raises_when_redis_is_gone() -> None:
    deadletter.push(None, _message())
