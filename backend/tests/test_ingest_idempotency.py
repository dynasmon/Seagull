from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from app.core.api import idempotency


class FakeRedis:
    def __init__(self):
        self.store: dict[str, str] = {}

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self.store:
            return False
        self.store[key] = value
        return True

    def get(self, key):
        return self.store.get(key)

    def setex(self, key, ttl, value):
        self.store[key] = value
        return True

    def delete(self, key):
        return int(self.store.pop(key, None) is not None)


@pytest.fixture
def fake_redis(monkeypatch):
    client = FakeRedis()
    monkeypatch.setattr(idempotency, "get_redis", lambda: client)
    return client


def _request(headers: dict[str, str]):
    return SimpleNamespace(headers=headers)


class TestReadBatchId:
    def test_accepts_uuid_shaped_header(self):
        request = _request({idempotency.BATCH_ID_HEADER: "0f6f8f2a-2b0a-4a3f-9d54-0c9b0a2b6f11"})
        assert idempotency.read_batch_id(request) == "0f6f8f2a-2b0a-4a3f-9d54-0c9b0a2b6f11"

    def test_rejects_short_or_malformed_values(self):
        assert idempotency.read_batch_id(_request({idempotency.BATCH_ID_HEADER: "abc"})) is None
        assert idempotency.read_batch_id(_request({idempotency.BATCH_ID_HEADER: "bad value!"})) is None
        assert idempotency.read_batch_id(_request({idempotency.BATCH_ID_HEADER: "x" * 200})) is None

    def test_missing_header_is_none(self):
        assert idempotency.read_batch_id(_request({})) is None
        assert idempotency.read_batch_id(None) is None


class TestRunOnce:
    def test_runs_handler_without_batch_id(self, fake_redis):
        calls = []
        result = idempotency.run_once(
            scope="ingest_events",
            agent_id="agent-1",
            batch_id=None,
            handler=lambda: calls.append(1) or {"received": 1},
        )
        assert result == {"received": 1}
        assert len(calls) == 1

    def test_second_delivery_of_same_batch_is_not_reprocessed(self, fake_redis):
        calls = []

        def handler():
            calls.append(1)
            return {"received": 3, "enqueued": 3}

        first = idempotency.run_once(
            scope="ingest_events",
            agent_id="agent-1",
            batch_id="batch-aaaaaaaa",
            handler=handler,
        )
        second = idempotency.run_once(
            scope="ingest_events",
            agent_id="agent-1",
            batch_id="batch-aaaaaaaa",
            handler=handler,
        )

        assert len(calls) == 1
        assert first == {"received": 3, "enqueued": 3}
        assert second == {"received": 3, "enqueued": 3, "duplicate": True}

    def test_same_batch_id_from_other_agent_is_processed(self, fake_redis):
        calls = []

        def handler():
            calls.append(1)
            return {"received": 1}

        idempotency.run_once(scope="ingest_events", agent_id="agent-1", batch_id="batch-aaaaaaaa", handler=handler)
        idempotency.run_once(scope="ingest_events", agent_id="agent-2", batch_id="batch-aaaaaaaa", handler=handler)
        assert len(calls) == 2

    def test_handler_failure_releases_claim(self, fake_redis):
        calls = []

        def failing():
            calls.append(1)
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError):
            idempotency.run_once(
                scope="ingest_events",
                agent_id="agent-1",
                batch_id="batch-aaaaaaaa",
                handler=failing,
            )

        with pytest.raises(RuntimeError):
            idempotency.run_once(
                scope="ingest_events",
                agent_id="agent-1",
                batch_id="batch-aaaaaaaa",
                handler=failing,
            )

        assert len(calls) == 2

    def test_duplicate_in_flight_returns_schema_safe_fallback(self, fake_redis):
        fake_redis.store[idempotency._key("ingest_vuln", "agent-1", "batch-aaaaaaaa")] = ""
        result = idempotency.run_once(
            scope="ingest_vuln",
            agent_id="agent-1",
            batch_id="batch-aaaaaaaa",
            handler=lambda: pytest.fail("handler must not run for duplicate"),
            duplicate_result={"received_findings": 5, "stored_findings": 0},
        )
        assert result == {"received_findings": 5, "stored_findings": 0, "duplicate": True}

    def test_falls_back_to_handler_when_redis_is_down(self, monkeypatch):
        monkeypatch.setattr(idempotency, "get_redis", lambda: None)
        calls = []
        for _ in range(2):
            idempotency.run_once(
                scope="ingest_events",
                agent_id="agent-1",
                batch_id="batch-aaaaaaaa",
                handler=lambda: calls.append(1),
            )
        assert len(calls) == 2

    def test_oversized_results_are_not_cached(self, fake_redis):
        payload = {"blob": "x" * 9000}
        idempotency.run_once(
            scope="ingest_events",
            agent_id="agent-1",
            batch_id="batch-aaaaaaaa",
            handler=lambda: payload,
        )
        stored = fake_redis.store[idempotency._key("ingest_events", "agent-1", "batch-aaaaaaaa")]
        assert stored == ""

    def test_cached_result_roundtrips_as_json(self, fake_redis):
        idempotency.run_once(
            scope="ingest_inventory",
            agent_id="agent-1",
            batch_id="batch-aaaaaaaa",
            handler=lambda: {"snapshot_id": 7},
        )
        stored = fake_redis.store[idempotency._key("ingest_inventory", "agent-1", "batch-aaaaaaaa")]
        assert json.loads(stored) == {"snapshot_id": 7}
