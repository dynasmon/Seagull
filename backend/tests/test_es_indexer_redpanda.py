from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

import pytest

from app.workers.indexing import es_redpanda
from app.workers.indexing.es_bootstrap import ESConfig
from app.workers.indexing.es_redpanda import ESRedpandaConfig, load_redpanda_config
from app.workers.manager import GROUPS, ChildSpec


class _FakeMessage:
    def __init__(self, event: Optional[Dict[str, Any]], *, partition: int = 0, offset: int = 0, raw: Optional[bytes] = None) -> None:
        self._event = event
        self._partition = partition
        self._offset = offset
        self._raw = raw

    def error(self) -> None:
        return None

    def value(self) -> bytes:
        if self._raw is not None:
            return self._raw
        return json.dumps({"schema_version": 1, "produced_at": "2026-07-13T00:00:00+00:00", "event": self._event}).encode()

    def partition(self) -> int:
        return self._partition

    def offset(self) -> int:
        return self._offset


class _FakeConsumer:
    def __init__(self, batches: List[List[_FakeMessage]]) -> None:
        self.batches = list(batches)
        self.commits: List[bool] = []
        self.paused = 0
        self.resumed = 0
        self.polls = 0

    def consume(self, num_messages: int, timeout: float) -> List[_FakeMessage]:
        if self.batches:
            return self.batches.pop(0)
        return []

    def commit(self, asynchronous: bool = True) -> None:
        self.commits.append(asynchronous)

    def assignment(self) -> List[Any]:
        return []

    def position(self, _partitions: List[Any]) -> List[Any]:
        return []

    def pause(self, _partitions: List[Any]) -> None:
        self.paused += 1

    def resume(self, _partitions: List[Any]) -> None:
        self.resumed += 1

    def poll(self, _timeout: float = 0.0) -> None:
        self.polls += 1
        return None


class _FakeDlqProducer:
    def __init__(self) -> None:
        self.published: List[Dict[str, Any]] = []
        self.flushes = 0

    def publish(
        self,
        topic: str,
        *,
        key: str,
        event: Mapping[str, Any],
        on_result: Optional[Callable[[bool], None]] = None,
        produced_at: Optional[str] = None,
    ) -> bool:
        self.published.append({"topic": topic, "key": key, "event": dict(event)})
        if on_result is not None:
            on_result(True)
        return True

    def flush(self, _timeout: float = 10.0) -> int:
        self.flushes += 1
        return 0


class _BulkScript:
    def __init__(self, outcomes: List[Any]) -> None:
        self.outcomes = list(outcomes)
        self.calls: List[List[Dict[str, Any]]] = []

    def __call__(self, _es: Any, actions: List[Dict[str, Any]], *, request_timeout: int) -> Tuple[int, List[Any]]:
        self.calls.append(actions)
        outcome = self.outcomes.pop(0) if self.outcomes else {}
        if isinstance(outcome, Exception):
            raise outcome
        errors = [
            {"index": {"_id": doc_id, "status": status, "error": {"type": reason}}}
            for doc_id, (status, reason) in outcome.items()
        ]
        return len(actions) - len(errors), errors


def _es_cfg() -> ESConfig:
    from app.workers.indexing.es_bootstrap import load_config

    return load_config()


def _cfg(**overrides: Any) -> ESRedpandaConfig:
    base = load_redpanda_config()
    fields = {
        "topic": base.topic,
        "dlq_topic": base.dlq_topic,
        "group": base.group,
        "batch_size": base.batch_size,
        "poll_timeout_seconds": 0.01,
        "max_retries": 2,
        "retry_backoff_seconds": 0.01,
        "retry_backoff_max_seconds": 0.02,
        "housekeeping_seconds": base.housekeeping_seconds,
    }
    fields.update(overrides)
    return ESRedpandaConfig(**fields)


def _event(event_id: int, agent_id: str = "agent-1") -> Dict[str, Any]:
    return {
        "id": event_id,
        "agent_id": agent_id,
        "event_type": "ssh_auth",
        "schema_version": 1,
        "timestamp": "2026-07-13T00:00:00+00:00",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 1,
        "dst_port": 22,
        "proto": "tcp",
        "bytes": 10,
        "extra": {},
    }


@pytest.fixture()
def dlq(monkeypatch: pytest.MonkeyPatch) -> _FakeDlqProducer:
    producer = _FakeDlqProducer()
    monkeypatch.setattr(es_redpanda, "get_producer", lambda: producer)
    return producer


def test_happy_path_indexes_and_commits(monkeypatch: pytest.MonkeyPatch, dlq: _FakeDlqProducer) -> None:
    bulk = _BulkScript(outcomes=[{}])
    monkeypatch.setattr(es_redpanda, "run_bulk", bulk)
    consumer = _FakeConsumer(batches=[[_FakeMessage(_event(1)), _FakeMessage(_event(2))]])

    es_redpanda.run(
        consumer=consumer,
        es=object(),
        es_cfg=_es_cfg(),
        cfg=_cfg(),
        bootstrap_enabled=False,
        ping=False,
        max_iterations=1,
    )

    assert consumer.commits == [False]
    assert len(bulk.calls) == 1
    assert {a["_id"] for a in bulk.calls[0]} == {"1", "2"}
    assert dlq.published == []


def test_permanent_error_goes_to_dlq_and_commits(monkeypatch: pytest.MonkeyPatch, dlq: _FakeDlqProducer) -> None:
    bulk = _BulkScript(outcomes=[{"1": (400, "mapper_parsing_exception")}])
    monkeypatch.setattr(es_redpanda, "run_bulk", bulk)
    consumer = _FakeConsumer(batches=[[_FakeMessage(_event(1), partition=3, offset=42), _FakeMessage(_event(2))]])

    es_redpanda.run(
        consumer=consumer,
        es=object(),
        es_cfg=_es_cfg(),
        cfg=_cfg(),
        bootstrap_enabled=False,
        ping=False,
        max_iterations=1,
    )

    assert consumer.commits == [False]
    assert len(dlq.published) == 1
    dlq_event = dlq.published[0]["event"]
    assert dlq.published[0]["topic"] == es_redpanda.EVENTS_INDEX_DLQ_TOPIC
    assert dlq_event["id"] == 1
    assert dlq_event["_dlq"]["reason"] == "permanent_400"
    assert dlq_event["_dlq"]["source_partition"] == 3
    assert dlq_event["_dlq"]["source_offset"] == 42
    assert dlq.flushes >= 1


def test_transient_error_retried_then_indexed(monkeypatch: pytest.MonkeyPatch, dlq: _FakeDlqProducer) -> None:
    bulk = _BulkScript(outcomes=[{"1": (429, "es_rejected_execution_exception")}, {}])
    monkeypatch.setattr(es_redpanda, "run_bulk", bulk)
    consumer = _FakeConsumer(batches=[[_FakeMessage(_event(1))]])

    es_redpanda.run(
        consumer=consumer,
        es=object(),
        es_cfg=_es_cfg(),
        cfg=_cfg(),
        bootstrap_enabled=False,
        ping=False,
        max_iterations=1,
    )

    assert len(bulk.calls) == 2
    assert dlq.published == []
    assert consumer.commits == [False]


def test_transient_exhausts_retries_then_dlq(monkeypatch: pytest.MonkeyPatch, dlq: _FakeDlqProducer) -> None:
    bulk = _BulkScript(
        outcomes=[
            {"1": (503, "unavailable_shard_exception")},
            {"1": (503, "unavailable_shard_exception")},
            {"1": (503, "unavailable_shard_exception")},
        ]
    )
    monkeypatch.setattr(es_redpanda, "run_bulk", bulk)
    consumer = _FakeConsumer(batches=[[_FakeMessage(_event(1))]])

    es_redpanda.run(
        consumer=consumer,
        es=object(),
        es_cfg=_es_cfg(),
        cfg=_cfg(max_retries=2),
        bootstrap_enabled=False,
        ping=False,
        max_iterations=1,
    )

    assert len(dlq.published) == 1
    assert dlq.published[0]["event"]["_dlq"]["reason"] == "max_retries"
    assert consumer.commits == [False]


def test_decode_error_goes_to_dlq_without_blocking_batch(monkeypatch: pytest.MonkeyPatch, dlq: _FakeDlqProducer) -> None:
    bulk = _BulkScript(outcomes=[{}])
    monkeypatch.setattr(es_redpanda, "run_bulk", bulk)
    consumer = _FakeConsumer(batches=[[_FakeMessage(None, raw=b"corrupted"), _FakeMessage(_event(2))]])

    es_redpanda.run(
        consumer=consumer,
        es=object(),
        es_cfg=_es_cfg(),
        cfg=_cfg(),
        bootstrap_enabled=False,
        ping=False,
        max_iterations=1,
    )

    assert len(dlq.published) == 1
    assert dlq.published[0]["event"]["_dlq"]["reason"] == "decode_error"
    assert consumer.commits == [False]
    assert {a["_id"] for a in bulk.calls[0]} == {"2"}


def test_unreachable_es_retries_with_keepalive_without_dlq(monkeypatch: pytest.MonkeyPatch, dlq: _FakeDlqProducer) -> None:
    bulk = _BulkScript(outcomes=[RuntimeError("conn refused"), {}])
    monkeypatch.setattr(es_redpanda, "run_bulk", bulk)
    consumer = _FakeConsumer(batches=[[_FakeMessage(_event(1))]])

    es_redpanda.run(
        consumer=consumer,
        es=object(),
        es_cfg=_es_cfg(),
        cfg=_cfg(max_retries=1),
        bootstrap_enabled=False,
        ping=False,
        max_iterations=1,
    )

    assert len(bulk.calls) == 2
    assert dlq.published == []
    assert consumer.commits == [False]
    assert consumer.polls >= 1


def _ingest_child(name: str) -> ChildSpec:
    for spec in GROUPS["ingest"]:
        if spec.name == name:
            return spec
    raise AssertionError(f"child not found: {name}")


def test_manager_defaults_keep_redis_consumer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SEAGULL_ES_INDEXER_STREAM_ENABLED", "true")
    monkeypatch.delenv("SEAGULL_ES_INDEXER_SOURCE", raising=False)
    assert _ingest_child("es-indexer-stream").is_enabled() is True
    assert _ingest_child("es-indexer-redpanda").is_enabled() is False


def test_manager_source_flag_switches_to_redpanda(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SEAGULL_ES_INDEXER_STREAM_ENABLED", "true")
    monkeypatch.setenv("SEAGULL_ES_INDEXER_SOURCE", "redpanda")
    assert _ingest_child("es-indexer-stream").is_enabled() is False
    assert _ingest_child("es-indexer-redpanda").is_enabled() is True


def test_manager_stream_disabled_turns_both_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SEAGULL_ES_INDEXER_STREAM_ENABLED", "false")
    monkeypatch.setenv("SEAGULL_ES_INDEXER_SOURCE", "redpanda")
    assert _ingest_child("es-indexer-stream").is_enabled() is False
    assert _ingest_child("es-indexer-redpanda").is_enabled() is False
