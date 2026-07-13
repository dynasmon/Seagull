from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional, Tuple

import pytest

from app.core.config import settings
from app.core.messaging import consumer as consumer_mod
from app.core.messaging import producer as producer_mod
from app.core.messaging import provision as provision_mod
from app.core.messaging.consumer import decode_message_event
from app.core.messaging.producer import EventLogProducer, get_producer, serialize_message
from app.core.messaging.topics import (
    ALERTS_RAW_TOPIC,
    EVENTS_INDEX_DLQ_TOPIC,
    EVENTS_INDEX_TOPIC,
    EVENTS_RAW_TOPIC,
    MESSAGE_SCHEMA_VERSION,
    topic_specs,
)


class _FakeConfluentProducer:
    def __init__(self, fail_with: Optional[Exception] = None, deliver_error: Any = None) -> None:
        self.fail_with = fail_with
        self.deliver_error = deliver_error
        self.produced: List[Dict[str, Any]] = []
        self.polls = 0
        self.flushes = 0

    def produce(self, topic: str, value: bytes, key: bytes, on_delivery: Callable[[Any, Any], None]) -> None:
        if self.fail_with is not None:
            raise self.fail_with
        self.produced.append({"topic": topic, "value": value, "key": key})
        on_delivery(self.deliver_error, object())

    def poll(self, _timeout: float = 0.0) -> int:
        self.polls += 1
        return 0

    def flush(self, _timeout: float = 10.0) -> int:
        self.flushes += 1
        return 0


class _FakeDeliveryError:
    def name(self) -> str:
        return "MSG_TIMED_OUT"


@pytest.fixture(autouse=True)
def _reset_producer_singleton():
    producer_mod.reset_producer_for_tests()
    yield
    producer_mod.reset_producer_for_tests()


def test_topic_specs_defaults() -> None:
    specs = {spec.name: spec for spec in topic_specs()}
    assert set(specs) == {EVENTS_RAW_TOPIC, EVENTS_INDEX_TOPIC, EVENTS_INDEX_DLQ_TOPIC, ALERTS_RAW_TOPIC}
    assert specs[EVENTS_RAW_TOPIC].partitions == 12
    assert specs[EVENTS_INDEX_TOPIC].partitions == 12
    assert specs[EVENTS_RAW_TOPIC].retention_hours == 168
    assert specs[ALERTS_RAW_TOPIC].retention_hours == 720
    assert specs[EVENTS_RAW_TOPIC].config()["retention.ms"] == str(168 * 3_600_000)
    assert specs[EVENTS_RAW_TOPIC].config()["cleanup.policy"] == "delete"


def test_topic_specs_env_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SEAGULL_REDPANDA_EVENTS_PARTITIONS", "6")
    monkeypatch.setenv("SEAGULL_REDPANDA_EVENTS_RETENTION_HOURS", "24")
    specs = {spec.name: spec for spec in topic_specs()}
    assert specs[EVENTS_RAW_TOPIC].partitions == 6
    assert specs[EVENTS_RAW_TOPIC].retention_hours == 24


def test_serialize_message_envelope_roundtrip() -> None:
    event = {"id": 7, "agent_id": "agent-1", "event_type": "ssh_auth"}
    raw = serialize_message(event, produced_at="2026-07-13T00:00:00+00:00")
    envelope = json.loads(raw.decode("utf-8"))
    assert envelope["schema_version"] == MESSAGE_SCHEMA_VERSION
    assert envelope["produced_at"] == "2026-07-13T00:00:00+00:00"
    assert envelope["event"] == event
    assert decode_message_event(raw) == event


def test_decode_message_event_rejects_garbage() -> None:
    assert decode_message_event(None) is None
    assert decode_message_event(b"") is None
    assert decode_message_event(b"not-json") is None
    assert decode_message_event(json.dumps([1, 2]).encode()) is None
    assert decode_message_event(json.dumps({"schema_version": 1}).encode()) is None


def test_producer_publish_success(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeConfluentProducer()
    monkeypatch.setattr(producer_mod, "_build_confluent_producer", lambda _cfg: fake)
    results: List[bool] = []

    producer = EventLogProducer(client_id="test")
    ok = producer.publish(EVENTS_RAW_TOPIC, key="agent-1", event={"id": 1, "agent_id": "agent-1"}, on_result=results.append)

    assert ok is True
    assert results == [True]
    assert len(fake.produced) == 1
    assert fake.produced[0]["topic"] == EVENTS_RAW_TOPIC
    assert fake.produced[0]["key"] == b"agent-1"
    assert decode_message_event(fake.produced[0]["value"]) == {"id": 1, "agent_id": "agent-1"}


def test_producer_publish_delivery_error_reports_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeConfluentProducer(deliver_error=_FakeDeliveryError())
    monkeypatch.setattr(producer_mod, "_build_confluent_producer", lambda _cfg: fake)
    results: List[bool] = []

    producer = EventLogProducer(client_id="test")
    ok = producer.publish(EVENTS_RAW_TOPIC, key="a", event={"id": 1}, on_result=results.append)

    assert ok is True
    assert results == [False]


def test_producer_publish_buffer_full_returns_false(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeConfluentProducer(fail_with=BufferError("queue full"))
    monkeypatch.setattr(producer_mod, "_build_confluent_producer", lambda _cfg: fake)
    results: List[bool] = []

    producer = EventLogProducer(client_id="test")
    ok = producer.publish(EVENTS_RAW_TOPIC, key="a", event={"id": 1}, on_result=results.append)

    assert ok is False
    assert results == [False]


def test_get_producer_disabled_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "SEAGULL_REDPANDA_ENABLED", False)
    assert get_producer() is None


def test_get_producer_singleton_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "SEAGULL_REDPANDA_ENABLED", True)
    fake = _FakeConfluentProducer()
    monkeypatch.setattr(producer_mod, "_build_confluent_producer", lambda _cfg: fake)

    first = get_producer()
    second = get_producer()
    assert first is not None
    assert first is second


def test_producer_config_hardening() -> None:
    cfg = producer_mod.producer_config("client-x")
    assert cfg["enable.idempotence"] is True
    assert cfg["compression.type"] == "zstd"
    assert cfg["client.id"] == "client-x"


def test_consumer_config_manual_commit() -> None:
    cfg = consumer_mod.consumer_config(group_id="es-indexer", client_id="c1")
    assert cfg["enable.auto.commit"] is False
    assert cfg["group.id"] == "es-indexer"
    assert cfg["auto.offset.reset"] == "earliest"


class _FakeFuture:
    def __init__(self, exc: Optional[Exception] = None) -> None:
        self._exc = exc

    def result(self, timeout: float = 0.0) -> None:
        if self._exc is not None:
            raise self._exc


class _FakeMetadata:
    def __init__(self, names: List[str]) -> None:
        self.topics = {name: object() for name in names}
        self.brokers = {1: object()}


class _FakeAdminClient:
    def __init__(self, existing: List[str]) -> None:
        self.existing = existing
        self.created: List[Any] = []
        self.altered: List[Any] = []

    def list_topics(self, timeout: float = 0.0) -> _FakeMetadata:
        return _FakeMetadata(self.existing)

    def create_topics(self, new_topics: List[Any], request_timeout: float = 0.0) -> Dict[str, _FakeFuture]:
        self.created.extend(new_topics)
        return {t.topic: _FakeFuture() for t in new_topics}

    def alter_configs(self, resources: List[Any], request_timeout: float = 0.0) -> Dict[Any, _FakeFuture]:
        self.altered.extend(resources)
        return {r: _FakeFuture() for r in resources}


def test_ensure_topics_creates_missing_and_reconciles_existing() -> None:
    admin = _FakeAdminClient(existing=[EVENTS_RAW_TOPIC])
    outcomes = provision_mod.ensure_topics(admin, topic_specs(), replication_factor=1, timeout_seconds=5.0)

    created_names = {t.topic for t in admin.created}
    assert created_names == {EVENTS_INDEX_TOPIC, EVENTS_INDEX_DLQ_TOPIC, ALERTS_RAW_TOPIC}
    assert outcomes[EVENTS_INDEX_TOPIC] == "created"
    assert outcomes[EVENTS_RAW_TOPIC] == "config_applied"
    for topic in admin.created:
        assert topic.config["cleanup.policy"] == "delete"
        assert int(topic.config["retention.ms"]) > 0


def _spec_pairs(specs: Any) -> List[Tuple[str, int]]:
    return [(s.name, s.partitions) for s in specs]


def test_partition_counts_scale_with_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SEAGULL_REDPANDA_EVENTS_PARTITIONS", "24")
    pairs = dict(_spec_pairs(topic_specs()))
    assert pairs[EVENTS_RAW_TOPIC] == 24
    assert pairs[EVENTS_INDEX_TOPIC] == 24
    assert pairs[ALERTS_RAW_TOPIC] == 3
