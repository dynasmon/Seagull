from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

import pytest

from app.shared.indexing.bulk import is_permanent_status, parse_bulk_errors
from app.shared.indexing.identity import event_document_id, event_fingerprint
from app.workers.indexing.es_bootstrap import ESConfig, load_config
from app.workers.sinks import elasticsearch as sink_es
from app.workers.sinks.elasticsearch import ElasticsearchDelivery, daily_index

TIMESTAMP = datetime(2026, 8, 10, 12, 30, tzinfo=timezone.utc)


def _event(**overrides: Any) -> Dict[str, Any]:
    event = {
        "agent_id": "agent-1",
        "event_type": "dns",
        "schema_version": 1,
        "timestamp": TIMESTAMP,
        "src_ip": "10.0.0.1",
        "dst_ip": "8.8.8.8",
        "src_port": 44444,
        "dst_port": 53,
        "proto": "udp",
        "bytes": 120,
        "extra": {"app_proto": "dns", "dns_qname": "Example.COM"},
    }
    event.update(overrides)
    return event


class _FakeEs:
    def __init__(self) -> None:
        self.pings = 0

    def ping(self) -> bool:
        self.pings += 1
        return True


@pytest.fixture()
def es_cfg(monkeypatch) -> ESConfig:
    monkeypatch.setenv("SEAGULL_ES_INDEX_PREFIX", "seagull-events")
    monkeypatch.delenv("SEAGULL_ES_WRITE_ALIAS", raising=False)
    return load_config()


def _delivery(monkeypatch, es_cfg: ESConfig, bulk_result) -> ElasticsearchDelivery:
    captured: List[List[Dict[str, Any]]] = []

    def _run_bulk(_es: Any, actions: List[Dict[str, Any]], *, request_timeout: int):
        captured.append(actions)
        return bulk_result(actions)

    monkeypatch.setattr(sink_es, "run_bulk", _run_bulk)
    delivery = ElasticsearchDelivery(
        sink="warm",
        es_cfg=es_cfg,
        index_for=lambda event: daily_index("seagull-events-warm", event.get("timestamp")),
        bootstrap=None,
    )
    delivery._client = _FakeEs()
    delivery.captured = captured
    return delivery


def test_document_id_is_stable_for_the_same_event() -> None:
    assert event_document_id(_event()) == event_document_id(_event())


def test_document_id_prefers_the_hot_store_identifier() -> None:
    assert event_document_id(_event(pg_event_id=4711)) == "4711"


def test_document_id_differs_when_the_event_differs() -> None:
    assert event_document_id(_event()) != event_document_id(_event(dst_port=443))


def test_fingerprint_is_stable_across_timestamp_encodings() -> None:
    assert event_fingerprint(_event()) == event_fingerprint(_event(timestamp=TIMESTAMP.isoformat()))


def test_successful_bulk_marks_every_event_delivered(monkeypatch, es_cfg: ESConfig) -> None:
    delivery = _delivery(monkeypatch, es_cfg, lambda actions: (len(actions), []))

    result = delivery.deliver([_event(), _event(dst_port=443)], batch_id=7)

    assert result.delivered == 2
    assert result.complete
    assert {action["_index"] for action in delivery.captured[0]} == {"seagull-events-warm-2026.08.10"}
    assert all(action["_op_type"] == "index" and action["_id"] for action in delivery.captured[0])


def test_partial_bulk_splits_transient_from_permanent(monkeypatch, es_cfg: ESConfig) -> None:
    permanent = _event(dst_port=443)
    transient = _event(dst_port=8080)
    permanent_id = event_document_id(permanent)
    transient_id = event_document_id(transient)

    def _bulk(actions: List[Dict[str, Any]]):
        return (
            len(actions) - 2,
            [
                {"index": {"_id": permanent_id, "status": 400, "error": {"type": "mapper_parsing_exception"}}},
                {"index": {"_id": transient_id, "status": 429, "error": {"type": "es_rejected_execution"}}},
            ],
        )

    delivery = _delivery(monkeypatch, es_cfg, _bulk)

    result = delivery.deliver([_event(), permanent, transient], batch_id=7)

    assert result.delivered == 1
    assert result.dead == [permanent]
    assert result.retry == [transient]


def test_bulk_exception_retries_the_whole_batch(monkeypatch, es_cfg: ESConfig) -> None:
    def _bulk(_actions: List[Dict[str, Any]]):
        raise ConnectionError("no route to elasticsearch")

    events = [_event(), _event(dst_port=443)]
    delivery = _delivery(monkeypatch, es_cfg, _bulk)

    result = delivery.deliver(events, batch_id=7)

    assert result.delivered == 0
    assert result.retry == events
    assert result.error == "ConnectionError"
    assert delivery._client is None


def test_unreachable_cluster_retries_without_calling_bulk(monkeypatch, es_cfg: ESConfig) -> None:
    class _DownEs:
        def ping(self) -> bool:
            return False

    delivery = _delivery(monkeypatch, es_cfg, lambda actions: (len(actions), []))
    delivery._client = None
    monkeypatch.setattr(sink_es, "build_es_client", lambda **_kwargs: _DownEs())

    result = delivery.deliver([_event()], batch_id=7)

    assert result.retry == [_event()]
    assert result.error == "elasticsearch_unavailable"
    assert delivery.captured == []


def test_bootstrap_failure_does_not_stop_delivery(monkeypatch, es_cfg: ESConfig) -> None:
    attempts: List[int] = []

    def _failing_bootstrap(_es: Any) -> None:
        attempts.append(1)
        raise RuntimeError("ilm api rejected the request")

    delivery = _delivery(monkeypatch, es_cfg, lambda actions: (len(actions), []))
    delivery._bootstrap = _failing_bootstrap
    delivery._bootstrap_done = False

    result = delivery.deliver([_event()], batch_id=7)

    assert result.delivered == 1
    assert result.complete
    assert attempts == [1]


def test_event_without_usable_timestamp_is_rejected(monkeypatch, es_cfg: ESConfig) -> None:
    delivery = _delivery(monkeypatch, es_cfg, lambda actions: (len(actions), []))

    result = delivery.deliver([_event(timestamp=None)], batch_id=7)

    assert result.delivered == 0
    assert result.retry == []
    assert len(result.dead) == 1


def test_search_delivery_targets_the_write_alias(es_cfg: ESConfig) -> None:
    delivery = sink_es.build_search_delivery(es_cfg=es_cfg)
    assert delivery._index_for(_event()) == es_cfg.write_alias


def test_permanent_status_classification() -> None:
    assert is_permanent_status(400) is True
    assert is_permanent_status(404) is True
    assert is_permanent_status(429) is False
    assert is_permanent_status(503) is False


def test_bulk_error_parsing_keeps_status_and_reason() -> None:
    parsed = parse_bulk_errors(
        [{"index": {"_id": "42", "status": 400, "error": {"type": "mapper_parsing_exception"}}}]
    )
    assert parsed == {"42": (400, "mapper_parsing_exception")}
