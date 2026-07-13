from __future__ import annotations

import json
import logging
from typing import Any, Dict, Mapping, Optional, Sequence

from app.core.config import settings
from app.core.observability import log_event, set_gauge

logger = logging.getLogger("seagull.messaging.consumer")


def _build_confluent_consumer(config: Mapping[str, Any]) -> Any:
    from confluent_kafka import Consumer

    return Consumer(dict(config))


def consumer_config(*, group_id: str, client_id: str) -> Dict[str, Any]:
    return {
        "bootstrap.servers": settings.SEAGULL_REDPANDA_BROKERS,
        "group.id": group_id,
        "client.id": client_id,
        "enable.auto.commit": False,
        "auto.offset.reset": "earliest",
        "session.timeout.ms": 45_000,
        "max.poll.interval.ms": 300_000,
        "socket.keepalive.enable": True,
        "log.connection.close": False,
    }


def build_consumer(*, group_id: str, client_id: str, topics: Sequence[str]) -> Any:
    consumer = _build_confluent_consumer(consumer_config(group_id=group_id, client_id=client_id))

    def _on_assign(_consumer: Any, partitions: Any) -> None:
        log_event(
            logger,
            "info",
            "redpanda_partitions_assigned",
            group=group_id,
            partitions=[f"{p.topic}[{p.partition}]" for p in partitions],
        )

    def _on_revoke(_consumer: Any, partitions: Any) -> None:
        log_event(
            logger,
            "info",
            "redpanda_partitions_revoked",
            group=group_id,
            partitions=[f"{p.topic}[{p.partition}]" for p in partitions],
        )

    consumer.subscribe(list(topics), on_assign=_on_assign, on_revoke=_on_revoke)
    return consumer


def decode_message_event(raw_value: Optional[bytes]) -> Optional[Dict[str, Any]]:
    if not raw_value:
        return None
    try:
        envelope = json.loads(raw_value.decode("utf-8", errors="replace"))
    except Exception:
        return None
    if not isinstance(envelope, dict):
        return None
    event = envelope.get("event")
    if isinstance(event, dict):
        return event
    return None


def report_consumer_lag(consumer: Any, *, group_id: str) -> Dict[str, int]:
    lag_by_topic: Dict[str, int] = {}
    try:
        assignment = consumer.assignment() or []
    except Exception:
        return lag_by_topic

    try:
        positions = {(p.topic, p.partition): p for p in (consumer.position(assignment) or [])}
    except Exception:
        positions = {}

    for partition in assignment:
        try:
            _low, high = consumer.get_watermark_offsets(partition, timeout=2.0, cached=False)
        except Exception:
            continue
        pos = positions.get((partition.topic, partition.partition))
        offset = getattr(pos, "offset", -1) if pos is not None else -1
        if offset is None or offset < 0:
            try:
                committed = consumer.committed([partition], timeout=2.0)
                offset = committed[0].offset if committed and committed[0].offset >= 0 else 0
            except Exception:
                offset = 0
        lag = max(0, int(high) - max(0, int(offset)))
        lag_by_topic[partition.topic] = lag_by_topic.get(partition.topic, 0) + lag

    for topic, lag in lag_by_topic.items():
        set_gauge("redpanda_consumer_lag", float(lag), topic=topic, group=group_id)
    return lag_by_topic
