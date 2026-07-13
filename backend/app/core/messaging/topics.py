from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple

from app.core.config.env_secrets import getenv_compat

MESSAGE_SCHEMA_VERSION = 1

EVENTS_RAW_TOPIC = "seagull.events.raw"
EVENTS_INDEX_TOPIC = "seagull.events.index"
EVENTS_INDEX_DLQ_TOPIC = "seagull.events.index.dlq"
ALERTS_RAW_TOPIC = "seagull.alerts.raw"


def _env_int(name: str, default: int) -> int:
    raw = getenv_compat(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip(), 10)
    except ValueError:
        return default


@dataclass(frozen=True)
class TopicSpec:
    name: str
    partitions: int
    retention_hours: int

    @property
    def retention_ms(self) -> int:
        return int(self.retention_hours) * 3_600_000

    def config(self) -> Dict[str, str]:
        return {
            "retention.ms": str(self.retention_ms),
            "cleanup.policy": "delete",
        }


def topic_specs() -> Tuple[TopicSpec, ...]:
    events_partitions = max(1, _env_int("SEAGULL_REDPANDA_EVENTS_PARTITIONS", 12))
    events_retention = max(1, _env_int("SEAGULL_REDPANDA_EVENTS_RETENTION_HOURS", 168))
    alerts_retention = max(1, _env_int("SEAGULL_REDPANDA_ALERTS_RETENTION_HOURS", 720))
    dlq_retention = max(1, _env_int("SEAGULL_REDPANDA_DLQ_RETENTION_HOURS", 720))
    return (
        TopicSpec(name=EVENTS_RAW_TOPIC, partitions=events_partitions, retention_hours=events_retention),
        TopicSpec(name=EVENTS_INDEX_TOPIC, partitions=events_partitions, retention_hours=events_retention),
        TopicSpec(
            name=EVENTS_INDEX_DLQ_TOPIC,
            partitions=max(1, _env_int("SEAGULL_REDPANDA_DLQ_PARTITIONS", 3)),
            retention_hours=dlq_retention,
        ),
        TopicSpec(
            name=ALERTS_RAW_TOPIC,
            partitions=max(1, _env_int("SEAGULL_REDPANDA_ALERTS_PARTITIONS", 3)),
            retention_hours=alerts_retention,
        ),
    )
