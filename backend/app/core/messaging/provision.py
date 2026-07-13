from __future__ import annotations

import logging
import sys
import time
from typing import Any, Dict, Mapping, Sequence

from app.core.config import settings
from app.core.config.env_secrets import getenv_compat
from app.core.observability import log_event, setup_logging

from .topics import TopicSpec, topic_specs

logger = logging.getLogger("seagull.messaging.provision")


def _build_admin_client(config: Mapping[str, Any]) -> Any:
    from confluent_kafka.admin import AdminClient

    return AdminClient(dict(config))


def _replication_factor() -> int:
    raw = getenv_compat("SEAGULL_REDPANDA_TOPIC_REPLICATION")
    try:
        return max(1, int((raw or "1").strip(), 10))
    except ValueError:
        return 1


def ensure_topics(
    admin: Any,
    specs: Sequence[TopicSpec],
    *,
    replication_factor: int,
    timeout_seconds: float = 30.0,
) -> Dict[str, str]:
    from confluent_kafka.admin import ConfigResource, NewTopic

    outcomes: Dict[str, str] = {}
    metadata = admin.list_topics(timeout=timeout_seconds)
    existing = set(metadata.topics.keys())

    to_create = [
        NewTopic(
            spec.name,
            num_partitions=spec.partitions,
            replication_factor=replication_factor,
            config=spec.config(),
        )
        for spec in specs
        if spec.name not in existing
    ]

    if to_create:
        for name, future in admin.create_topics(to_create, request_timeout=timeout_seconds).items():
            try:
                future.result(timeout=timeout_seconds)
                outcomes[name] = "created"
            except Exception as exc:
                if "already exists" in str(exc).lower():
                    outcomes[name] = "exists"
                else:
                    outcomes[name] = f"create_failed: {exc}"

    for spec in specs:
        if spec.name not in existing:
            continue
        resource = ConfigResource(ConfigResource.Type.TOPIC, spec.name, set_config=spec.config())
        try:
            for _name, future in admin.alter_configs([resource], request_timeout=timeout_seconds).items():
                future.result(timeout=timeout_seconds)
            outcomes[spec.name] = "config_applied"
        except Exception as exc:
            outcomes[spec.name] = f"config_failed: {exc}"

    return outcomes


def provision(*, max_attempts: int = 30, backoff_seconds: float = 2.0) -> int:
    specs = topic_specs()
    replication = _replication_factor()

    admin: Any = None
    for attempt in range(1, max_attempts + 1):
        try:
            admin = _build_admin_client({"bootstrap.servers": settings.SEAGULL_REDPANDA_BROKERS})
            admin.list_topics(timeout=5.0)
            break
        except Exception as exc:
            log_event(
                logger,
                "warning",
                "redpanda_provision_broker_unreachable",
                attempt=attempt,
                max_attempts=max_attempts,
                error=repr(exc),
            )
            admin = None
            time.sleep(backoff_seconds)

    if admin is None:
        log_event(logger, "error", "redpanda_provision_failed", reason="broker_unreachable")
        return 1

    outcomes = ensure_topics(admin, specs, replication_factor=replication)
    failed = {name: out for name, out in outcomes.items() if "failed" in out}
    log_event(
        logger,
        "error" if failed else "info",
        "redpanda_provision_complete",
        brokers=settings.SEAGULL_REDPANDA_BROKERS,
        replication_factor=replication,
        outcomes=outcomes,
    )
    return 1 if failed else 0


def main() -> int:
    setup_logging("redpanda-provision")
    return provision()


if __name__ == "__main__":
    sys.exit(main())
