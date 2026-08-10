from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from app.core.observability import log_event
from app.shared.indexing.bulk import is_permanent_status, parse_bulk_errors, run_bulk
from app.shared.indexing.es_client import build_es_client
from app.shared.indexing.es_doc import build_event_doc
from app.shared.indexing.es_mapping import event_index_mapping_properties
from app.shared.indexing.identity import event_document_id
from app.shared.outbox.models import SINK_SEARCH, SINK_WARM
from app.workers.indexing.es_bootstrap import ESConfig, bootstrap, ensure_write_index
from app.workers.sinks.config import DispatcherConfig
from app.workers.sinks.delivery import DeliveryResult, retry_all

logger = logging.getLogger("seagull.worker.sinks")

IndexResolver = Callable[[Dict[str, Any]], str]
Bootstrap = Callable[[Any], None]


def daily_index(prefix: str, timestamp: Any) -> str:
    if not isinstance(timestamp, datetime):
        raise ValueError("event timestamp must be a datetime")
    return f"{prefix}-{timestamp.strftime('%Y.%m.%d')}"


def warm_index_bootstrap(cfg: DispatcherConfig) -> Bootstrap:
    def _bootstrap(es: Any) -> None:
        if not cfg.warm_ilm_enabled:
            return
        es.ilm.put_lifecycle(
            name=cfg.warm_ilm_policy,
            body={
                "policy": {
                    "phases": {
                        "hot": {"actions": {}},
                        "delete": {
                            "min_age": f"{int(cfg.warm_ilm_delete_after_days)}d",
                            "actions": {"delete": {}},
                        },
                    }
                }
            },
        )
        es.indices.put_index_template(
            name=f"{cfg.warm_index_prefix}-template",
            body={
                "index_patterns": [f"{cfg.warm_index_prefix}-*"],
                "template": {
                    "settings": {
                        "number_of_shards": 1,
                        "number_of_replicas": 0,
                        "refresh_interval": "30s",
                        "index.lifecycle.name": cfg.warm_ilm_policy,
                    },
                    "mappings": {"dynamic": True, "properties": event_index_mapping_properties()},
                },
                "priority": 190,
                "_meta": {"project": "dynasmon-seagull", "component": "sink_dispatcher", "tier": "warm"},
            },
        )

    return _bootstrap


class ElasticsearchDelivery:
    def __init__(
        self,
        *,
        sink: str,
        es_cfg: ESConfig,
        index_for: IndexResolver,
        bootstrap: Optional[Bootstrap] = None,
    ) -> None:
        self.sink = sink
        self.es_cfg = es_cfg
        self._index_for = index_for
        self._bootstrap = bootstrap
        self._client: Any = None
        self._bootstrap_done = bootstrap is None

    def _connect(self) -> Any:
        if self._client is None:
            client = build_es_client(
                url=self.es_cfg.url,
                request_timeout_seconds=self.es_cfg.request_timeout_seconds,
                username=self.es_cfg.username,
                password=self.es_cfg.password,
                verify_certs=self.es_cfg.verify_certs,
                ca_certs=self.es_cfg.ca_certs,
            )
            if not client.ping():
                return None
            self._client = client
        self._run_bootstrap()
        return self._client

    def _run_bootstrap(self) -> None:
        if self._bootstrap_done or self._bootstrap is None:
            return
        try:
            self._bootstrap(self._client)
        except Exception as exc:
            log_event(
                logger,
                "warning",
                "sink_index_bootstrap_failed",
                sink=self.sink,
                error_type=type(exc).__name__,
            )
            return
        self._bootstrap_done = True

    def _disconnect(self) -> None:
        self._client = None
        self._bootstrap_done = self._bootstrap is None

    def deliver(self, events: List[Dict[str, Any]], *, batch_id: int) -> DeliveryResult:
        try:
            es = self._connect()
        except Exception as exc:
            self._disconnect()
            return retry_all(events, error=type(exc).__name__)
        if es is None:
            return retry_all(events, error="elasticsearch_unavailable")

        actions: List[Dict[str, Any]] = []
        by_doc_id: Dict[str, Dict[str, Any]] = {}
        rejected: List[Dict[str, Any]] = []

        for event in events:
            try:
                index = self._index_for(event)
            except ValueError:
                rejected.append(event)
                continue
            doc_id = event_document_id(event)
            actions.append(
                {
                    "_op_type": "index",
                    "_index": index,
                    "_id": doc_id,
                    "_source": build_event_doc(event),
                }
            )
            by_doc_id[doc_id] = event

        if not actions:
            return DeliveryResult(dead=rejected, error="invalid_event" if rejected else "")

        try:
            _written, raw_errors = run_bulk(es, actions, request_timeout=self.es_cfg.request_timeout_seconds)
        except Exception as exc:
            self._disconnect()
            log_event(
                logger,
                "warning",
                "sink_elasticsearch_bulk_error",
                sink=self.sink,
                error_type=type(exc).__name__,
                batch_id=int(batch_id),
                events=len(events),
            )
            return DeliveryResult(retry=list(by_doc_id.values()), dead=rejected, error=type(exc).__name__)

        failures = parse_bulk_errors(raw_errors)
        retry: List[Dict[str, Any]] = []
        dead: List[Dict[str, Any]] = list(rejected)
        last_error = "invalid_event" if rejected else ""
        succeeded = 0

        for doc_id, event in by_doc_id.items():
            failure = failures.get(doc_id)
            if failure is None:
                succeeded += 1
                continue
            status, reason = failure
            last_error = f"{status}:{reason}"
            if is_permanent_status(status):
                dead.append(event)
            else:
                retry.append(event)

        if retry or dead:
            log_event(
                logger,
                "warning",
                "sink_elasticsearch_partial_batch",
                sink=self.sink,
                batch_id=int(batch_id),
                indexed=succeeded,
                retry=len(retry),
                dead=len(dead),
            )

        return DeliveryResult(delivered=succeeded, retry=retry, dead=dead, error=last_error)


def build_warm_delivery(*, es_cfg: ESConfig, cfg: DispatcherConfig) -> ElasticsearchDelivery:
    return ElasticsearchDelivery(
        sink=SINK_WARM,
        es_cfg=es_cfg,
        index_for=lambda event: daily_index(cfg.warm_index_prefix, event.get("timestamp")),
        bootstrap=warm_index_bootstrap(cfg),
    )


def build_search_delivery(*, es_cfg: ESConfig) -> ElasticsearchDelivery:
    def _bootstrap(es: Any) -> None:
        if es_cfg.bootstrap:
            bootstrap(es, es_cfg)
        else:
            ensure_write_index(es, es_cfg)

    return ElasticsearchDelivery(
        sink=SINK_SEARCH,
        es_cfg=es_cfg,
        index_for=lambda _event: es_cfg.write_alias,
        bootstrap=_bootstrap,
    )
