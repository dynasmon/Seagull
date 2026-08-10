from __future__ import annotations

import logging
import time
from typing import Any, Dict, Iterable, List

from sqlalchemy import select
from sqlalchemy.exc import OperationalError

from app.core.config import settings
from app.core.db import engine
from app.core.db.lifecycle import ensure_database_ready
from app.core.observability import log_event, setup_logging
from app.features.events.worker_runtime import NetEventModel
from app.shared.indexing.es_client import build_es_client
from app.shared.indexing.es_doc import build_event_doc as _to_doc
from app.shared.indexing.offset_store import ensure_offset, get_offset, set_offset
from app.workers.indexing.es_bootstrap import ESConfig, bootstrap, load_config

setup_logging("worker-es-indexer")
logger = logging.getLogger("seagull.worker.es_indexer")


def _get_last_id() -> int:
    ensure_offset("events")
    return get_offset("events")


def _set_last_id(last_id: int) -> None:
    set_offset("events", last_id)


def _fetch_events(after_id: int, limit: int) -> List[Dict[str, Any]]:
    with engine.begin() as conn:
        rows = conn.execute(
            select(
                NetEventModel.id,
                NetEventModel.agent_id,
                NetEventModel.event_type,
                NetEventModel.schema_version,
                NetEventModel.timestamp,
                NetEventModel.src_ip,
                NetEventModel.dst_ip,
                NetEventModel.src_port,
                NetEventModel.dst_port,
                NetEventModel.proto,
                NetEventModel.bytes,
                NetEventModel.extra,
            )
            .where(NetEventModel.id > int(after_id))
            .order_by(NetEventModel.id.asc())
            .limit(int(limit))
        ).mappings().all()
        return [dict(r) for r in rows]


def _build_es_client(cfg: ESConfig):
    return build_es_client(
        url=cfg.url,
        request_timeout_seconds=cfg.request_timeout_seconds,
        username=cfg.username,
        password=cfg.password,
        verify_certs=cfg.verify_certs,
        ca_certs=cfg.ca_certs,
    )


def _bulk_index(es, actions: Iterable[Dict[str, Any]], cfg: ESConfig) -> None:
    from elasticsearch import helpers

    success, errors = helpers.bulk(
        es,
        actions,
        request_timeout=cfg.request_timeout_seconds,
        raise_on_error=False,
        raise_on_exception=False,
    )

    if errors:
        sample = errors[0]
        log_event(logger, "warning", "es_bulk_partial_success", success=success, errors=len(errors), sample=str(sample)[:500])
    else:
        log_event(logger, "info", "es_bulk_ok", success=success)


def main() -> None:
    settings.validate_for_service("worker-es-indexer")
    cfg = load_config()

    ensure_database_ready()

    es = _build_es_client(cfg)

    backoff = 1.0
    bootstrap_done = False
    while True:
        try:
            if not es.ping():
                raise RuntimeError("elasticsearch_ping_failed")

            if cfg.bootstrap and not bootstrap_done:
                bootstrap(es, cfg)
                bootstrap_done = True

            last_id = _get_last_id()
            rows = _fetch_events(last_id, cfg.batch_size)

            if not rows:
                time.sleep(cfg.idle_sleep_seconds)
                backoff = 1.0
                continue

            actions: List[Dict[str, Any]] = []
            max_id = last_id

            for r in rows:
                doc_id = int(r["id"])
                max_id = max(max_id, doc_id)
                actions.append(
                    {
                        "_op_type": "index",
                        "_index": cfg.write_alias,
                        "_id": doc_id,
                        "_source": _to_doc(r),
                    }
                )

            _bulk_index(es, actions, cfg)
            _set_last_id(max_id)
            backoff = 1.0

            time.sleep(cfg.every_seconds)

        except OperationalError as e:
            wait_s = min(backoff, 15.0)
            log_event(logger, "warning", "es_indexer_db_not_ready", wait_s=wait_s, error=str(e).splitlines()[0])
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 15.0)
        except Exception as e:
            wait_s = min(backoff, 15.0)
            log_event(logger, "error", "es_indexer_loop_error", wait_s=wait_s, error=repr(e))
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 15.0)


if __name__ == "__main__":
    main()
