from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import select
from sqlalchemy.exc import OperationalError

from app.core.config import settings
from app.core.db import engine
from app.core.db.lifecycle import ensure_database_ready
from app.core.observability import log_event, setup_logging
from app.features.events.worker_runtime import NetEventModel
from app.shared.indexing.offset_store import ensure_offset, get_offset, set_offset
from app.workers.indexing.es_bootstrap import ESConfig, bootstrap, load_config

setup_logging("worker-es-indexer")
logger = logging.getLogger("seagull.worker.es_indexer")

_EXTRA_SEARCH_KEYS = (
    "event_type",
    "app_proto",
    "dns_qname",
    "http_host",
    "tls_sni",
    "tls_alpn_first",
    "geo_country",
    "geo_org",
    "asn_org",
    "ssh_username",
    "sudo_username",
    "sudo_command",
    "proc_name",
    "proc_exe",
    "fim_path",
)


def _to_doc(row: Dict[str, Any]) -> Dict[str, Any]:
    ts = row.get("timestamp")
    if isinstance(ts, datetime):
        ts_iso = ts.isoformat()
    else:
        ts_iso = str(ts) if ts is not None else None

    extra = row.get("extra") or {}
    if not isinstance(extra, dict):
        extra = {}

    def _as_str(v: Any) -> Optional[str]:
        if v is None:
            return None
        if isinstance(v, str):
            vv = v.strip()
            return vv if vv else None
        return str(v)

    def _as_int(v: Any) -> Optional[int]:
        try:
            if v is None:
                return None
            if isinstance(v, bool):
                return None
            return int(v)
        except Exception:
            return None

    event_type = _as_str(row.get("event_type"))

    doc: Dict[str, Any] = {
        "id": row.get("id"),
        "agent_id": row.get("agent_id"),
        "event_type": event_type,
        "schema_version": row.get("schema_version"),
        "@timestamp": ts_iso,
        "timestamp": ts_iso,
        "src_ip": row.get("src_ip"),
        "dst_ip": row.get("dst_ip"),
        "src_port": row.get("src_port"),
        "dst_port": row.get("dst_port"),
        "proto": row.get("proto"),
        "bytes": row.get("bytes"),
        "extra": extra,
    }

    app_proto = _as_str(extra.get("app_proto"))
    if app_proto:
        doc["app_proto"] = app_proto
    app_proto_reason = _as_str(extra.get("app_proto_reason"))
    if app_proto_reason:
        doc["app_proto_reason"] = app_proto_reason
    app_proto_conf_band = _as_str(extra.get("app_proto_conf_band"))
    if app_proto_conf_band:
        doc["app_proto_conf_band"] = app_proto_conf_band

    dns_qname = _as_str(extra.get("dns_qname"))
    if dns_qname:
        doc["dns_qname"] = dns_qname.lower()

    dns_risk = _as_int(extra.get("dns_risk"))
    if dns_risk is not None:
        doc["dns_risk"] = dns_risk

    http_host = _as_str(extra.get("http_host"))
    if http_host:
        doc["http_host"] = http_host.lower()

    http_method = _as_str(extra.get("http_method"))
    if http_method:
        doc["http_method"] = http_method.upper()

    tls_sni = _as_str(extra.get("tls_sni"))
    if tls_sni:
        doc["tls_sni"] = tls_sni.lower()

    tls_alpn = _as_str(extra.get("tls_alpn_first"))
    if tls_alpn:
        doc["tls_alpn_first"] = tls_alpn.lower()

    ja4 = _as_str(extra.get("ja4"))
    if ja4:
        doc["ja4"] = ja4

    ja4_ptype = _as_str(extra.get("ja4_ptype")) or "t"
    doc["ja4_ptype"] = ja4_ptype

    ja3 = _as_str(extra.get("ja3"))
    if ja3:
        doc["ja3"] = ja3

    for k in ["geo_country", "geo_org", "asn", "asn_org"]:
        vv = _as_str(extra.get(k))
        if vv:
            doc[k] = vv

    if event_type == "ssh_auth":
        ssh_action = _as_str(extra.get("action"))
        if ssh_action:
            doc["ssh_action"] = ssh_action
        ssh_username = _as_str(extra.get("username"))
        if ssh_username:
            doc["ssh_username"] = ssh_username

    if event_type == "sudo_cmd":
        for k_src, k_dst in [
            ("username", "sudo_username"),
            ("target_user", "sudo_target_user"),
            ("command", "sudo_command"),
            ("tty", "sudo_tty"),
            ("pwd", "sudo_pwd"),
        ]:
            vv = _as_str(extra.get(k_src))
            if vv:
                doc[k_dst] = vv

    tokens = [str(doc[k]) for k in _EXTRA_SEARCH_KEYS if doc.get(k)]
    if tokens:
        doc["extra_search"] = " ".join(tokens)

    return {k: v for k, v in doc.items() if v is not None}


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
    from elasticsearch import Elasticsearch

    kwargs: Dict[str, Any] = {
        "request_timeout": cfg.request_timeout_seconds,
    }
    if cfg.username and cfg.password:
        kwargs["basic_auth"] = (cfg.username, cfg.password)
    kwargs["verify_certs"] = cfg.verify_certs
    if cfg.ca_certs:
        kwargs["ca_certs"] = cfg.ca_certs

    return Elasticsearch(cfg.url, **kwargs)


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
