"""Async ingest worker.

This worker drains Redis queue items produced by /ingest/events and persists them
into Postgres (hot) and Elasticsearch (warm) without blocking the agent.

Design goals:
- Reduce Postgres pressure under volumetric attacks (Storm Mode).
- Provide stable rollups (1s) and optional warm tier indexing.
- Keep failure modes safe: if warm indexing fails, hot ingestion still succeeds.

Operational notes:
- Uses BRPOPLPUSH to a processing list to reduce loss on crash.
- Decrements backlog_events counter on successful commit.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.dialects.postgresql import insert

from app.core.clickhouse import (
    ensure_clickhouse_events_schema,
    get_clickhouse_client,
    reset_clickhouse_client,
)
from app.core.db import engine
from app.core.config import settings
from app.core.redis_client import get_redis
from app.core.db_lifecycle import ensure_database_ready
from app.core.env_secrets import env_value, getenv_compat
from app.core.ingest_control import (
    record_sink_runtime_metric,
    record_worker_progress,
    set_sink_queue_depth,
    storm_maybe_close_alert,
    storm_maybe_open_alert,
    worker_heartbeat,
)
from app.core.observability import incr_counter, log_event, observe_hist, setup_logging
from app.features.events.worker_runtime import NetEventModel, NetEventRollup1sModel, write_clickhouse_events

setup_logging("worker-ingest")
logger = logging.getLogger("seagull.worker.ingest")


@dataclass(frozen=True)
class WorkerConfig:
    queue_key: str
    processing_key: str
    batch_messages: int
    idle_sleep_seconds: float
    values_page_size: int
    rollup_page_size: int
    warm_enabled: bool
    es_url: str
    es_index_prefix: str
    warm_index_prefix: str
    warm_ilm_enabled: bool
    warm_ilm_policy: str
    warm_ilm_delete_after_days: int
    es_request_timeout_seconds: int
    es_username: Optional[str]
    es_password: Optional[str]
    es_verify_certs: bool
    es_ca_certs: Optional[str]
    clickhouse_enabled: bool
    clickhouse_required: bool
    clickhouse_reconnect_seconds: float
    clickhouse_sink_queue_max_batches: int
    warm_sink_queue_max_batches: int
    sink_max_batch_retries: int


def _env_str(name: str, default: str) -> str:
    return env_value(name, default) or default


def _env_int(name: str, default: int) -> int:
    v = getenv_compat(name)
    if v is None:
        return default
    v = v.strip()
    if not v:
        return default
    try:
        return int(v, 10)
    except Exception:
        return default


def _env_float(name: str, default: float) -> float:
    v = getenv_compat(name)
    if v is None:
        return default
    v = v.strip()
    if not v:
        return default
    try:
        return float(v)
    except Exception:
        return default


def _env_bool(name: str, default: bool) -> bool:
    v = getenv_compat(name)
    if v is None:
        return default
    s = v.strip().lower()
    if s in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "f", "no", "n", "off"}:
        return False
    return default


def load_config() -> WorkerConfig:
    qk = _env_str("SEAGULL_INGEST_QUEUE_KEY", "seagull:ingest:queue")
    return WorkerConfig(
        queue_key=qk,
        processing_key=_env_str("SEAGULL_INGEST_PROCESSING_KEY", f"{qk}:processing"),
        batch_messages=max(1, _env_int("SEAGULL_INGEST_WORKER_BATCH_MESSAGES", 50)),
        idle_sleep_seconds=max(0.1, _env_float("SEAGULL_INGEST_WORKER_IDLE_SLEEP_SECONDS", 0.25)),
        values_page_size=max(100, _env_int("SEAGULL_INGEST_VALUES_PAGE_SIZE", 1000)),
        rollup_page_size=max(100, _env_int("SEAGULL_INGEST_ROLLUP_PAGE_SIZE", 500)),
        warm_enabled=_env_bool("SEAGULL_INGEST_WARM_ENABLED", True),
        es_url=_env_str("SEAGULL_ES_URL", "http://elasticsearch:9200"),
        es_index_prefix=_env_str("SEAGULL_ES_INDEX_PREFIX", "seagull-events"),
        warm_index_prefix=_env_str("SEAGULL_INGEST_WARM_INDEX_PREFIX", _env_str("SEAGULL_ES_INDEX_PREFIX", "seagull-events") + "-warm"),
        warm_ilm_enabled=_env_bool("SEAGULL_INGEST_WARM_ILM_ENABLED", True),
        warm_ilm_policy=_env_str("SEAGULL_INGEST_WARM_ILM_POLICY", "seagull-warm-delete-30d"),
        warm_ilm_delete_after_days=max(1, _env_int("SEAGULL_INGEST_WARM_ILM_DELETE_AFTER_DAYS", 30)),
        es_request_timeout_seconds=max(5, _env_int("SEAGULL_ES_REQUEST_TIMEOUT_SECONDS", 30)),
        es_username=env_value("SEAGULL_ES_USERNAME", None),
        es_password=env_value("SEAGULL_ES_PASSWORD", None),
        es_verify_certs=_env_bool("SEAGULL_ES_VERIFY_CERTS", True),
        es_ca_certs=env_value("SEAGULL_ES_CA_CERTS", None),
        clickhouse_enabled=_env_bool("SEAGULL_CLICKHOUSE_ENABLED", True),
        clickhouse_required=_env_bool("SEAGULL_CLICKHOUSE_REQUIRED", True),
        clickhouse_reconnect_seconds=max(1.0, _env_float("SEAGULL_CLICKHOUSE_RECONNECT_SECONDS", 5.0)),
        clickhouse_sink_queue_max_batches=max(1, _env_int("SEAGULL_INGEST_CLICKHOUSE_SINK_QUEUE_MAX_BATCHES", 128)),
        warm_sink_queue_max_batches=max(1, _env_int("SEAGULL_INGEST_WARM_SINK_QUEUE_MAX_BATCHES", 128)),
        sink_max_batch_retries=max(0, _env_int("SEAGULL_INGEST_SINK_MAX_BATCH_RETRIES", 1)),
    )


def _build_es_client(cfg: WorkerConfig):
    from elasticsearch import Elasticsearch

    kwargs: Dict[str, Any] = {
        "request_timeout": cfg.es_request_timeout_seconds,
        "verify_certs": bool(cfg.es_verify_certs),
    }
    if cfg.es_username and cfg.es_password:
        kwargs["basic_auth"] = (cfg.es_username, cfg.es_password)
    if cfg.es_ca_certs:
        kwargs["ca_certs"] = cfg.es_ca_certs
    return Elasticsearch(cfg.es_url, **kwargs)


def _index_for(prefix: str, ts: datetime) -> str:
    return f"{prefix}-{ts.strftime('%Y.%m.%d')}"


def _to_doc(row: Dict[str, Any]) -> Dict[str, Any]:
    """Build an ES doc consistent with es_indexer mappings."""

    ts = row.get("timestamp")
    ts_iso = ts.isoformat() if isinstance(ts, datetime) else (str(ts) if ts else None)

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

    # Protocol intel and enrichments (optional)
    for k in ["app_proto", "dns_qname", "http_host", "tls_sni", "ja4", "ja4_ptype", "ja3"]:
        vv = _as_str(extra.get(k))
        if vv:
            doc[k] = vv.lower() if k in {"dns_qname", "http_host", "tls_sni"} else vv

    dns_risk = _as_int(extra.get("dns_risk"))
    if dns_risk is not None:
        doc["dns_risk"] = dns_risk

    http_method = _as_str(extra.get("http_method"))
    if http_method:
        doc["http_method"] = http_method.upper()

    # Geo/ASN
    for k in ["geo_country", "geo_org", "asn", "asn_org"]:
        vv = _as_str(extra.get(k))
        if vv:
            doc[k] = vv

    # SSH
    if event_type == "ssh_auth":
        vv = _as_str(extra.get("action"))
        if vv:
            doc["ssh_action"] = vv
        vv2 = _as_str(extra.get("username"))
        if vv2:
            doc["ssh_username"] = vv2

    # Sudo
    if event_type == "sudo_cmd":
        mapping = {
            "username": "sudo_username",
            "target_user": "sudo_target_user",
            "command": "sudo_command",
            "tty": "sudo_tty",
            "pwd": "sudo_pwd",
        }
        for src, dst in mapping.items():
            vv = _as_str(extra.get(src))
            if vv:
                doc[dst] = vv

    if event_type == "proc_exec":
        doc["proc_pid"] = _as_int(extra.get("pid"))
        doc["proc_ppid"] = _as_int(extra.get("ppid"))
        doc["proc_name"] = _as_str(extra.get("exe_name") or extra.get("comm") or extra.get("binary"))
        doc["proc_exe"] = _as_str(extra.get("exe_path"))
        doc["proc_parent_name"] = _as_str(extra.get("parent_exe_name") or extra.get("parent_comm"))

    if event_type in {"fim_change", "persistence_systemd", "persistence_cron", "ssh_key_change"}:
        doc["fim_path"] = _as_str(extra.get("path"))
        doc["fim_category"] = _as_str(extra.get("path_category"))

    if event_type in {"beacon_suspect", "c2_suspect", "exfil_suspect", "egress_anomaly"}:
        doc["heuristic_name"] = _as_str(extra.get("heuristic_name") or extra.get("heuristic_kind") or extra.get("reason_kind"))
        doc["heuristic_confidence"] = _as_int(extra.get("confidence"))

    return {k: v for k, v in doc.items() if v is not None}


def _ensure_warm_ilm_and_template(es, cfg: WorkerConfig) -> None:
    """Ensure ILM policy + index template for warm tier (best-effort).

    This keeps warm indexes self-managing (retention via ILM) and tuned for
    ingest bursts (lower refresh interval).
    """

    if not cfg.warm_ilm_enabled:
        return

    policy_name = cfg.warm_ilm_policy

    # Create/overwrite policy (idempotent).
    try:
        body = {
            "policy": {
                "phases": {
                    "hot": {"actions": {}},
                    "delete": {
                        "min_age": f"{int(cfg.warm_ilm_delete_after_days)}d",
                        "actions": {"delete": {}},
                    },
                }
            }
        }
        es.transport.perform_request("PUT", f"/_ilm/policy/{policy_name}", body=body)
    except Exception as e:
        log_event(logger, "warning", "ingest_ilm_policy_error", error_type=type(e).__name__)
        return

    try:
        name = f"{cfg.warm_index_prefix}-template"

        mappings = {
            "dynamic": True,
            "properties": {
                "@timestamp": {"type": "date"},
                "timestamp": {"type": "date"},
                "schema_version": {"type": "short"},
                "agent_id": {"type": "keyword"},
                "event_type": {"type": "keyword"},
                "proto": {"type": "keyword"},
                "src_ip": {"type": "ip"},
                "dst_ip": {"type": "ip"},
                "src_port": {"type": "integer"},
                "dst_port": {"type": "integer"},
                "bytes": {"type": "long"},

                # Protocol Intel
                "app_proto": {"type": "keyword"},
                "dns_qname": {"type": "keyword"},
                "dns_risk": {"type": "integer"},
                "http_host": {"type": "keyword"},
                "http_method": {"type": "keyword"},
                "tls_sni": {"type": "keyword"},
                "tls_alpn_first": {"type": "keyword"},
                "ja4": {"type": "keyword"},
                "ja4_ptype": {"type": "keyword"},
                "ja3": {"type": "keyword"},

                # Enrichment
                "geo_country": {"type": "keyword"},
                "geo_org": {"type": "keyword"},
                "asn": {"type": "keyword"},
                "asn_org": {"type": "keyword"},

                # SSH
                "ssh_action": {"type": "keyword"},
                "ssh_username": {"type": "keyword"},

                # Sudo
                "sudo_username": {"type": "keyword"},
                "sudo_target_user": {"type": "keyword"},
                "sudo_command": {"type": "keyword"},
                "sudo_tty": {"type": "keyword"},
                "sudo_pwd": {"type": "keyword"},

                # Process / FIM / heuristic signals
                "proc_pid": {"type": "integer"},
                "proc_ppid": {"type": "integer"},
                "proc_name": {"type": "keyword"},
                "proc_exe": {"type": "keyword"},
                "proc_parent_name": {"type": "keyword"},
                "fim_path": {"type": "keyword"},
                "fim_category": {"type": "keyword"},
                "heuristic_name": {"type": "keyword"},
                "heuristic_confidence": {"type": "integer"},

                "extra": {"type": "flattened"},
            },
        }

        body = {
            "index_patterns": [f"{cfg.warm_index_prefix}-*"],
            "template": {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                    "refresh_interval": "30s",
                    "index.lifecycle.name": policy_name,
                },
                "mappings": mappings,
            },
            "priority": 190,
            "_meta": {
                "project": "dynasmon-seagull",
                "component": "ingest_worker",
                "tier": "warm",
            },
        }

        es.indices.put_index_template(name=name, body=body)
    except Exception as e:
        log_event(logger, "warning", "ingest_warm_template_error", error_type=type(e).__name__)
        return

    log_event(logger, "info", "ingest_warm_ilm_ready", warm_index_prefix=cfg.warm_index_prefix, policy=policy_name)


def _requeue_processing(r, cfg: WorkerConfig) -> None:
    """Move any leftover processing items back to the main queue."""

    try:
        while True:
            item = r.rpoplpush(cfg.processing_key, cfg.queue_key)
            if not item:
                break
    except Exception:
        return


def _requeue_processing_with_retry_cap(r, cfg: WorkerConfig) -> None:
    """Requeue processing items and dead-letter poison messages.

    This prevents infinite retry loops where malformed items keep the pipeline
    permanently in draining/shedding without useful backlog convergence.
    """

    max_retries = max(1, _env_int("SEAGULL_INGEST_WORKER_MAX_MESSAGE_RETRIES", 4))

    try:
        while True:
            raw = r.rpop(cfg.processing_key)
            if not raw:
                break

            received = 0
            retry_n = 0
            try:
                msg = json.loads(raw)
                received = max(0, int(msg.get("received") or 0))
                retry_n = max(0, int(msg.get("_retry_count") or 0)) + 1
                msg["_retry_count"] = retry_n
                payload = json.dumps(msg, separators=(",", ":"), ensure_ascii=False)
            except Exception:
                # Malformed messages are considered poison and dropped.
                payload = None

            if payload is not None and retry_n <= max_retries:
                r.lpush(cfg.queue_key, payload)
                continue

            if received > 0:
                _decr_backlog_events(r, received)
            log_event(
                logger,
                "warning",
                "ingest_deadletter_message",
                retries=retry_n,
                received=received,
            )
    except Exception:
        return


def _decr_backlog_events(r, received: int) -> None:
    """Decrease backlog counter and clamp to 0.

    Under Redis hiccups or worker restarts, the counter can drift. Negative
    values break backpressure evaluation (ingest may stop protecting itself).
    """

    try:
        key = _env_str("SEAGULL_INGEST_BACKLOG_EVENTS_KEY", "seagull:ingest:backlog_events")
        new_v = r.decrby(key, int(received))
        try:
            vv = int(new_v)
            if vv < 0:
                r.set(key, 0)
        except Exception:
            # If we can't parse the returned value, fail open.
            pass
    except Exception:
        return


def _record_clickhouse_progress(r, *, rows: int) -> None:
    if r is None or rows <= 0:
        return
    ts_s = int(time.time())
    rows_key = f"seagull:ingest:clickhouse:rows:{ts_s}"
    batches_key = f"seagull:ingest:clickhouse:batches:{ts_s}"
    try:
        pipe = r.pipeline()
        pipe.incrby(rows_key, int(rows))
        pipe.expire(rows_key, 30)
        pipe.incrby(batches_key, 1)
        pipe.expire(batches_key, 30)
        pipe.execute()
    except Exception:
        return


def _set_clickhouse_state(r, *, state: str, error_type: str = "") -> None:
    if r is None:
        return
    try:
        pipe = r.pipeline()
        pipe.setex("seagull:ingest:clickhouse:state", 120, str(state or "unknown"))
        if error_type:
            pipe.setex("seagull:ingest:clickhouse:error_type", 120, str(error_type)[:64])
        else:
            pipe.delete("seagull:ingest:clickhouse:error_type")
        pipe.execute()
    except Exception:
        return


def _insert_hot_rows_with_pg_ids(conn, hot_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Insert hot rows in Postgres and return rows linked with pg_event_id.

    The first attempt uses bulk INSERT ... RETURNING for throughput. If that fails,
    we fallback safely using savepoints so the outer transaction remains usable.
    """

    if not hot_rows:
        return []

    inserted_hot_rows: List[Dict[str, Any]] = []

    try:
        with conn.begin_nested():
            res = conn.execute(insert(NetEventModel).returning(NetEventModel.id), hot_rows)
            ids = [int(r[0]) for r in (res.fetchall() or [])]
            if len(ids) != len(hot_rows):
                raise RuntimeError(f"returning mismatch ids={len(ids)} rows={len(hot_rows)}")
            for row, eid in zip(hot_rows, ids):
                rr = dict(row)
                rr["pg_event_id"] = int(eid)
                inserted_hot_rows.append(rr)
        return inserted_hot_rows
    except Exception as e:
        log_event(
            logger,
            "warning",
            "ingest_pg_returning_bulk_error",
            error_type=type(e).__name__,
            hot_rows=len(hot_rows),
        )

    rows_without_id = 0
    for row in hot_rows:
        try:
            with conn.begin_nested():
                stmt = insert(NetEventModel).values(**row).returning(NetEventModel.id)
                eid = conn.execute(stmt).scalar_one_or_none()
                if eid is None:
                    raise RuntimeError("missing returned id")
                rr = dict(row)
                rr["pg_event_id"] = int(eid)
                inserted_hot_rows.append(rr)
        except Exception:
            try:
                with conn.begin_nested():
                    conn.execute(insert(NetEventModel).values(**row))
                rows_without_id += 1
            except Exception as inner_exc:
                log_event(
                    logger,
                    "error",
                    "ingest_pg_row_insert_error",
                    error_type=type(inner_exc).__name__,
                )
                raise

    if rows_without_id > 0:
        log_event(
            logger,
            "warning",
            "ingest_pg_returning_row_fallback_partial",
            rows_without_id=rows_without_id,
            total_rows=len(hot_rows),
        )

    return inserted_hot_rows


def _to_ch_ts(ts: Any) -> datetime:
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc)
    return datetime.now(timezone.utc)


def _norm_port(v: Any) -> Optional[int]:
    try:
        if v is None:
            return None
        n = int(v)
        if n < 0 or n > 65535:
            return None
        return n
    except Exception:
        return None


def _event_hot_columns(event_type: str, extra: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(extra, dict):
        extra = {}

    def _s(k: str, *, lower: bool = False, upper: bool = False, default: Optional[str] = None) -> Optional[str]:
        raw = extra.get(k)
        if raw is None:
            return default
        v = str(raw).strip()
        if not v:
            return default
        if lower:
            return v.lower()
        if upper:
            return v.upper()
        return v

    def _i(k: str) -> Optional[int]:
        raw = extra.get(k)
        if raw is None or raw == "":
            return None
        try:
            return int(raw)
        except Exception:
            return None

    out: Dict[str, Any] = {
        "app_proto": _s("app_proto"),
        "app_proto_reason": _s("app_proto_reason"),
        "app_proto_conf_band": _s("app_proto_conf_band"),
        "dns_qname": _s("dns_qname", lower=True),
        "http_host": _s("http_host", lower=True),
        "http_method": _s("http_method", upper=True),
        "tls_sni": _s("tls_sni", lower=True),
        "tls_alpn_first": _s("tls_alpn_first", lower=True),
        "ja3": _s("ja3"),
        "ja4": _s("ja4"),
        "ja4_ptype": _s("ja4_ptype", default="t"),
        "proc_pid": None,
        "proc_ppid": None,
        "proc_name": None,
        "proc_exe": None,
        "proc_parent_name": None,
        "fim_path": None,
        "fim_category": None,
        "heuristic_name": None,
        "heuristic_confidence": None,
    }
    if event_type == "ssh_auth":
        out["ssh_action"] = _s("action")
        out["ssh_username"] = _s("username")
    else:
        out["ssh_action"] = None
        out["ssh_username"] = None

    if event_type == "proc_exec":
        out["proc_pid"] = _i("pid")
        out["proc_ppid"] = _i("ppid")
        out["proc_name"] = _s("exe_name") or _s("comm") or _s("binary")
        out["proc_exe"] = _s("exe_path")
        out["proc_parent_name"] = _s("parent_exe_name") or _s("parent_comm")

    if event_type in {"fim_change", "persistence_systemd", "persistence_cron", "ssh_key_change"}:
        out["fim_path"] = _s("path")
        out["fim_category"] = _s("path_category")

    if event_type in {"beacon_suspect", "c2_suspect", "exfil_suspect", "egress_anomaly"}:
        out["heuristic_name"] = _s("heuristic_name") or _s("heuristic_kind") or _s("reason_kind")
        out["heuristic_confidence"] = _i("confidence")
    return out


def _event_fingerprint(row: Dict[str, Any]) -> str:
    extra = row.get("extra") or {}
    if not isinstance(extra, dict):
        extra = {}
    return "|".join(
        [
            str(row.get("agent_id") or ""),
            str(row.get("event_type") or ""),
            _to_ch_ts(row.get("timestamp")).isoformat(),
            str(row.get("src_ip") or ""),
            str(row.get("dst_ip") or ""),
            str(_norm_port(row.get("src_port")) or 0),
            str(_norm_port(row.get("dst_port")) or 0),
            str(row.get("proto") or ""),
            str(int(row.get("bytes") or 0)),
            json.dumps(extra, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str),
        ]
    )


def _event_from_wire(ev: List[Any]) -> Dict[str, Any] | None:
    agent_id = ev[0] if len(ev) > 0 else None
    event_type = ev[1] if len(ev) > 1 else None
    if not agent_id or not event_type:
        return None

    try:
        ts = datetime.fromisoformat(ev[3]) if (len(ev) > 3 and ev[3]) else datetime.utcnow()
    except Exception:
        ts = datetime.utcnow()

    try:
        schema_v = int(ev[2] or 1)
    except Exception:
        schema_v = 1

    src_ip = ev[4] if (len(ev) > 4 and ev[4]) else None
    dst_ip = ev[5] if (len(ev) > 5 and ev[5]) else None

    src_port = ev[6] if (len(ev) > 6) else None
    dst_port = ev[7] if (len(ev) > 7) else None
    try:
        src_port = int(src_port) if src_port is not None else None
    except Exception:
        src_port = None
    try:
        dst_port = int(dst_port) if dst_port is not None else None
    except Exception:
        dst_port = None

    proto = ev[8] if (len(ev) > 8 and ev[8]) else None

    bytes_v = ev[9] if (len(ev) > 9) else None
    try:
        bytes_v = int(bytes_v) if bytes_v is not None else 0
    except Exception:
        bytes_v = 0

    extra_v = ev[10] if (len(ev) > 10 and isinstance(ev[10], dict)) else {}
    row = {
        "agent_id": agent_id,
        "event_type": event_type,
        "schema_version": schema_v,
        "timestamp": ts,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "proto": proto,
        "bytes": bytes_v,
        "extra": extra_v,
    }
    row.update(_event_hot_columns(event_type=event_type, extra=extra_v))
    return row


def _write_clickhouse_events(*, ch_client: Any, hot_rows: List[Dict[str, Any]]) -> int:
    """Backward-compatible wrapper for tests and legacy imports."""
    return write_clickhouse_events(ch_client=ch_client, hot_rows=hot_rows)


def _try_bootstrap_clickhouse() -> Any | None:
    try:
        ch_client = get_clickhouse_client()
        ok = ensure_clickhouse_events_schema()
        if not ok:
            return None
        return ch_client
    except Exception:
        return None


@dataclass
class _SinkTask:
    payload: List[Dict[str, Any]]
    retries: int = 0
    enqueued_at: float = field(default_factory=time.monotonic)


class _OptionalSinkRuntime:
    def __init__(self, *, cfg: WorkerConfig, redis_client: Any) -> None:
        self.cfg = cfg
        self.r = redis_client
        self.clickhouse_q: queue.Queue[_SinkTask] = queue.Queue(maxsize=max(1, int(cfg.clickhouse_sink_queue_max_batches)))
        self.warm_q: queue.Queue[_SinkTask] = queue.Queue(maxsize=max(1, int(cfg.warm_sink_queue_max_batches)))
        self._stop = threading.Event()

    def start(self) -> None:
        if self.cfg.clickhouse_enabled:
            threading.Thread(target=self._clickhouse_loop, name="ingest-sink-clickhouse", daemon=True).start()
        else:
            _set_clickhouse_state(self.r, state="disabled")
            set_sink_queue_depth(sink="clickhouse", depth=0)

        if self.cfg.warm_enabled:
            threading.Thread(target=self._warm_loop, name="ingest-sink-warm", daemon=True).start()
        else:
            set_sink_queue_depth(sink="warm", depth=0)

    def enqueue_clickhouse(self, rows: List[Dict[str, Any]]) -> bool:
        if not self.cfg.clickhouse_enabled:
            return False
        return self._enqueue(queue_obj=self.clickhouse_q, sink="clickhouse", payload=rows)

    def enqueue_warm(self, rows: List[Dict[str, Any]]) -> bool:
        if not self.cfg.warm_enabled:
            return False
        return self._enqueue(queue_obj=self.warm_q, sink="warm", payload=rows)

    def _enqueue(self, *, queue_obj: queue.Queue[_SinkTask], sink: str, payload: List[Dict[str, Any]]) -> bool:
        if not payload:
            return True
        task = _SinkTask(payload=list(payload))
        try:
            queue_obj.put_nowait(task)
            q_depth = queue_obj.qsize()
            set_sink_queue_depth(sink=sink, depth=q_depth)
            record_sink_runtime_metric(sink=sink, metric="enqueued_batches", value=1)
            record_sink_runtime_metric(sink=sink, metric="enqueued_events", value=len(task.payload))
            observe_hist("ingest_optional_sink_queue_depth", float(q_depth), sink=sink)
            return True
        except queue.Full:
            record_sink_runtime_metric(sink=sink, metric="dropped_batches", value=1)
            record_sink_runtime_metric(sink=sink, metric="dropped_events", value=len(task.payload))
            set_sink_queue_depth(sink=sink, depth=queue_obj.qsize())
            incr_counter("ingest_optional_sink_dropped_total", value=float(len(task.payload)), sink=sink, reason="queue_full")
            log_event(logger, "warning", "ingest_optional_sink_queue_full", sink=sink, dropped_events=len(task.payload))
            return False

    def _requeue_or_drop(self, *, queue_obj: queue.Queue[_SinkTask], sink: str, task: _SinkTask) -> None:
        retries = int(task.retries or 0)
        if retries >= int(self.cfg.sink_max_batch_retries):
            record_sink_runtime_metric(sink=sink, metric="dropped_batches", value=1)
            record_sink_runtime_metric(sink=sink, metric="dropped_events", value=len(task.payload))
            incr_counter(
                "ingest_optional_sink_dropped_total",
                value=float(len(task.payload)),
                sink=sink,
                reason="max_retries",
            )
            log_event(
                logger,
                "warning",
                "ingest_optional_sink_drop_after_retry",
                sink=sink,
                retries=retries,
                dropped_events=len(task.payload),
            )
            return

        retry_task = _SinkTask(payload=list(task.payload), retries=retries + 1, enqueued_at=task.enqueued_at)
        try:
            queue_obj.put_nowait(retry_task)
            set_sink_queue_depth(sink=sink, depth=queue_obj.qsize())
        except queue.Full:
            record_sink_runtime_metric(sink=sink, metric="dropped_batches", value=1)
            record_sink_runtime_metric(sink=sink, metric="dropped_events", value=len(task.payload))
            incr_counter(
                "ingest_optional_sink_dropped_total",
                value=float(len(task.payload)),
                sink=sink,
                reason="retry_queue_full",
            )
            log_event(
                logger,
                "warning",
                "ingest_optional_sink_retry_queue_full",
                sink=sink,
                dropped_events=len(task.payload),
            )

    def _clickhouse_loop(self) -> None:
        ch = None
        next_retry_at = 0.0
        _set_clickhouse_state(self.r, state="degraded", error_type="starting")
        set_sink_queue_depth(sink="clickhouse", depth=0)

        while not self._stop.is_set():
            try:
                task = self.clickhouse_q.get(timeout=0.5)
            except queue.Empty:
                continue

            set_sink_queue_depth(sink="clickhouse", depth=self.clickhouse_q.qsize())
            started = time.perf_counter()
            try:
                if ch is None and time.monotonic() >= next_retry_at:
                    ch = _try_bootstrap_clickhouse()
                    if ch is None:
                        reset_clickhouse_client()
                        next_retry_at = time.monotonic() + self.cfg.clickhouse_reconnect_seconds
                        _set_clickhouse_state(self.r, state="degraded", error_type="unavailable")
                if ch is None:
                    self._requeue_or_drop(queue_obj=self.clickhouse_q, sink="clickhouse", task=task)
                    record_sink_runtime_metric(sink="clickhouse", metric="failed_batches", value=1)
                    continue

                written = _write_clickhouse_events(ch_client=ch, hot_rows=task.payload)
                _record_clickhouse_progress(self.r, rows=written)
                _set_clickhouse_state(self.r, state="available")
                record_sink_runtime_metric(sink="clickhouse", metric="processed_batches", value=1)
                record_sink_runtime_metric(sink="clickhouse", metric="processed_events", value=written)
                observe_hist("ingest_optional_sink_latency_seconds", time.perf_counter() - started, sink="clickhouse", outcome="ok")
            except Exception as exc:
                ch = None
                reset_clickhouse_client()
                next_retry_at = time.monotonic() + self.cfg.clickhouse_reconnect_seconds
                _set_clickhouse_state(self.r, state="degraded", error_type=type(exc).__name__)
                record_sink_runtime_metric(sink="clickhouse", metric="failed_batches", value=1)
                observe_hist(
                    "ingest_optional_sink_latency_seconds",
                    time.perf_counter() - started,
                    sink="clickhouse",
                    outcome="error",
                )
                log_event(
                    logger,
                    "warning",
                    "ingest_clickhouse_write_error",
                    error_type=type(exc).__name__,
                    batch_rows=len(task.payload),
                    retries=int(task.retries or 0),
                )
                self._requeue_or_drop(queue_obj=self.clickhouse_q, sink="clickhouse", task=task)
            finally:
                self.clickhouse_q.task_done()
                set_sink_queue_depth(sink="clickhouse", depth=self.clickhouse_q.qsize())

    def _warm_loop(self) -> None:
        es = None
        template_ready = False
        next_retry_at = 0.0
        set_sink_queue_depth(sink="warm", depth=0)

        while not self._stop.is_set():
            try:
                task = self.warm_q.get(timeout=0.5)
            except queue.Empty:
                continue

            set_sink_queue_depth(sink="warm", depth=self.warm_q.qsize())
            started = time.perf_counter()
            try:
                if es is None and time.monotonic() >= next_retry_at:
                    es = _build_es_client(self.cfg)
                    if not es.ping():
                        es = None
                        next_retry_at = time.monotonic() + 2.0
                        template_ready = False
                if es is None:
                    record_sink_runtime_metric(sink="warm", metric="failed_batches", value=1)
                    self._requeue_or_drop(queue_obj=self.warm_q, sink="warm", task=task)
                    continue
                if not template_ready:
                    _ensure_warm_ilm_and_template(es, self.cfg)
                    template_ready = True

                from elasticsearch import helpers

                actions: List[Dict[str, Any]] = []
                for wd in task.payload:
                    idx = _index_for(self.cfg.warm_index_prefix, wd["timestamp"])
                    actions.append({"_op_type": "index", "_index": idx, "_source": _to_doc(wd)})
                helpers.bulk(
                    es,
                    actions,
                    request_timeout=self.cfg.es_request_timeout_seconds,
                    raise_on_error=False,
                    raise_on_exception=False,
                )
                record_sink_runtime_metric(sink="warm", metric="processed_batches", value=1)
                record_sink_runtime_metric(sink="warm", metric="processed_events", value=len(task.payload))
                observe_hist("ingest_optional_sink_latency_seconds", time.perf_counter() - started, sink="warm", outcome="ok")
            except Exception as exc:
                record_sink_runtime_metric(sink="warm", metric="failed_batches", value=1)
                observe_hist("ingest_optional_sink_latency_seconds", time.perf_counter() - started, sink="warm", outcome="error")
                log_event(
                    logger,
                    "warning",
                    "ingest_warm_index_error",
                    error_type=type(exc).__name__,
                    batch_rows=len(task.payload),
                    retries=int(task.retries or 0),
                )
                es = None
                template_ready = False
                next_retry_at = time.monotonic() + 2.0
                self._requeue_or_drop(queue_obj=self.warm_q, sink="warm", task=task)
            finally:
                self.warm_q.task_done()
                set_sink_queue_depth(sink="warm", depth=self.warm_q.qsize())


def main() -> None:
    settings.validate_for_service("worker-ingest")
    cfg = load_config()

    ensure_database_ready()

    r = get_redis()
    if r is None:
        log_event(logger, "error", "ingest_redis_unavailable")
        while True:
            time.sleep(2.0)

    _requeue_processing(r, cfg)
    worker_id = f"ingest-{uuid.uuid4().hex[:8]}"
    sink_runtime = _OptionalSinkRuntime(cfg=cfg, redis_client=r)
    sink_runtime.start()

    backoff = 0.25

    while True:
        try:
            worker_heartbeat(worker_id)

            item = r.brpoplpush(cfg.queue_key, cfg.processing_key, timeout=1)
            if not item:
                storm_maybe_close_alert()
                time.sleep(cfg.idle_sleep_seconds)
                continue

            # Collect up to N messages (non-blocking)
            items = [item]
            for _ in range(cfg.batch_messages - 1):
                nxt = r.rpoplpush(cfg.queue_key, cfg.processing_key)
                if not nxt:
                    break
                items.append(nxt)

            hot_rows: List[Dict[str, Any]] = []
            analytics_rows: List[Dict[str, Any]] = []
            rollup_rows: List[Dict[str, Any]] = []
            warm_docs: List[Dict[str, Any]] = []

            total_received = 0
            received_by_raw: Dict[str, int] = {}

            for raw in items:
                msg = json.loads(raw)
                received = int(msg.get("received") or 0)
                total_received += received
                received_by_raw[str(raw)] = received_by_raw.get(str(raw), 0) + max(0, int(received))

                # Ensure the 'Ingest Storm Detected' alert exists even if the API
                # couldn't write it during peak DB pressure.
                try:
                    mode = str(msg.get("mode") or "normal")
                    pressure = bool(msg.get("storm_active")) or mode != "normal"
                    if pressure:
                        storm_maybe_open_alert(
                            reason=str(msg.get("storm_reason") or mode)[:64],
                            sample_hot=int(msg.get("sample_hot_percent") or 0),
                            sample_warm=int(msg.get("sample_warm_percent") or 0),
                        )
                except Exception:
                    # fail open
                    pass

                # hot
                for ev in msg.get("hot_events") or []:
                    row = _event_from_wire(ev)
                    if row is not None:
                        hot_rows.append(row)

                for ev in msg.get("analytics_events") or []:
                    row = _event_from_wire(ev)
                    if row is not None:
                        analytics_rows.append(row)

                # rollups
                for rr in msg.get("rollups") or []:
                    try:
                        bts = datetime.fromisoformat(rr[0])
                    except Exception:
                        bts = datetime.utcnow()
                    rollup_rows.append(
                        {
                            "bucket_ts": bts,
                            "agent_id": rr[1],
                            "event_type": rr[2],
                            "dst_ip": rr[3],
                            "dst_port": rr[4],
                            "proto": rr[5],
                            "count": int(rr[6] or 0),
                            "bytes_sum": int(rr[7] or 0),
                        }
                    )

                # warm
                if cfg.warm_enabled:
                    for ev in msg.get("warm_events") or []:
                        agent_id = ev[0] if len(ev) > 0 else None
                        event_type = ev[1] if len(ev) > 1 else None
                        if not agent_id or not event_type:
                            continue

                        try:
                            ts = datetime.fromisoformat(ev[3]) if (len(ev) > 3 and ev[3]) else datetime.utcnow()
                        except Exception:
                            ts = datetime.utcnow()

                        try:
                            schema_v = int(ev[2] or 1)
                        except Exception:
                            schema_v = 1

                        bytes_v = ev[9] if (len(ev) > 9) else None
                        try:
                            bytes_v = int(bytes_v) if bytes_v is not None else 0
                        except Exception:
                            bytes_v = 0

                        warm_docs.append(
                            {
                                "agent_id": agent_id,
                                "event_type": event_type,
                                "schema_version": schema_v,
                                "timestamp": ts,
                                "src_ip": ev[4] if (len(ev) > 4 and ev[4]) else None,
                                "dst_ip": ev[5] if (len(ev) > 5 and ev[5]) else None,
                                "src_port": int(ev[6]) if (len(ev) > 6 and ev[6] is not None) else None,
                                "dst_port": int(ev[7]) if (len(ev) > 7 and ev[7] is not None) else None,
                                "proto": ev[8] if (len(ev) > 8 and ev[8]) else None,
                                "bytes": bytes_v,
                                "extra": ev[10] if (len(ev) > 10 and isinstance(ev[10], dict)) else {},
                            }
                        )

            inserted_hot_rows: List[Dict[str, Any]] = []
            hot_path_started = time.perf_counter()

            # Persist in a single DB transaction.
            with engine.begin() as conn:
                if hot_rows:
                    inserted_hot_rows = _insert_hot_rows_with_pg_ids(conn, hot_rows)

                if rollup_rows:
                    ins = insert(NetEventRollup1sModel).values(rollup_rows)
                    upsert = ins.on_conflict_do_update(
                        index_elements=[
                            NetEventRollup1sModel.bucket_ts,
                            NetEventRollup1sModel.agent_id,
                            NetEventRollup1sModel.event_type,
                            NetEventRollup1sModel.dst_ip,
                            NetEventRollup1sModel.dst_port,
                            NetEventRollup1sModel.proto,
                        ],
                        set_={
                            "count": NetEventRollup1sModel.count + ins.excluded.count,
                            "bytes_sum": NetEventRollup1sModel.bytes_sum + ins.excluded.bytes_sum,
                        },
                    )
                    conn.execute(upsert)

            hot_id_by_fp = {_event_fingerprint(row): int(row.get("pg_event_id") or 0) for row in inserted_hot_rows}
            analytics_rows_for_ch: List[Dict[str, Any]] = []
            if analytics_rows:
                seen_fp: set[str] = set()
                for row in analytics_rows:
                    fp = _event_fingerprint(row)
                    if fp in seen_fp:
                        continue
                    seen_fp.add(fp)
                    item = dict(row)
                    mapped_pg_id = hot_id_by_fp.get(fp)
                    if mapped_pg_id:
                        item["pg_event_id"] = mapped_pg_id
                    analytics_rows_for_ch.append(item)

            if analytics_rows_for_ch and not sink_runtime.enqueue_clickhouse(analytics_rows_for_ch):
                log_event(
                    logger,
                    "warning",
                    "ingest_clickhouse_enqueue_drop",
                    dropped_rows=len(analytics_rows_for_ch),
                )

            if warm_docs and not sink_runtime.enqueue_warm(warm_docs):
                log_event(
                    logger,
                    "warning",
                    "ingest_warm_enqueue_drop",
                    dropped_rows=len(warm_docs),
                )

            observe_hist("ingest_hot_path_latency_seconds", time.perf_counter() - hot_path_started)

            # Ack processing list
            ack_ok = True
            removed_received = 0
            removed_messages = 0
            try:
                pipe = r.pipeline()
                for raw in items:
                    pipe.lrem(cfg.processing_key, 1, raw)
                results = pipe.execute() or []
                for raw, removed in zip(items, results):
                    if int(removed or 0) > 0:
                        removed_received += received_by_raw.get(str(raw), 0)
                        removed_messages += 1
            except Exception:
                # Retry ack per-message to reduce counter drift under Redis hiccups.
                ack_ok = False
                for raw in items:
                    try:
                        removed = int(r.lrem(cfg.processing_key, 1, raw) or 0)
                        if removed > 0:
                            removed_received += received_by_raw.get(str(raw), 0)
                            removed_messages += 1
                    except Exception:
                        continue

            if removed_received > 0:
                # Backlog counter
                _decr_backlog_events(r, removed_received)
                record_worker_progress(
                    processed_events=removed_received,
                    processed_messages=removed_messages,
                )
            elif ack_ok:
                # Defensive fallback for malformed received counters.
                _decr_backlog_events(r, total_received)
                record_worker_progress(processed_events=max(0, total_received), processed_messages=len(items))
            else:
                try:
                    plen = int(r.llen(cfg.processing_key) or 0)
                except Exception:
                    plen = -1
                # If ACK partially failed, immediately salvage leftovers from processing.
                # This avoids ghost items pinning backlog forever after storm recovery.
                try:
                    _requeue_processing_with_retry_cap(r, cfg)
                except Exception:
                    pass
                log_event(
                    logger,
                    "warning",
                    "ingest_ack_failed",
                    processing_len=plen,
                    removed_received=removed_received,
                    total_received=total_received,
                )

            storm_maybe_close_alert()

            backoff = 0.25

        except Exception as e:
            # If the DB transaction failed, items may be stuck in the processing list.
            # Re-queue them so we can retry after backoff.
            try:
                _requeue_processing_with_retry_cap(r, cfg)
            except Exception:
                pass

            col = getattr(getattr(e, "diag", None), "column_name", None)
            tbl = getattr(getattr(e, "diag", None), "table_name", None)
            msg = f"[INGEST] error={type(e).__name__}"
            if tbl or col:
                msg += f" table={tbl} column={col}"
            msg += f" backoff={backoff}"
            log_event(logger, "error", "ingest_loop_error", message=msg)
            time.sleep(backoff)
            backoff = min(5.0, backoff * 1.8)


if __name__ == "__main__":
    main()
