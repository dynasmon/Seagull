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
import os
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from psycopg2.extras import Json, execute_values

from app.core.db import engine
from app.core.redis_client import get_redis
from app.core.schema_bootstrap import bootstrap_schema
from app.core.ingest_control import storm_maybe_close_alert, storm_maybe_open_alert


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


def _env_str(name: str, default: str) -> str:
    v = os.getenv(name)
    if v is None:
        return default
    v = v.strip()
    return v if v else default


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
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
    v = os.getenv(name)
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
    v = os.getenv(name)
    if v is None:
        return default
    s = v.strip().lower()
    if s in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "f", "no", "n", "off"}:
        return False
    return default


def load_config() -> WorkerConfig:
    qk = _env_str("NETWATCH_INGEST_QUEUE_KEY", "netwatch:ingest:queue")
    return WorkerConfig(
        queue_key=qk,
        processing_key=_env_str("NETWATCH_INGEST_PROCESSING_KEY", f"{qk}:processing"),
        batch_messages=max(1, _env_int("NETWATCH_INGEST_WORKER_BATCH_MESSAGES", 50)),
        idle_sleep_seconds=max(0.1, _env_float("NETWATCH_INGEST_WORKER_IDLE_SLEEP_SECONDS", 0.25)),
        values_page_size=max(100, _env_int("NETWATCH_INGEST_VALUES_PAGE_SIZE", 1000)),
        rollup_page_size=max(100, _env_int("NETWATCH_INGEST_ROLLUP_PAGE_SIZE", 500)),
        warm_enabled=_env_bool("NETWATCH_INGEST_WARM_ENABLED", True),
        es_url=_env_str("NETWATCH_ES_URL", "http://elasticsearch:9200"),
        es_index_prefix=_env_str("NETWATCH_ES_INDEX_PREFIX", "netwatch-events"),
        warm_index_prefix=_env_str("NETWATCH_INGEST_WARM_INDEX_PREFIX", _env_str("NETWATCH_ES_INDEX_PREFIX", "netwatch-events") + "-warm"),
        warm_ilm_enabled=_env_bool("NETWATCH_INGEST_WARM_ILM_ENABLED", True),
        warm_ilm_policy=_env_str("NETWATCH_INGEST_WARM_ILM_POLICY", "netwatch-warm-delete-30d"),
        warm_ilm_delete_after_days=max(1, _env_int("NETWATCH_INGEST_WARM_ILM_DELETE_AFTER_DAYS", 30)),
        es_request_timeout_seconds=max(5, _env_int("NETWATCH_ES_REQUEST_TIMEOUT_SECONDS", 30)),
    )


def _build_es_client(cfg: WorkerConfig):
    from elasticsearch import Elasticsearch

    return Elasticsearch(cfg.es_url, request_timeout=cfg.es_request_timeout_seconds)


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
        print(f"[INGEST] ilm_policy_error={type(e).__name__}")
        return

    # Create index template for warm indexes
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
                "project": "dynasmon-netwatch",
                "component": "ingest_worker",
                "tier": "warm",
            },
        }

        es.indices.put_index_template(name=name, body=body)
    except Exception as e:
        print(f"[INGEST] warm_template_error={type(e).__name__}")
        return

    print(f"[INGEST] warm_ilm_ready prefix={cfg.warm_index_prefix} policy={policy_name}")


def _requeue_processing(r, cfg: WorkerConfig) -> None:
    """Move any leftover processing items back to the main queue."""

    try:
        while True:
            item = r.rpoplpush(cfg.processing_key, cfg.queue_key)
            if not item:
                break
    except Exception:
        return


def _decr_backlog_events(r, received: int) -> None:
    """Decrease backlog counter and clamp to 0.

    Under Redis hiccups or worker restarts, the counter can drift. Negative
    values break backpressure evaluation (ingest may stop protecting itself).
    """

    try:
        key = _env_str("NETWATCH_INGEST_BACKLOG_EVENTS_KEY", "netwatch:ingest:backlog_events")
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


def main() -> None:
    cfg = load_config()

    bootstrap_schema(engine)

    r = get_redis()
    if r is None:
        print("[INGEST] redis_unavailable")
        while True:
            time.sleep(2.0)

    _requeue_processing(r, cfg)

    es = None
    if cfg.warm_enabled:
        try:
            es = _build_es_client(cfg)
            if not es.ping():
                es = None
            else:
                _ensure_warm_ilm_and_template(es, cfg)
        except Exception:
            es = None

    backoff = 0.25

    while True:
        try:
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

            hot_rows: List[Tuple] = []
            rollup_rows: List[Tuple] = []
            warm_docs: List[Dict[str, Any]] = []
            warm_actions: List[Dict[str, Any]] = []

            total_received = 0

            for raw in items:
                msg = json.loads(raw)
                received = int(msg.get("received") or 0)
                total_received += received

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
                    # Defensive: older queued messages may contain nulls / missing fields.
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

                    hot_rows.append(
                        (
                            agent_id,
                            event_type,
                            schema_v,
                            ts,
                            src_ip,
                            dst_ip,
                            src_port,
                            dst_port,
                            proto,
                            bytes_v,
                            Json(extra_v, dumps=json.dumps),
                        )
                    )

                # rollups
                for rr in msg.get("rollups") or []:
                    try:
                        bts = datetime.fromisoformat(rr[0])
                    except Exception:
                        bts = datetime.utcnow()
                    rollup_rows.append(
                        (
                            bts,
                            rr[1],
                            rr[2],
                            rr[3],
                            rr[4],
                            rr[5],
                            int(rr[6] or 0),
                            int(rr[7] or 0),
                        )
                    )

                # warm
                if es is not None and cfg.warm_enabled:
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

            # Persist in a single DB transaction.
            conn = engine.raw_connection()
            try:
                cur = conn.cursor()

                if hot_rows:
                    cols = (
                        "agent_id",
                        "event_type",
                        "schema_version",
                        "timestamp",
                        "src_ip",
                        "dst_ip",
                        "src_port",
                        "dst_port",
                        "proto",
                        "bytes",
                        "extra",
                    )
                    sql = f"INSERT INTO net_events ({', '.join(cols)}) VALUES %s"
                    execute_values(cur, sql, hot_rows, page_size=cfg.values_page_size)

                if rollup_rows:
                    rollup_sql = """
                        INSERT INTO net_event_rollups_1s (
                            bucket_ts, agent_id, event_type, dst_ip, dst_port, proto, count, bytes_sum
                        ) VALUES %s
                        ON CONFLICT (bucket_ts, agent_id, event_type, dst_ip, dst_port, proto)
                        DO UPDATE SET
                            count = net_event_rollups_1s.count + EXCLUDED.count,
                            bytes_sum = net_event_rollups_1s.bytes_sum + EXCLUDED.bytes_sum;
                    """
                    execute_values(cur, rollup_sql, rollup_rows, page_size=cfg.rollup_page_size)

                conn.commit()
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

            # Warm indexing (best-effort)
            if es is not None and warm_docs:
                try:
                    from elasticsearch import helpers

                    for wd in warm_docs:
                        idx = _index_for(cfg.warm_index_prefix, wd["timestamp"])
                        doc = _to_doc(wd)
                        warm_actions.append({"_op_type": "index", "_index": idx, "_source": doc})

                    helpers.bulk(
                        es,
                        warm_actions,
                        request_timeout=cfg.es_request_timeout_seconds,
                        raise_on_error=False,
                        raise_on_exception=False,
                    )
                except Exception as e:
                    print(f"[INGEST] warm_index_error={type(e).__name__}")

            # Ack processing list
            ack_ok = True
            try:
                pipe = r.pipeline()
                for raw in items:
                    pipe.lrem(cfg.processing_key, 1, raw)
                pipe.execute()
            except Exception:
                # If we fail to ack, the message can be re-queued on restart.
                # Keeping backlog counters intact is safer than going negative.
                ack_ok = False

            if ack_ok:
                # Backlog counter
                _decr_backlog_events(r, total_received)
            else:
                try:
                    plen = int(r.llen(cfg.processing_key) or 0)
                except Exception:
                    plen = -1
                print(f"[INGEST] warn=ack_failed processing_len={plen}")

            storm_maybe_close_alert()

            backoff = 0.25

        except Exception as e:
            # If the DB transaction failed, items may be stuck in the processing list.
            # Re-queue them so we can retry after backoff.
            try:
                _requeue_processing(r, cfg)
            except Exception:
                pass

            col = getattr(getattr(e, "diag", None), "column_name", None)
            tbl = getattr(getattr(e, "diag", None), "table_name", None)
            msg = f"[INGEST] error={type(e).__name__}"
            if tbl or col:
                msg += f" table={tbl} column={col}"
            msg += f" backoff={backoff}"
            print(msg)
            time.sleep(backoff)
            backoff = min(5.0, backoff * 1.8)


if __name__ == "__main__":
    main()
