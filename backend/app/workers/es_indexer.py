"""Elasticsearch forwarder (async indexing).

Design goals:
- Keep Postgres as the source of truth.
- Index events into Elasticsearch for fast hunting / full-text search.
- Avoid impacting ingest path: this worker polls DB and indexes in batches.

Operational notes:
- Uses a simple offset table: search_index_offsets(name='events').
- Indexing uses daily indices: <prefix>-YYYY.MM.DD
- Mappings are kept stable via an index template (optional bootstrap).
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import OperationalError

from app.core.db import engine
from app.core.schema_bootstrap import bootstrap_schema
from app.models.events import NetEventModel
from app.models.search_index_offsets import SearchIndexOffsetModel


@dataclass(frozen=True)
class ESConfig:
    url: str
    index_prefix: str
    batch_size: int
    every_seconds: float
    idle_sleep_seconds: float
    request_timeout_seconds: int
    bootstrap: bool
    ilm_enabled: bool
    ilm_delete_after_days: int
    ilm_policy_name: str
    username: Optional[str]
    password: Optional[str]
    verify_certs: bool
    ca_certs: Optional[str]


def _env_str(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(name)
    if v is None:
        return default
    v = v.strip()
    return v if v else default


def _env_int(name: str, default: int) -> int:
    v = _env_str(name)
    if v is None:
        return default
    try:
        return int(v, 10)
    except Exception:
        return default


def _env_float(name: str, default: float) -> float:
    v = _env_str(name)
    if v is None:
        return default
    try:
        return float(v)
    except Exception:
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    v = _env_str(name)
    if v is None:
        return default
    v = v.lower()
    return v in {"1", "true", "yes", "y", "on"}


def load_config() -> ESConfig:
    return ESConfig(
        url=_env_str("NETWATCH_ES_URL", "http://elasticsearch:9200") or "http://elasticsearch:9200",
        index_prefix=_env_str("NETWATCH_ES_INDEX_PREFIX", "netwatch-events") or "netwatch-events",
        batch_size=max(1, _env_int("NETWATCH_ES_BATCH_SIZE", 500)),
        every_seconds=max(0.1, _env_float("NETWATCH_ES_EVERY_SECONDS", 1.0)),
        idle_sleep_seconds=max(0.25, _env_float("NETWATCH_ES_IDLE_SLEEP_SECONDS", 2.0)),
        request_timeout_seconds=max(5, _env_int("NETWATCH_ES_REQUEST_TIMEOUT_SECONDS", 30)),
        bootstrap=_env_bool("NETWATCH_ES_BOOTSTRAP", False),
        ilm_enabled=_env_bool("NETWATCH_ES_ILM_ENABLED", True),
        ilm_delete_after_days=max(1, _env_int("NETWATCH_ES_ILM_DELETE_AFTER_DAYS", 30)),
        ilm_policy_name=_env_str("NETWATCH_ES_ILM_POLICY_NAME", "") or "",
        username=_env_str("NETWATCH_ES_USERNAME", None),
        password=_env_str("NETWATCH_ES_PASSWORD", None),
        verify_certs=_env_bool("NETWATCH_ES_VERIFY_CERTS", True),
        ca_certs=_env_str("NETWATCH_ES_CA_CERTS", None),
    )


def _index_for(prefix: str, ts: datetime) -> str:
    # Daily indices keep rollover simple and avoid large shards on small clusters.
    return f"{prefix}-{ts.strftime('%Y.%m.%d')}"


def _to_doc(row: Dict[str, Any]) -> Dict[str, Any]:
    ts = row.get("timestamp")
    if isinstance(ts, datetime):
        ts_iso = ts.isoformat()
    else:
        ts_iso = str(ts) if ts is not None else None

    extra = row.get("extra") or {}
    if not isinstance(extra, dict):
        extra = {}

    # Derived/normalized fields (top-level) for fast aggregations.
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

    # Protocol intelligence fields
    app_proto = _as_str(extra.get("app_proto"))
    if app_proto:
        doc["app_proto"] = app_proto

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

    # Geo/ASN enrichment (if available)
    for k in ["geo_country", "geo_org", "asn", "asn_org"]:
        vv = _as_str(extra.get(k))
        if vv:
            doc[k] = vv

    # SSH enrichment
    if event_type == "ssh_auth":
        ssh_action = _as_str(extra.get("action"))
        if ssh_action:
            doc["ssh_action"] = ssh_action
        ssh_username = _as_str(extra.get("username"))
        if ssh_username:
            doc["ssh_username"] = ssh_username

    # Sudo enrichment
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

    # Remove None fields to reduce payload size.
    return {k: v for k, v in doc.items() if v is not None}



def _get_last_id() -> int:

    with engine.begin() as conn:
        conn.execute(
            insert(SearchIndexOffsetModel)
            .values(name="events", last_id=0)
            .on_conflict_do_nothing(index_elements=[SearchIndexOffsetModel.name])
        )
        row = conn.execute(
            select(SearchIndexOffsetModel.last_id).where(SearchIndexOffsetModel.name == "events").limit(1)
        ).fetchone()
        return int(row[0]) if row and row[0] is not None else 0


def _set_last_id(last_id: int) -> None:
    with engine.begin() as conn:
        conn.execute(
            update(SearchIndexOffsetModel)
            .where(SearchIndexOffsetModel.name == "events")
            .values(last_id=int(last_id), updated_at=datetime.utcnow())
        )


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
    # TLS knobs: useful if you later enable security (https + CA).
    kwargs["verify_certs"] = cfg.verify_certs
    if cfg.ca_certs:
        kwargs["ca_certs"] = cfg.ca_certs

    return Elasticsearch(cfg.url, **kwargs)


def _ensure_index_template(es, cfg: ESConfig) -> None:
    """Create a composable index template for predictable mappings.

    This is optional (controlled by NETWATCH_ES_BOOTSTRAP).
    """

    name = f"{cfg.index_prefix}-template"
    try:
        exists = es.indices.exists_index_template(name=name)
    except Exception:
        exists = False

    if exists:
        return

    body = {
        "index_patterns": [f"{cfg.index_prefix}-*"],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "refresh_interval": "5s",
            },
            "mappings": {
                "dynamic": True,
                "properties": {
                    "@timestamp": {"type": "date"},
                    "timestamp": {"type": "date"},
                    "id": {"type": "long"},
                    "schema_version": {"type": "short"},
                    "agent_id": {"type": "keyword"},
                    "event_type": {"type": "keyword"},
                    "proto": {"type": "keyword"},
                    "src_ip": {"type": "ip"},
                    "dst_ip": {"type": "ip"},
                    "src_port": {"type": "integer"},
                    "dst_port": {"type": "integer"},
                    "bytes": {"type": "long"},

                    # Protocol Intel (top-level, normalized)
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

                    # Enrichment (optional)
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

                    # Prevent mapping explosions from arbitrary JSON.
                    # 'flattened' is a good fit for SIEM "extra" payloads.
                    "extra": {"type": "flattened"},
                },
            },
        },
        "priority": 200,
        "_meta": {
            "project": "dynasmon-netwatch",
            "component": "es_indexer",
        },
    }

    es.indices.put_index_template(name=name, body=body)
    print(f"[ES] created_index_template name={name}")


def _bulk_index(es, actions: Iterable[Dict[str, Any]], cfg: ESConfig) -> None:
    from elasticsearch import helpers

    # helpers.bulk returns (success_count, errors)
    success, errors = helpers.bulk(
        es,
        actions,
        request_timeout=cfg.request_timeout_seconds,
        raise_on_error=False,
        raise_on_exception=False,
    )

    if errors:
        # Keep logs concise; full error payloads can be huge.
        sample = errors[0]
        print(f"[ES] bulk_partial_success success={success} errors={len(errors)} sample={sample}")
    else:
        print(f"[ES] bulk_ok success={success}")


def main() -> None:
    cfg = load_config()

    # Ensure DB bootstrap changes exist even if this worker starts early.
    bootstrap_schema(engine)

    es = _build_es_client(cfg)

    backoff = 1.0
    while True:
        try:
            if not es.ping():
                raise RuntimeError("elasticsearch_ping_failed")

            if cfg.bootstrap:
                _ensure_index_template(es, cfg)

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
                ts = r.get("timestamp")
                if not isinstance(ts, datetime):
                    # Fallback to now if timestamp is missing/invalid.
                    ts = datetime.utcnow()

                actions.append(
                    {
                        "_op_type": "index",
                        "_index": _index_for(cfg.index_prefix, ts),
                        "_id": doc_id,
                        "_source": _to_doc(r),
                    }
                )

            _bulk_index(es, actions, cfg)
            _set_last_id(max_id)
            backoff = 1.0

            # Small pause to avoid monopolizing CPU under continuous load.
            time.sleep(cfg.every_seconds)

        except OperationalError as e:
            wait_s = min(backoff, 15.0)
            print(f"[ES_INDEXER] db_not_ready wait_s={wait_s} error={str(e).splitlines()[0]}")
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 15.0)
        except Exception as e:
            wait_s = min(backoff, 15.0)
            print(f"[ES_INDEXER] error wait_s={wait_s} error={repr(e)}")
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 15.0)


if __name__ == "__main__":
    main()
