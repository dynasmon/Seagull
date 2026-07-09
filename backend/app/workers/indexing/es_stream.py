from __future__ import annotations

import json
import logging
import os
import socket
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import redis

from app.core.config import settings
from app.core.config.env_secrets import env_value, getenv_compat
from app.core.observability import incr_counter, init_counter, log_event, observe_hist, set_gauge, setup_logging
from app.shared.es_hosts import es_hosts
from app.shared.indexing.es_doc import build_event_doc
from app.workers.indexing.es_bootstrap import ESConfig, bootstrap, load_config

setup_logging("worker-es-indexer-stream")
logger = logging.getLogger("seagull.worker.es_indexer_stream")

_READ_TIMEOUT_ERRORS: Tuple[type, ...] = (redis.exceptions.TimeoutError, TimeoutError)


def _env_str(name: str, default: str) -> str:
    return env_value(name, default) or default


def _env_int(name: str, default: int) -> int:
    v = getenv_compat(name)
    if v is None or not v.strip():
        return default
    try:
        return int(v.strip(), 10)
    except Exception:
        return default


def _env_float(name: str, default: float) -> float:
    v = getenv_compat(name)
    if v is None or not v.strip():
        return default
    try:
        return float(v.strip())
    except Exception:
        return default


def _default_consumer_name() -> str:
    for candidate in (os.environ.get("SEAGULL_WORKER_PROCESS"), os.environ.get("HOSTNAME")):
        if candidate and candidate.strip():
            return candidate.strip()
    try:
        host = socket.gethostname().strip()
    except Exception:
        host = ""
    return host or "es-indexer"


@dataclass(frozen=True)
class ESStreamConfig:
    stream_key: str
    group: str
    consumer: str
    batch_size: int
    block_ms: int
    max_retries: int
    start_id: str
    dlq_key: str
    dlq_maxlen: int
    attempts_key: str
    claim_min_idle_ms: int
    housekeeping_seconds: float
    backlog_alert_threshold: int
    retry_backoff_seconds: float
    retry_backoff_max_seconds: float


def load_stream_config() -> ESStreamConfig:
    stream_key = _env_str("SEAGULL_ES_STREAM_KEY", "seagull:events:index")
    return ESStreamConfig(
        stream_key=stream_key,
        group=_env_str("SEAGULL_ES_STREAM_GROUP", "es-indexer"),
        consumer=_env_str("SEAGULL_ES_STREAM_CONSUMER", _default_consumer_name()),
        batch_size=min(5000, max(1, _env_int("SEAGULL_ES_STREAM_BATCH_SIZE", 500))),
        block_ms=min(60000, max(100, _env_int("SEAGULL_ES_STREAM_BLOCK_MS", 5000))),
        max_retries=max(1, _env_int("SEAGULL_ES_STREAM_MAX_RETRIES", 5)),
        start_id=_env_str("SEAGULL_ES_STREAM_START_ID", "$"),
        dlq_key=_env_str("SEAGULL_ES_STREAM_DLQ_KEY", f"{stream_key}:dlq"),
        dlq_maxlen=max(1000, _env_int("SEAGULL_ES_STREAM_DLQ_MAXLEN", 100000)),
        attempts_key=_env_str("SEAGULL_ES_STREAM_ATTEMPTS_KEY", f"{stream_key}:attempts"),
        claim_min_idle_ms=max(1000, _env_int("SEAGULL_ES_STREAM_CLAIM_MIN_IDLE_MS", 30000)),
        housekeeping_seconds=max(1.0, _env_float("SEAGULL_ES_STREAM_HOUSEKEEPING_SECONDS", 5.0)),
        backlog_alert_threshold=max(1, _env_int("SEAGULL_ES_STREAM_BACKLOG_ALERT", 100000)),
        retry_backoff_seconds=max(0.05, _env_float("SEAGULL_ES_STREAM_RETRY_BACKOFF_SECONDS", 0.5)),
        retry_backoff_max_seconds=max(1.0, _env_float("SEAGULL_ES_STREAM_RETRY_BACKOFF_MAX_SECONDS", 15.0)),
    )


@dataclass
class _Entry:
    entry_id: str
    row: Dict[str, Any]
    raw: str


def _build_es_client(cfg: ESConfig) -> Any:
    from elasticsearch import Elasticsearch

    kwargs: Dict[str, Any] = {"request_timeout": cfg.request_timeout_seconds}
    if cfg.username and cfg.password:
        kwargs["basic_auth"] = (cfg.username, cfg.password)
    kwargs["verify_certs"] = cfg.verify_certs
    if cfg.ca_certs:
        kwargs["ca_certs"] = cfg.ca_certs
    return Elasticsearch(es_hosts(cfg.url), **kwargs)


def _build_redis_client(cfg: ESStreamConfig) -> "redis.Redis":
    socket_timeout = max(1.0, cfg.block_ms / 1000.0 + 5.0)
    return redis.Redis(
        host=getattr(settings, "SEAGULL_REDIS_HOST", "redis"),
        port=int(getattr(settings, "SEAGULL_REDIS_PORT", 6379)),
        username=getattr(settings, "SEAGULL_REDIS_USERNAME", None) or None,
        password=getattr(settings, "SEAGULL_REDIS_PASSWORD", None) or None,
        decode_responses=True,
        socket_connect_timeout=5.0,
        socket_timeout=socket_timeout,
        health_check_interval=30,
    )


def _run_bulk(es: Any, actions: List[Dict[str, Any]], request_timeout: int) -> Tuple[int, List[Any]]:
    from elasticsearch import helpers

    return helpers.bulk(
        es,
        actions,
        request_timeout=request_timeout,
        raise_on_error=False,
        raise_on_exception=False,
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _ensure_group(r: Any, cfg: ESStreamConfig) -> None:
    try:
        r.xgroup_create(name=cfg.stream_key, groupname=cfg.group, id=cfg.start_id, mkstream=True)
        log_event(logger, "info", "es_stream_group_created", stream=cfg.stream_key, group=cfg.group, start_id=cfg.start_id)
    except Exception as exc:
        if "BUSYGROUP" in str(exc):
            return
        raise


def _extract_stream_entries(resp: Any) -> List[_Entry]:
    out: List[_Entry] = []
    for stream_row in resp or []:
        if not isinstance(stream_row, (tuple, list)) or len(stream_row) != 2:
            continue
        entries = stream_row[1]
        if not isinstance(entries, (list, tuple)):
            continue
        for entry_row in entries:
            parsed = _parse_entry(entry_row)
            if parsed is not None:
                out.append(parsed)
    return out


def _extract_claim_entries(resp: Any) -> Tuple[str, List[_Entry]]:
    cursor = "0-0"
    messages: Any = []
    if isinstance(resp, (tuple, list)):
        if len(resp) >= 1:
            cursor = str(resp[0])
        if len(resp) >= 2:
            messages = resp[1]
    out: List[_Entry] = []
    for entry_row in messages or []:
        parsed = _parse_entry(entry_row)
        if parsed is not None:
            out.append(parsed)
    return cursor, out


def _parse_entry(entry_row: Any) -> Optional[_Entry]:
    if not isinstance(entry_row, (tuple, list)) or len(entry_row) != 2:
        return None
    entry_id = str(entry_row[0])
    fields = entry_row[1]
    if not isinstance(fields, dict):
        return None
    raw = fields.get("event") or fields.get(b"event")
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    if not isinstance(raw, str) or not raw.strip():
        return _Entry(entry_id=entry_id, row={}, raw="")
    try:
        row = json.loads(raw)
        if not isinstance(row, dict):
            row = {}
    except Exception:
        row = {}
    return _Entry(entry_id=entry_id, row=row, raw=raw)


def _is_permanent(status: int) -> bool:
    return 400 <= status < 500 and status != 429


def _parse_bulk_errors(errors: List[Any]) -> Dict[str, Tuple[int, str]]:
    out: Dict[str, Tuple[int, str]] = {}
    for err in errors or []:
        if not isinstance(err, dict):
            continue
        for op, info in err.items():
            if not isinstance(info, dict):
                continue
            doc_id = info.get("_id")
            if doc_id is None:
                continue
            status = 0
            try:
                status = int(info.get("status") or 0)
            except Exception:
                status = 0
            detail = info.get("error")
            reason = ""
            if isinstance(detail, dict):
                reason = str(detail.get("type") or detail.get("reason") or "")[:80]
            elif detail:
                reason = str(detail)[:80]
            out[str(doc_id)] = (status, reason or str(op))
    return out


def _observe_lag(row: Dict[str, Any], now_epoch: float) -> None:
    ts = row.get("timestamp")
    if not isinstance(ts, str) or not ts:
        return
    try:
        parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    lag = now_epoch - parsed.timestamp()
    if lag >= 0:
        observe_hist("es_indexer_lag_seconds", lag)


def _dlq(r: Any, cfg: ESStreamConfig, entry: _Entry, *, reason: str, error: str, doc_id: str) -> None:
    try:
        r.xadd(
            cfg.dlq_key,
            {
                "event": entry.raw or json.dumps(entry.row, ensure_ascii=False, default=str),
                "reason": reason,
                "error": error[:300],
                "doc_id": doc_id,
                "orig_entry_id": entry.entry_id,
                "failed_at": _now_iso(),
            },
            maxlen=cfg.dlq_maxlen,
            approximate=True,
        )
    except Exception as exc:
        log_event(logger, "error", "es_stream_dlq_write_failed", error=repr(exc), orig_entry_id=entry.entry_id)


def _process_batch(*, r: Any, es: Any, es_cfg: ESConfig, cfg: ESStreamConfig, entries: List[_Entry]) -> int:
    if not entries:
        return 0

    actions: List[Dict[str, Any]] = []
    by_docid: Dict[str, _Entry] = {}
    now_epoch = time.time()

    for entry in entries:
        doc = build_event_doc(entry.row)
        doc_id = doc.get("id")
        if doc_id is None:
            incr_counter("es_indexer_dlq_total", reason="missing_id")
            _dlq(r, cfg, entry, reason="missing_id", error="event has no id", doc_id="")
            _ack(r, cfg, [entry.entry_id])
            continue
        did = str(doc_id)
        actions.append({"_op_type": "index", "_index": es_cfg.write_alias, "_id": did, "_source": doc})
        by_docid[did] = entry

    if not actions:
        return 0

    try:
        _success, raw_errors = _run_bulk(es, actions, es_cfg.request_timeout_seconds)
        failed = _parse_bulk_errors(raw_errors)
        unreachable = False
    except Exception as exc:
        failed = {did: (503, type(exc).__name__) for did in by_docid}
        unreachable = True
        incr_counter("es_indexer_bulk_error_total", reason="unreachable", value=float(len(by_docid)))
        log_event(logger, "warning", "es_stream_bulk_exception", error=type(exc).__name__, docs=len(by_docid))

    ok_acks: List[str] = []
    dlq_acks: List[str] = []
    transient_left = 0

    for did, entry in by_docid.items():
        if did not in failed:
            ok_acks.append(entry.entry_id)
            _observe_lag(entry.row, now_epoch)
            _clear_attempts(r, cfg, entry.entry_id)
            continue

        status, reason = failed[did]
        if not unreachable and _is_permanent(status):
            incr_counter("es_indexer_bulk_error_total", reason="permanent")
            incr_counter("es_indexer_dlq_total", reason="permanent")
            _dlq(r, cfg, entry, reason=f"permanent_{status}", error=reason, doc_id=did)
            _clear_attempts(r, cfg, entry.entry_id)
            dlq_acks.append(entry.entry_id)
            continue

        if unreachable:
            transient_left += 1
            continue

        incr_counter("es_indexer_bulk_error_total", reason="transient")
        attempts = _bump_attempts(r, cfg, entry.entry_id)
        if attempts >= cfg.max_retries:
            incr_counter("es_indexer_dlq_total", reason="max_retries")
            _dlq(r, cfg, entry, reason="max_retries", error=f"{status}:{reason}", doc_id=did)
            _clear_attempts(r, cfg, entry.entry_id)
            dlq_acks.append(entry.entry_id)
        else:
            transient_left += 1

    if ok_acks:
        _ack(r, cfg, ok_acks)
        incr_counter("es_indexer_bulk_success_total", value=float(len(ok_acks)))
    if dlq_acks:
        _ack(r, cfg, dlq_acks)

    if transient_left:
        log_event(
            logger,
            "warning",
            "es_stream_batch_partial",
            indexed=len(ok_acks),
            dlq=len(dlq_acks),
            pending_retry=transient_left,
            unreachable=unreachable,
        )

    return transient_left


def _ack(r: Any, cfg: ESStreamConfig, entry_ids: List[str]) -> None:
    try:
        r.xack(cfg.stream_key, cfg.group, *entry_ids)
    except Exception as exc:
        log_event(logger, "error", "es_stream_ack_failed", error=repr(exc), count=len(entry_ids))


def _bump_attempts(r: Any, cfg: ESStreamConfig, entry_id: str) -> int:
    try:
        return int(r.hincrby(cfg.attempts_key, entry_id, 1) or 0)
    except Exception:
        return cfg.max_retries


def _clear_attempts(r: Any, cfg: ESStreamConfig, entry_id: str) -> None:
    try:
        r.hdel(cfg.attempts_key, entry_id)
    except Exception:
        pass


def _drain_pending(*, r: Any, es: Any, es_cfg: ESConfig, cfg: ESStreamConfig, once: bool) -> int:
    seen: set[str] = set()
    cursor = "0"
    total_left = 0
    while True:
        resp = r.xreadgroup(
            groupname=cfg.group,
            consumername=cfg.consumer,
            streams={cfg.stream_key: cursor},
            count=cfg.batch_size,
        )
        entries = [e for e in _extract_stream_entries(resp) if e.entry_id not in seen]
        if not entries:
            break
        total_left += _process_batch(r=r, es=es, es_cfg=es_cfg, cfg=cfg, entries=entries)
        for e in entries:
            seen.add(e.entry_id)
        cursor = entries[-1].entry_id
        if once:
            break
    return total_left


def _reclaim_stranded(*, r: Any, es: Any, es_cfg: ESConfig, cfg: ESStreamConfig) -> None:
    try:
        resp = r.xautoclaim(
            name=cfg.stream_key,
            groupname=cfg.group,
            consumername=cfg.consumer,
            min_idle_time=cfg.claim_min_idle_ms,
            start_id="0-0",
            count=cfg.batch_size,
        )
    except Exception as exc:
        if "NOGROUP" in str(exc):
            _ensure_group(r, cfg)
        return
    _, entries = _extract_claim_entries(resp)
    if entries:
        log_event(logger, "info", "es_stream_reclaimed", count=len(entries))
        _process_batch(r=r, es=es, es_cfg=es_cfg, cfg=cfg, entries=entries)


def _update_backlog_gauges(r: Any, cfg: ESStreamConfig) -> None:
    pending = 0
    try:
        summary = r.xpending(cfg.stream_key, cfg.group)
        if isinstance(summary, dict):
            pending = int(summary.get("pending") or 0)
        elif isinstance(summary, (list, tuple)) and summary:
            pending = int(summary[0] or 0)
    except Exception:
        pending = 0
    set_gauge("es_indexer_pending_count", float(pending))

    backlog: Optional[int] = None
    try:
        for grp in r.xinfo_groups(cfg.stream_key) or []:
            if not isinstance(grp, dict):
                continue
            if str(grp.get("name")) == cfg.group and grp.get("lag") is not None:
                backlog = int(grp.get("lag") or 0)
                break
    except Exception:
        backlog = None

    if backlog is not None:
        set_gauge("es_indexer_stream_backlog", float(backlog))
        if backlog > cfg.backlog_alert_threshold:
            log_event(
                logger,
                "warning",
                "es_stream_backlog_high",
                backlog=backlog,
                threshold=cfg.backlog_alert_threshold,
                pending=pending,
            )


def _housekeeping(*, r: Any, es: Any, es_cfg: ESConfig, cfg: ESStreamConfig) -> None:
    _update_backlog_gauges(r, cfg)
    _reclaim_stranded(r=r, es=es, es_cfg=es_cfg, cfg=cfg)


def _read_new(r: Any, cfg: ESStreamConfig) -> List[_Entry]:
    try:
        resp = r.xreadgroup(
            groupname=cfg.group,
            consumername=cfg.consumer,
            streams={cfg.stream_key: ">"},
            count=cfg.batch_size,
            block=cfg.block_ms,
        )
    except _READ_TIMEOUT_ERRORS:
        return []
    return _extract_stream_entries(resp)


def run(
    *,
    r: Any,
    es: Any,
    es_cfg: ESConfig,
    cfg: ESStreamConfig,
    bootstrap_enabled: bool,
    ping: bool = True,
    max_iterations: Optional[int] = None,
) -> None:
    _ensure_group(r, cfg)

    for name in ("permanent", "transient", "unreachable"):
        init_counter("es_indexer_bulk_error_total", reason=name)
    for name in ("permanent", "max_retries", "missing_id"):
        init_counter("es_indexer_dlq_total", reason=name)

    bootstrap_done = not bootstrap_enabled
    replay_done = False
    backoff = 1.0
    retry_backoff = cfg.retry_backoff_seconds
    last_housekeeping = 0.0
    iterations = 0

    while max_iterations is None or iterations < max_iterations:
        iterations += 1
        try:
            if ping and not es.ping():
                raise RuntimeError("elasticsearch_ping_failed")

            if not bootstrap_done:
                bootstrap(es, es_cfg)
                bootstrap_done = True

            if not replay_done:
                _drain_pending(r=r, es=es, es_cfg=es_cfg, cfg=cfg, once=False)
                replay_done = True

            now = time.monotonic()
            if now - last_housekeeping >= cfg.housekeeping_seconds:
                last_housekeeping = now
                _housekeeping(r=r, es=es, es_cfg=es_cfg, cfg=cfg)

            transient_left = _drain_pending(r=r, es=es, es_cfg=es_cfg, cfg=cfg, once=True)
            if transient_left > 0:
                _sleep(retry_backoff)
                retry_backoff = min(retry_backoff * 2.0, cfg.retry_backoff_max_seconds)
                continue
            retry_backoff = cfg.retry_backoff_seconds

            entries = _read_new(r, cfg)
            if not entries:
                backoff = 1.0
                continue

            incr_counter("es_indexer_events_consumed_total", value=float(len(entries)))
            _process_batch(r=r, es=es, es_cfg=es_cfg, cfg=cfg, entries=entries)
            backoff = 1.0

        except Exception as exc:
            wait_s = min(backoff, 15.0)
            log_event(logger, "warning", "es_stream_loop_error", wait_s=wait_s, error=repr(exc))
            _sleep(wait_s)
            backoff = min(backoff * 2.0, 15.0)


def _sleep(seconds: float) -> None:
    time.sleep(max(0.0, seconds))


def main() -> None:
    settings.validate_for_service("worker-es-indexer")
    es_cfg = load_config()
    cfg = load_stream_config()

    r = _build_redis_client(cfg)
    es = _build_es_client(es_cfg)
    log_event(
        logger,
        "info",
        "es_stream_indexer_starting",
        stream=cfg.stream_key,
        group=cfg.group,
        consumer=cfg.consumer,
        write_alias=es_cfg.write_alias,
        batch_size=cfg.batch_size,
    )
    run(r=r, es=es, es_cfg=es_cfg, cfg=cfg, bootstrap_enabled=es_cfg.bootstrap)


if __name__ == "__main__":
    main()
