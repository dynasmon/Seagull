from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from sqlalchemy import func, select

from app.core.config import settings
from app.core.db import engine
from app.core.db.lifecycle import ensure_database_ready
from app.core.integrations.clickhouse import clickhouse_events_table_ref, get_clickhouse_client
from app.core.observability import incr_counter, init_counter, log_event, observe_hist, set_gauge, setup_logging
from app.features.events.worker_runtime import NetEventModel
from app.features.ingest.control.service import get_storm_status
from app.shared.indexing.es_client import build_es_client
from app.shared.outbox import store
from app.shared.outbox.models import SINK_CLICKHOUSE, SINK_SEARCH
from app.workers.indexing.es_bootstrap import load_config as load_es_config
from app.workers.sinks.config import ReconcilerConfig, load_reconciler_config

setup_logging("worker-projection-reconciler")
logger = logging.getLogger("seagull.worker.projection_reconciler")

PresentIds = Callable[[datetime], Set[int]]
ProjectionPass = Callable[[], Tuple[Dict[datetime, int], PresentIds]]

_ID_PAGE_SIZE = 5000
_REPAIR_CHUNK_EVENTS = 500

_REPAIR_COLUMNS = (
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
    NetEventModel.app_proto,
    NetEventModel.app_proto_reason,
    NetEventModel.app_proto_conf_band,
    NetEventModel.dns_qname,
    NetEventModel.http_host,
    NetEventModel.http_method,
    NetEventModel.tls_sni,
    NetEventModel.tls_alpn_first,
    NetEventModel.ja3,
    NetEventModel.ja4,
    NetEventModel.ja4_ptype,
    NetEventModel.ssh_action,
    NetEventModel.ssh_username,
    NetEventModel.proc_pid,
    NetEventModel.proc_ppid,
    NetEventModel.proc_name,
    NetEventModel.proc_exe,
    NetEventModel.proc_parent_name,
    NetEventModel.fim_path,
    NetEventModel.fim_category,
    NetEventModel.heuristic_name,
    NetEventModel.heuristic_confidence,
    NetEventModel.extra,
)


@dataclass(frozen=True)
class Divergence:
    sink: str
    expected: int
    missing: int
    repaired: int

    @property
    def ratio(self) -> float:
        return (self.missing / self.expected) if self.expected > 0 else 0.0


@dataclass(frozen=True)
class Window:
    start: datetime
    end: datetime


def floor_minute(moment: datetime) -> datetime:
    return moment.replace(second=0, microsecond=0)


def reconcile_window(cfg: ReconcilerConfig, *, now: Optional[datetime] = None) -> Window:
    end = floor_minute((now or datetime.now(timezone.utc)) - timedelta(seconds=cfg.settle_seconds))
    return Window(start=end - timedelta(minutes=cfg.lookback_minutes), end=end)


def postgres_minute_counts(window: Window) -> Dict[datetime, int]:
    bucket = func.date_trunc("minute", NetEventModel.timestamp)
    with engine.connect() as conn:
        rows = conn.execute(
            select(bucket.label("bucket"), func.count(NetEventModel.id))
            .where(NetEventModel.timestamp >= window.start, NetEventModel.timestamp < window.end)
            .group_by(bucket)
        ).all()
    return {_as_utc(row[0]): int(row[1] or 0) for row in rows if row[0] is not None}


def postgres_event_ids(minute: datetime) -> Set[int]:
    with engine.connect() as conn:
        rows = conn.execute(
            select(NetEventModel.id).where(
                NetEventModel.timestamp >= minute,
                NetEventModel.timestamp < minute + timedelta(minutes=1),
            )
        ).all()
    return {int(row[0]) for row in rows}


def clickhouse_minute_counts(client: Any, window: Window) -> Dict[datetime, int]:
    rows = client.query(
        f"SELECT toStartOfMinute(timestamp) AS bucket, count() AS total FROM {clickhouse_events_table_ref()} "
        "WHERE timestamp >= {start_ts:DateTime64(3)} AND timestamp < {end_ts:DateTime64(3)} "
        "AND pg_event_id > 0 GROUP BY bucket",
        parameters={"start_ts": window.start, "end_ts": window.end},
    ).result_rows
    return {_as_utc(row[0]): int(row[1] or 0) for row in rows if row[0] is not None}


def clickhouse_event_ids(client: Any, minute: datetime) -> Set[int]:
    rows = client.query(
        f"SELECT DISTINCT pg_event_id FROM {clickhouse_events_table_ref()} "
        "WHERE timestamp >= {start_ts:DateTime64(3)} AND timestamp < {end_ts:DateTime64(3)} "
        "AND pg_event_id > 0",
        parameters={"start_ts": minute, "end_ts": minute + timedelta(minutes=1)},
    ).result_rows
    return {int(row[0]) for row in rows if row[0]}


def _search_range_filter(start: datetime, end: datetime) -> List[Dict[str, Any]]:
    return [
        {"range": {"@timestamp": {"gte": start.isoformat(), "lt": end.isoformat()}}},
        {"exists": {"field": "id"}},
    ]


def search_minute_counts(es: Any, pattern: str, window: Window) -> Dict[datetime, int]:
    response = es.search(
        index=pattern,
        body={
            "size": 0,
            "query": {"bool": {"filter": _search_range_filter(window.start, window.end)}},
            "aggs": {
                "per_minute": {
                    "date_histogram": {"field": "@timestamp", "fixed_interval": "1m", "min_doc_count": 1}
                }
            },
        },
        ignore_unavailable=True,
        allow_no_indices=True,
    )
    buckets = ((response.get("aggregations") or {}).get("per_minute") or {}).get("buckets") or []
    counts: Dict[datetime, int] = {}
    for bucket in buckets:
        key = bucket.get("key")
        if key is None:
            continue
        moment = datetime.fromtimestamp(int(key) / 1000.0, tz=timezone.utc)
        counts[floor_minute(moment)] = int(bucket.get("doc_count") or 0)
    return counts


def search_event_ids(es: Any, pattern: str, minute: datetime) -> Set[int]:
    body: Dict[str, Any] = {
        "size": _ID_PAGE_SIZE,
        "_source": False,
        "query": {"bool": {"filter": _search_range_filter(minute, minute + timedelta(minutes=1))}},
        "sort": [{"id": "asc"}],
    }
    found: Set[int] = set()
    while True:
        response = es.search(index=pattern, body=body, ignore_unavailable=True, allow_no_indices=True)
        hits = ((response.get("hits") or {}).get("hits")) or []
        if not hits:
            break
        for hit in hits:
            try:
                found.add(int(hit["_id"]))
            except (KeyError, TypeError, ValueError):
                continue
        if len(hits) < _ID_PAGE_SIZE:
            break
        body["search_after"] = hits[-1].get("sort")
    return found


def repair_rows(event_ids: Sequence[int]) -> List[Dict[str, Any]]:
    if not event_ids:
        return []
    with engine.connect() as conn:
        rows = (
            conn.execute(select(*_REPAIR_COLUMNS).where(NetEventModel.id.in_(list(event_ids))))
            .mappings()
            .all()
        )
    repaired: List[Dict[str, Any]] = []
    for row in rows:
        event = dict(row)
        event["pg_event_id"] = int(event["id"])
        if not isinstance(event.get("extra"), dict):
            event["extra"] = {}
        repaired.append(event)
    return repaired


def enqueue_repair(*, sink: str, event_ids: Sequence[int]) -> int:
    events = repair_rows(event_ids)
    if not events:
        return 0
    with engine.begin() as conn:
        store.enqueue(conn, sink=sink, events=events, chunk_size=_REPAIR_CHUNK_EVENTS)
    incr_counter("projection_repair_enqueued_total", value=float(len(events)), sink=sink)
    return len(events)


def _diverging_minutes(
    expected: Dict[datetime, int], present: Dict[datetime, int]
) -> List[datetime]:
    return sorted(minute for minute, count in expected.items() if present.get(minute, 0) < count)


def _as_utc(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    raise TypeError(f"expected datetime bucket, got {type(value).__name__}")


def reconcile_sink(
    *,
    sink: str,
    expected: Dict[datetime, int],
    present: Dict[datetime, int],
    present_ids: PresentIds,
    cfg: ReconcilerConfig,
) -> Divergence:
    expected_total = sum(expected.values())
    missing_total = 0
    repaired_total = 0
    budget = cfg.repair_max_events if cfg.repair_enabled else 0

    for minute in _diverging_minutes(expected, present):
        source_ids = postgres_event_ids(minute)
        missing = sorted(source_ids - present_ids(minute))
        if not missing:
            continue
        missing_total += len(missing)
        if budget <= 0:
            continue
        selected = missing[:budget]
        repaired = enqueue_repair(sink=sink, event_ids=selected)
        repaired_total += repaired
        budget -= len(selected)

    return Divergence(sink=sink, expected=expected_total, missing=missing_total, repaired=repaired_total)


def _publish(divergence: Divergence, *, elapsed: float) -> None:
    set_gauge("projection_missing_events", float(divergence.missing), sink=divergence.sink)
    set_gauge("projection_divergence_ratio", divergence.ratio, sink=divergence.sink)
    observe_hist("projection_reconcile_seconds", elapsed, sink=divergence.sink)
    log_event(
        logger,
        "warning" if divergence.missing else "info",
        "projection_reconciled",
        sink=divergence.sink,
        expected=divergence.expected,
        missing=divergence.missing,
        repaired=divergence.repaired,
        elapsed_seconds=round(elapsed, 3),
    )


class ProjectionReconciler:
    def __init__(self, cfg: ReconcilerConfig) -> None:
        self.cfg = cfg
        self._search: Any = None

    def search_client(self) -> Any:
        if self._search is None:
            es_cfg = load_es_config()
            self._search = build_es_client(
                url=es_cfg.url,
                request_timeout_seconds=es_cfg.request_timeout_seconds,
                username=es_cfg.username,
                password=es_cfg.password,
                verify_certs=es_cfg.verify_certs,
                ca_certs=es_cfg.ca_certs,
            )
        return self._search

    def sinks(self) -> List[str]:
        enabled: List[str] = []
        if self.cfg.clickhouse_enabled:
            enabled.append(SINK_CLICKHOUSE)
        if self.cfg.search_enabled:
            enabled.append(SINK_SEARCH)
        return enabled

    def run_once(self, *, now: Optional[datetime] = None) -> List[Divergence]:
        window = reconcile_window(self.cfg, now=now)
        expected = postgres_minute_counts(window)
        results: List[Divergence] = []

        if self.cfg.clickhouse_enabled:
            results.extend(self._reconcile(SINK_CLICKHOUSE, expected, self._clickhouse_pass(window)))
        if self.cfg.search_enabled:
            results.extend(self._reconcile(SINK_SEARCH, expected, self._search_pass(window)))

        return results

    def _clickhouse_pass(self, window: Window) -> ProjectionPass:
        def _pass() -> Tuple[Dict[datetime, int], PresentIds]:
            client = get_clickhouse_client()
            return (
                clickhouse_minute_counts(client, window),
                lambda minute: clickhouse_event_ids(client, minute),
            )

        return _pass

    def _search_pass(self, window: Window) -> ProjectionPass:
        def _pass() -> Tuple[Dict[datetime, int], PresentIds]:
            es = self.search_client()
            pattern = self.cfg.search_index_pattern
            return (
                search_minute_counts(es, pattern, window),
                lambda minute: search_event_ids(es, pattern, minute),
            )

        return _pass

    def _reconcile(
        self,
        sink: str,
        expected: Dict[datetime, int],
        projection: ProjectionPass,
    ) -> List[Divergence]:
        started = time.perf_counter()
        try:
            present, present_ids = projection()
            divergence = reconcile_sink(
                sink=sink,
                expected=expected,
                present=present,
                present_ids=present_ids,
                cfg=self.cfg,
            )
        except Exception as exc:
            if sink == SINK_SEARCH:
                self._search = None
            incr_counter("projection_reconcile_errors_total", sink=sink)
            log_event(
                logger,
                "warning",
                "projection_reconcile_sink_failed",
                sink=sink,
                error=type(exc).__name__,
            )
            return []
        _publish(divergence, elapsed=time.perf_counter() - started)
        return [divergence]


def _ingestion_under_pressure() -> bool:
    try:
        status = get_storm_status()
    except Exception:
        return False
    phase = str(status.get("phase") or "").lower()
    return bool(status.get("active")) or phase not in {"", "ok", "normal", "recovered"}


def _sleep(seconds: float) -> None:
    time.sleep(max(1.0, seconds))


def main() -> None:
    settings.validate_for_service("worker-projection-reconciler")
    cfg = load_reconciler_config()
    reconciler = ProjectionReconciler(cfg)

    if not cfg.enabled or not reconciler.sinks():
        log_event(logger, "info", "projection_reconciler_disabled")
        return

    ensure_database_ready()
    for sink in reconciler.sinks():
        init_counter("projection_repair_enqueued_total", sink=sink)
        init_counter("projection_reconcile_errors_total", sink=sink)

    log_event(
        logger,
        "info",
        "projection_reconciler_starting",
        sinks=reconciler.sinks(),
        interval_seconds=cfg.interval_seconds,
        lookback_minutes=cfg.lookback_minutes,
        settle_seconds=cfg.settle_seconds,
        repair_max_events=cfg.repair_max_events,
    )

    backoff = 1.0
    while True:
        try:
            if _ingestion_under_pressure():
                log_event(logger, "info", "projection_reconcile_skipped_backpressure")
            else:
                reconciler.run_once()
            backoff = 1.0
            _sleep(cfg.interval_seconds)
        except Exception as exc:
            log_event(logger, "error", "projection_reconcile_error", error=repr(exc), wait_s=backoff)
            _sleep(min(backoff, 60.0))
            backoff = min(backoff * 2.0, 60.0)


if __name__ == "__main__":
    main()
