from __future__ import annotations

import time

from app.core.cache import get_redis
from app.features.ingest.control.queue_keys import (
    _clickhouse_batches_key,
    _clickhouse_error_type_key,
    _clickhouse_rows_key,
    _clickhouse_state_key,
    _sink_counter_key,
    _sink_depth_key,
)

_COUNTER_TTL_SECONDS = 30
_STATE_TTL_SECONDS = 120


def record_sink_runtime_metric(*, sink: str, metric: str, value: int) -> None:
    r = get_redis()
    if r is None:
        return
    ts_s = int(time.time())
    key = _sink_counter_key(sink=str(sink), metric=str(metric), ts_s=ts_s)
    try:
        pipe = r.pipeline()
        pipe.incrby(key, max(0, int(value)))
        pipe.expire(key, _COUNTER_TTL_SECONDS)
        pipe.execute()
    except Exception:
        return


def set_sink_queue_depth(*, sink: str, depth: int) -> None:
    r = get_redis()
    if r is None:
        return
    try:
        r.setex(_sink_depth_key(sink=str(sink)), _COUNTER_TTL_SECONDS, str(max(0, int(depth))))
    except Exception:
        return


def record_clickhouse_progress(*, rows: int, batches: int = 1) -> None:
    if rows <= 0:
        return
    r = get_redis()
    if r is None:
        return
    ts_s = int(time.time())
    try:
        pipe = r.pipeline()
        pipe.incrby(_clickhouse_rows_key(ts_s), int(rows))
        pipe.expire(_clickhouse_rows_key(ts_s), _COUNTER_TTL_SECONDS)
        pipe.incrby(_clickhouse_batches_key(ts_s), max(1, int(batches)))
        pipe.expire(_clickhouse_batches_key(ts_s), _COUNTER_TTL_SECONDS)
        pipe.execute()
    except Exception:
        return


def set_clickhouse_state(*, state: str, error_type: str = "") -> None:
    r = get_redis()
    if r is None:
        return
    try:
        pipe = r.pipeline()
        pipe.setex(_clickhouse_state_key(), _STATE_TTL_SECONDS, str(state or "unknown"))
        if error_type:
            pipe.setex(_clickhouse_error_type_key(), _STATE_TTL_SECONDS, str(error_type)[:64])
        else:
            pipe.delete(_clickhouse_error_type_key())
        pipe.execute()
    except Exception:
        return
