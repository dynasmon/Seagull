from __future__ import annotations

import time

from app.core.cache import get_redis
from app.features.ingest.control.queue_keys import _sink_counter_key, _sink_depth_key


def record_sink_runtime_metric(*, sink: str, metric: str, value: int) -> None:
    r = get_redis()
    if r is None:
        return
    ts_s = int(time.time())
    key = _sink_counter_key(sink=str(sink), metric=str(metric), ts_s=ts_s)
    try:
        pipe = r.pipeline()
        pipe.incrby(key, max(0, int(value)))
        pipe.expire(key, 30)
        pipe.execute()
    except Exception:
        return


def set_sink_queue_depth(*, sink: str, depth: int) -> None:
    r = get_redis()
    if r is None:
        return
    try:
        r.setex(_sink_depth_key(sink=str(sink)), 30, str(max(0, int(depth))))
    except Exception:
        return
