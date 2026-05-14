from __future__ import annotations

import time

from app.core.cache import get_redis
from app.features.ingest.control.backpressure import _update_events_per_msg_avg
from app.features.ingest.control.queue_keys import (
    _env_int,
    _overview_live_key,
    _worker_eps_key,
    _worker_hb_key,
    _worker_msgs_key,
)


def record_worker_progress(*, processed_events: int, processed_messages: int) -> None:
    r = get_redis()
    if r is None:
        return

    ts_s = int(time.time())
    ev = max(0, int(processed_events))
    msgs = max(0, int(processed_messages))
    try:
        pipe = r.pipeline()
        pipe.incrby(_worker_eps_key(ts_s), ev)
        pipe.expire(_worker_eps_key(ts_s), 10)
        pipe.incrby(_worker_msgs_key(ts_s), msgs)
        pipe.expire(_worker_msgs_key(ts_s), 10)
        pipe.hincrby(_overview_live_key(ts_s), "processed_events", ev)
        pipe.expire(_overview_live_key(ts_s), max(60, _env_int("SEAGULL_OVERVIEW_LIVE_RETENTION_SECONDS", 1800)))
        pipe.execute()
        if msgs > 0:
            _update_events_per_msg_avg(r, ev / float(msgs))
    except Exception:
        return


def worker_heartbeat(worker_id: str, *, ttl_seconds: int = 8) -> None:
    if not worker_id:
        return
    r = get_redis()
    if r is None:
        return
    try:
        r.setex(_worker_hb_key(worker_id), max(2, int(ttl_seconds)), str(int(time.time())))
    except Exception:
        return


def count_active_workers() -> int:
    r = get_redis()
    if r is None:
        return 0
    try:
        n = 0
        for _ in r.scan_iter(match="seagull:ingest:worker:hb:*", count=64):
            n += 1
        return max(0, int(n))
    except Exception:
        return 0
