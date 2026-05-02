from __future__ import annotations

import time
from typing import Any, Dict, List

from app.core.integrations.clickhouse import ensure_clickhouse_events_schema, get_clickhouse_client
from app.features.events.worker_runtime import write_clickhouse_events


def _record_clickhouse_progress(r: Any, *, rows: int) -> None:
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


def _set_clickhouse_state(r: Any, *, state: str, error_type: str = "") -> None:
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


def _write_clickhouse_events(*, ch_client: Any, hot_rows: List[Dict[str, Any]]) -> int:
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
