from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.integrations.clickhouse import ensure_clickhouse_events_schema, get_clickhouse_client
from app.features.events.worker_runtime import write_clickhouse_events
from app.shared.indexing.watermark import write_clickhouse_watermark


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


def _coerce_row_ts(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def _record_clickhouse_watermark(hot_rows: List[Dict[str, Any]]) -> None:
    if not hot_rows:
        return
    max_id = 0
    max_ts: Optional[datetime] = None
    for row in hot_rows:
        try:
            pg_id = int(row.get("pg_event_id") or 0)
        except Exception:
            pg_id = 0
        if pg_id > max_id:
            max_id = pg_id
        ts = _coerce_row_ts(row.get("timestamp"))
        if ts is not None and (max_ts is None or ts > max_ts):
            max_ts = ts
    if max_ts is None:
        return
    write_clickhouse_watermark(max_pg_event_id=max_id, max_ts=max_ts)


def _try_bootstrap_clickhouse() -> Any | None:
    try:
        ch_client = get_clickhouse_client()
        ok = ensure_clickhouse_events_schema()
        if not ok:
            return None
        return ch_client
    except Exception:
        return None
