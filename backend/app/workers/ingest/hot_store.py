from __future__ import annotations

import logging
from typing import Any, Dict, List

from sqlalchemy.dialects.postgresql import insert

from app.core.observability import log_event
from app.features.events.worker_runtime import NetEventModel

logger = logging.getLogger("seagull.worker.ingest")


def _insert_hot_rows_with_pg_ids(conn, hot_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:

    if not hot_rows:
        return []

    inserted_hot_rows: List[Dict[str, Any]] = []

    try:
        with conn.begin_nested():
            res = conn.execute(insert(NetEventModel).returning(NetEventModel.id), hot_rows)
            ids = [int(r[0]) for r in (res.fetchall() or [])]
            if len(ids) != len(hot_rows):
                raise RuntimeError(f"returning mismatch ids={len(ids)} rows={len(hot_rows)}")
            for row, eid in zip(hot_rows, ids, strict=False):
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
