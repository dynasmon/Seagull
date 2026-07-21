from __future__ import annotations

from typing import Any, Dict, List, Tuple

from sqlalchemy.dialects.postgresql import insert

from app.features.events.worker_runtime import NetEventRollup1sModel


def _merge_rollup_rows(rollup_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    for row in rollup_rows:
        key = (
            row["bucket_ts"],
            row["agent_id"],
            row["event_type"],
            row["dst_ip"],
            row["dst_port"],
            row["proto"],
        )
        found = merged.get(key)
        if found is None:
            merged[key] = dict(row)
            continue
        found["count"] = int(found["count"] or 0) + int(row["count"] or 0)
        found["bytes_sum"] = int(found["bytes_sum"] or 0) + int(row["bytes_sum"] or 0)
    return list(merged.values())


def upsert_rollups(conn: Any, rollup_rows: List[Dict[str, Any]]) -> None:
    if not rollup_rows:
        return

    ins = insert(NetEventRollup1sModel).values(_merge_rollup_rows(rollup_rows))
    upsert = ins.on_conflict_do_update(
        index_elements=[
            NetEventRollup1sModel.bucket_ts,
            NetEventRollup1sModel.agent_id,
            NetEventRollup1sModel.event_type,
            NetEventRollup1sModel.dst_ip,
            NetEventRollup1sModel.dst_port,
            NetEventRollup1sModel.proto,
        ],
        set_={
            "count": NetEventRollup1sModel.count + ins.excluded.count,
            "bytes_sum": NetEventRollup1sModel.bytes_sum + ins.excluded.bytes_sum,
        },
    )
    conn.execute(upsert)
