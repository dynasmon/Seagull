from __future__ import annotations

from typing import Any, Dict, List

from sqlalchemy.dialects.postgresql import insert

from app.features.events.worker_runtime import NetEventRollup1sModel


def upsert_rollups(conn: Any, rollup_rows: List[Dict[str, Any]]) -> None:
    if not rollup_rows:
        return

    ins = insert(NetEventRollup1sModel).values(rollup_rows)
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
