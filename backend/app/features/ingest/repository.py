from __future__ import annotations

from datetime import datetime
from typing import List

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.features.events.models import NetEventModel, NetEventRollup1sModel


def persist_fallback_ingest(db: Session, *, hot_events: List[List], rollup_rows: List[List]) -> None:
    if hot_events:
        raw_rows = [
            {
                "agent_id": row[0],
                "event_type": row[1],
                "schema_version": int(row[2] or 1),
                "timestamp": datetime.fromisoformat(row[3]),
                "src_ip": row[4],
                "dst_ip": row[5],
                "src_port": row[6],
                "dst_port": row[7],
                "proto": row[8],
                "bytes": row[9],
                "extra": dict(row[10] or {}),
            }
            for row in hot_events
        ]
        db.execute(insert(NetEventModel), raw_rows)

    if rollup_rows:
        rr = [
            {
                "bucket_ts": datetime.fromisoformat(rrow[0]),
                "agent_id": rrow[1],
                "event_type": rrow[2],
                "dst_ip": rrow[3],
                "dst_port": rrow[4],
                "proto": rrow[5],
                "count": int(rrow[6]),
                "bytes_sum": int(rrow[7]),
            }
            for rrow in rollup_rows
        ]
        ins = insert(NetEventRollup1sModel).values(rr)
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
        db.execute(upsert)

    db.commit()
