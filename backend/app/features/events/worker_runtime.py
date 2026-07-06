
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.features.events.clickhouse_sink import write_clickhouse_events
from app.features.events.models import (
    EventRollup1mModel,
    NetEventModel,
    NetEventRollup1sModel,
    SshFailRollup1mModel,
)

__all__ = [
    "EventRollup1mModel",
    "NetEventModel",
    "NetEventRollup1sModel",
    "SshFailRollup1mModel",
    "purge_stale_rollups_1s",
    "write_clickhouse_events",
]


def purge_stale_rollups_1s(session: Session, *, retention_days: int, batch: int) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, int(retention_days)))
    subq = (
        session.query(NetEventRollup1sModel.bucket_ts)
        .filter(NetEventRollup1sModel.bucket_ts < cutoff)
        .order_by(NetEventRollup1sModel.bucket_ts.asc())
        .limit(max(1, int(batch)))
        .subquery()
    )
    boundary = session.query(func.max(subq.c.bucket_ts)).scalar()
    if boundary is None:
        return 0
    deleted = (
        session.query(NetEventRollup1sModel)
        .filter(NetEventRollup1sModel.bucket_ts <= boundary)
        .delete(synchronize_session=False)
    )
    return int(deleted or 0)
