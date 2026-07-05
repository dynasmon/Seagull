from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from sqlalchemy import text

_READ_SQL = text(
    "SELECT schema_version, payload, computed_at, computed_ms "
    "FROM dashboard_snapshots WHERE page = :page AND scope_key = :scope_key"
)

_UPSERT_SQL = text(
    "INSERT INTO dashboard_snapshots "
    "(page, scope_key, schema_version, payload, computed_at, computed_ms, updated_at) "
    "VALUES (:page, :scope_key, :schema_version, CAST(:payload AS JSONB), :computed_at, :computed_ms, :updated_at) "
    "ON CONFLICT (page, scope_key) DO UPDATE SET "
    "schema_version = EXCLUDED.schema_version, "
    "payload = EXCLUDED.payload, "
    "computed_at = EXCLUDED.computed_at, "
    "computed_ms = EXCLUDED.computed_ms, "
    "updated_at = EXCLUDED.updated_at"
)

_OLDEST_SQL = text("SELECT page, min(computed_at) FROM dashboard_snapshots GROUP BY page")

_PRUNE_SQL = text("DELETE FROM dashboard_snapshots WHERE updated_at < :cutoff")


@dataclass(frozen=True)
class SnapshotRow:
    page: str
    scope_key: str
    schema_version: int
    payload: dict
    computed_at: datetime
    computed_ms: float


def _session():
    from app.core.db import SessionLocal

    return SessionLocal()


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def read_snapshot(page: str, scope_key: str) -> Optional[SnapshotRow]:
    db = _session()
    try:
        row = db.execute(_READ_SQL, {"page": page, "scope_key": scope_key}).fetchone()
    finally:
        db.close()
    if row is None:
        return None
    payload = row[1]
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except Exception:
            payload = None
    if not isinstance(payload, dict) or row[2] is None:
        return None
    return SnapshotRow(
        page=page,
        scope_key=scope_key,
        schema_version=int(row[0] or 0),
        payload=payload,
        computed_at=_as_utc(row[2]),
        computed_ms=float(row[3] or 0.0),
    )


def upsert_snapshot(
    *,
    page: str,
    scope_key: str,
    schema_version: int,
    payload: dict,
    computed_ms: float,
    computed_at: Optional[datetime] = None,
) -> None:
    now = datetime.now(timezone.utc)
    db = _session()
    try:
        db.execute(
            _UPSERT_SQL,
            {
                "page": page,
                "scope_key": scope_key,
                "schema_version": int(schema_version),
                "payload": json.dumps(payload, ensure_ascii=True, separators=(",", ":"), default=str),
                "computed_at": computed_at or now,
                "computed_ms": float(computed_ms),
                "updated_at": now,
            },
        )
        db.commit()
    finally:
        db.close()


def oldest_age_seconds(now: Optional[datetime] = None) -> Dict[str, float]:
    ref = now or datetime.now(timezone.utc)
    db = _session()
    try:
        rows = db.execute(_OLDEST_SQL).fetchall()
    finally:
        db.close()
    out: Dict[str, float] = {}
    for page, oldest in rows:
        if oldest is None:
            continue
        out[str(page)] = max(0.0, (ref - _as_utc(oldest)).total_seconds())
    return out


def prune_stale(*, retention_hours: int) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=max(1, int(retention_hours)))
    db = _session()
    try:
        result = db.execute(_PRUNE_SQL, {"cutoff": cutoff})
        db.commit()
        return int(result.rowcount or 0)
    finally:
        db.close()
