from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.observability import incr_counter, observe_hist
from app.core.api.pagination import make_cursor_ts_id, parse_cursor_ts_id
from app.core.cache import get_redis
from app.features.inventory.repository import (
    create_snapshot_and_upsert_latest,
    fetch_overview_payload,
    get_latest_snapshot,
    list_snapshot_history,
    list_snapshot_history_page,
)
from app.features.inventory.schemas import InventorySnapshotIn, PackageEntry
from app.features.realtime.service import publish_realtime
from app.shared.schemas import CursorPage


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_packages(packages: list[PackageEntry]) -> bytes:
    rows = [f"{p.name}\t{p.version}\t{p.arch or ''}" for p in packages]
    rows.sort()
    return ("\n".join(rows) + "\n").encode("utf-8") if rows else b""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _fmt_hhmm(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%H:%M")


def _floor_dt(dt: datetime, minutes_step: int) -> datetime:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    minute = (dt.minute // minutes_step) * minutes_step
    return dt.replace(minute=minute, second=0, microsecond=0)


def _cache_get_json(key: str) -> Optional[dict[str, Any]]:
    r = get_redis()
    if r is None:
        return None
    try:
        raw = r.get(key)
        if not raw:
            return None
        out = json.loads(raw)
        return out if isinstance(out, dict) else None
    except Exception:
        return None


def _cache_set_json(key: str, payload: dict[str, Any], ttl_s: int) -> None:
    if ttl_s <= 0:
        return
    r = get_redis()
    if r is None:
        return
    try:
        r.setex(key, int(ttl_s), json.dumps(payload, ensure_ascii=True, separators=(",", ":"), default=str))
    except Exception:
        return


def _cache_delete_prefixes(*prefixes: str) -> None:
    r = get_redis()
    if r is None:
        return
    for prefix in prefixes:
        raw_prefix = str(prefix or "").strip()
        if not raw_prefix:
            continue
        try:
            cursor: int | str = 0
            while True:
                cursor, keys = r.scan(cursor=cursor, match=f"{raw_prefix}*", count=200)
                if keys:
                    r.delete(*keys)
                if str(cursor) == "0":
                    break
        except Exception:
            return


def invalidate_inventory_overview_cache(*, agent_id: str | None = None) -> None:
    _cache_delete_prefixes("seagull:inventory:overview:v2:")


def ingest_inventory(db: Session, *, payload: InventorySnapshotIn, agent_id: str) -> dict[str, Any]:
    now = _utc_now()

    packages_count = payload.packages_count if payload.packages_count is not None else len(payload.packages)
    if packages_count != len(payload.packages):
        packages_count = len(payload.packages)

    packages_hash = (payload.packages_hash or "").strip()
    if not packages_hash or len(packages_hash) != 64:
        packages_hash = _sha256_hex(_canonical_packages(payload.packages))

    extra = dict(payload.extra or {})
    if payload.collected_at is not None:
        try:
            ts = payload.collected_at
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            extra.setdefault("client_collected_at", ts.isoformat())
        except Exception:
            pass

    row_id = create_snapshot_and_upsert_latest(
        db,
        agent_id=agent_id,
        collected_at=now,
        schema_version=int(payload.schema_version or 1),
        os_data=dict(payload.os or {}),
        packages_data=[p.dict() for p in payload.packages],
        packages_hash=packages_hash,
        packages_count=int(packages_count),
        manager=payload.manager,
        extra=extra,
    )
    invalidate_inventory_overview_cache(agent_id=agent_id)
    try:
        publish_realtime(
            "ui.inventory.invalidate",
            {
                "reason": "inventory_snapshot_ingested",
                "scope": "inventory",
                "agent_id": str(agent_id or "").strip(),
                "snapshot_id": int(row_id),
            },
        )
    except Exception:
        pass
    return {"id": row_id, "stored": True}


def get_latest_inventory_or_404(db: Session, *, agent_id: str):
    row = get_latest_snapshot(db, agent_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No inventory")
    return row


def list_inventory_history(db: Session, *, agent_id: str, limit: int):
    return list_snapshot_history(db, agent_id, limit)


def list_inventory_history_page(db: Session, *, agent_id: str, page_size: int, cursor: str | None):
    cursor_parsed = parse_cursor_ts_id(cursor) if cursor else None
    rows = list_snapshot_history_page(
        db,
        agent_id=agent_id,
        page_size=page_size,
        cursor_parsed=cursor_parsed,
    )
    has_more = len(rows) > page_size
    items = rows[:page_size]
    next_cursor = make_cursor_ts_id(items[-1].collected_at, items[-1].id) if has_more and items else None
    return CursorPage(items=items, next_cursor=next_cursor, has_more=has_more)


def get_inventory_overview(
    db: Session,
    *,
    window_minutes: int,
    agent_id: str | None,
) -> dict[str, Any]:
    started = time.perf_counter()
    a = (agent_id or "").strip()
    if not a or a == "__all":
        a = None

    now = _utc_now()
    start_ts = now - timedelta(minutes=window_minutes)

    start_1m = _floor_dt(start_ts, 1)
    start_10m = _floor_dt(start_ts, 10)
    end_1m = _floor_dt(now, 1)
    end_10m = _floor_dt(now, 10)

    cache_key = f"seagull:inventory:overview:v2:w={int(window_minutes)}:a={a or '*'}"
    cached = _cache_get_json(cache_key)
    if cached is not None:
        incr_counter("api_cache_hit_total", route="/inventory/overview")
        return cached

    payload = fetch_overview_payload(
        db,
        now=now,
        start_ts=start_ts,
        start_1m=start_1m,
        start_10m=start_10m,
        end_1m=end_1m,
        end_10m=end_10m,
        agent_filter=a,
        fmt_hhmm=_fmt_hhmm,
        floor_dt=_floor_dt,
    )
    payload.update({"window_minutes": window_minutes, "agent_id": agent_id or "__all"})

    _cache_set_json(cache_key, payload, int(getattr(settings, "SEAGULL_EVENTS_SUMMARY_CACHE_TTL_SECONDS", 15) or 15))
    observe_hist("api_route_latency_seconds", time.perf_counter() - started, route="/inventory/overview")
    return payload
