from __future__ import annotations

from datetime import timedelta
from typing import Optional

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert

from app.core.db import engine
from app.core.db.lifecycle import ensure_database_ready
from app.features.events.worker_runtime import NetEventModel
from app.shared.enrichment.models import IpEnrichmentCacheModel
from app.shared.indexing.offset_store import ensure_offset, get_offset, set_offset

from .normalization import _utc_now

OFFSET_LUPE = "lupe_enricher_ssh_v1"
SSH_ACTIONS: tuple[str, ...] = ("accepted", "failed_password", "invalid_user")

THREAT_GEO_SOURCE_TYPES: tuple[str, ...] = (
    "dos_attack",
    "ddos_telemetry",
    "scan_summary",
    "ssh_auth",
    "beacon_suspect",
    "c2_suspect",
    "exfil_suspect",
    "egress_anomaly",
)
THREAT_GEO_DOS_TYPES: tuple[str, ...] = ("dos_attack", "ddos_telemetry")


def _ensure_bootstrap(default_ttl_days: int) -> None:
    ensure_database_ready()
    with engine.begin() as conn:
        ensure_offset(OFFSET_LUPE, conn=conn)
        conn.execute(
            update(IpEnrichmentCacheModel)
            .where(IpEnrichmentCacheModel.expires_at.is_(None))
            .values(expires_at=_utc_now() + timedelta(days=int(default_ttl_days)))
        )


def _get_last_id() -> int:
    return get_offset(OFFSET_LUPE)


def _set_last_id(last_id: int) -> None:
    set_offset(OFFSET_LUPE, last_id)


def _pick_batch_max_id(last_id: int, max_rows: int) -> Optional[int]:
    with engine.begin() as conn:
        subq = (
            select(NetEventModel.id)
            .where(NetEventModel.id > int(last_id))
            .order_by(NetEventModel.id.asc())
            .limit(int(max_rows))
            .subquery()
        )
        row = conn.execute(select(func.max(subq.c.id))).fetchone()
        v = row[0] if row else None
        return int(v) if v is not None else None


def _fetch_batch(last_id: int, max_id: int, limit: int) -> list[dict]:
    with engine.begin() as conn:
        rows = conn.execute(
            select(
                NetEventModel.id,
                NetEventModel.agent_id,
                NetEventModel.src_ip,
                NetEventModel.extra["action"].astext.label("action"),
            )
            .where(
                NetEventModel.id > int(last_id),
                NetEventModel.id <= int(max_id),
                NetEventModel.event_type == "ssh_auth",
                NetEventModel.src_ip.is_not(None),
                NetEventModel.extra["action"].astext.in_(list(SSH_ACTIONS)),
                ~NetEventModel.extra.has_key("lupe_enriched_at"),
            )
            .order_by(NetEventModel.id.asc())
            .limit(int(limit))
        ).mappings().all()
        return [dict(r) for r in rows]


def _fetch_threat_geo_candidates(window_minutes: int, limit: int) -> list[str]:
    since = _utc_now() - timedelta(minutes=int(window_minutes))
    seen: set[str] = set()
    ordered: list[str] = []

    def _add(value) -> None:
        ip = str(value or "").strip()
        if ip and ip not in seen:
            seen.add(ip)
            ordered.append(ip)

    with engine.begin() as conn:
        dos_rows = conn.execute(
            select(NetEventModel.extra["top_src"].label("top_src"))
            .where(
                NetEventModel.timestamp >= since,
                NetEventModel.event_type.in_(THREAT_GEO_DOS_TYPES),
                NetEventModel.extra.has_key("top_src"),
            )
            .order_by(NetEventModel.timestamp.desc())
            .limit(50)
        ).all()
        src_rows = conn.execute(
            select(NetEventModel.src_ip)
            .where(
                NetEventModel.timestamp >= since,
                NetEventModel.src_ip.is_not(None),
                NetEventModel.event_type.in_(THREAT_GEO_SOURCE_TYPES),
            )
            .group_by(NetEventModel.src_ip)
            .order_by(func.max(NetEventModel.timestamp).desc())
            .limit(int(limit))
        ).all()

    for row in dos_rows:
        top = row[0]
        if isinstance(top, list):
            for item in top:
                if isinstance(item, dict):
                    _add(item.get("ip"))
    for row in src_rows:
        _add(row[0])

    if not ordered:
        return []

    with engine.begin() as conn:
        cached = {
            str(row[0])
            for row in conn.execute(
                select(IpEnrichmentCacheModel.ip).where(IpEnrichmentCacheModel.ip.in_(ordered))
            ).all()
        }
    return [ip for ip in ordered if ip not in cached]


def _get_cached_ip(ip: str) -> Optional[dict]:
    with engine.begin() as conn:
        row = conn.execute(
            select(
                IpEnrichmentCacheModel.country,
                IpEnrichmentCacheModel.region,
                IpEnrichmentCacheModel.city,
                IpEnrichmentCacheModel.loc,
                IpEnrichmentCacheModel.org,
                IpEnrichmentCacheModel.asn,
                IpEnrichmentCacheModel.asn_org,
                IpEnrichmentCacheModel.data,
                IpEnrichmentCacheModel.expires_at,
            )
            .where(IpEnrichmentCacheModel.ip == ip)
            .limit(1)
        ).mappings().fetchone()
        if not row:
            return None
        expires_at = row.get("expires_at")
        if expires_at is not None:
            try:
                if expires_at <= _utc_now():
                    return None
            except Exception:
                return None
        data = row.get("data") or {}
        return {
            "country": row.get("country"),
            "region": row.get("region"),
            "city": row.get("city"),
            "loc": row.get("loc"),
            "org": row.get("org"),
            "asn": row.get("asn"),
            "asn_org": row.get("asn_org"),
            "data": data,
            "provider": data.get("provider") if isinstance(data, dict) else None,
        }


def _upsert_cache(ip: str, rec: dict, ttl_days: int) -> None:
    expires_at = _utc_now() + timedelta(days=int(ttl_days))
    with engine.begin() as conn:
        ins = insert(IpEnrichmentCacheModel).values(
            ip=ip,
            country=rec.get("country"),
            region=rec.get("region"),
            city=rec.get("city"),
            loc=rec.get("loc"),
            org=rec.get("org"),
            asn=rec.get("asn"),
            asn_org=rec.get("asn_org"),
            data=rec.get("data") or {},
            fetched_at=_utc_now(),
            expires_at=expires_at,
        )
        conn.execute(
            ins.on_conflict_do_update(
                index_elements=[IpEnrichmentCacheModel.ip],
                set_={
                    "country": ins.excluded.country,
                    "region": ins.excluded.region,
                    "city": ins.excluded.city,
                    "loc": ins.excluded.loc,
                    "org": ins.excluded.org,
                    "asn": ins.excluded.asn,
                    "asn_org": ins.excluded.asn_org,
                    "data": ins.excluded.data,
                    "fetched_at": _utc_now(),
                    "expires_at": ins.excluded.expires_at,
                },
            )
        )


def _patch_event(event_id: int, patch: dict) -> None:
    with engine.begin() as conn:
        conn.execute(
            update(NetEventModel)
            .where(NetEventModel.id == int(event_id))
            .values(extra=NetEventModel.extra.op("||")(patch))
        )
