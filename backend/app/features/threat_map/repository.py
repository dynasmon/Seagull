from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.features.alerts.models import AlertModel
from app.features.events.models import NetEventModel
from app.shared.enrichment.models import IpEnrichmentCacheModel

DOS_EVENT_SCAN_LIMIT = 500
DOS_EVENT_TYPES = ("dos_attack", "ddos_telemetry")


def parse_loc(loc: Any) -> tuple[float, float] | None:
    if not loc:
        return None
    parts = str(loc).split(",")
    if len(parts) != 2:
        return None
    try:
        lat = float(parts[0].strip())
        lon = float(parts[1].strip())
    except (TypeError, ValueError):
        return None
    if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
        return None
    if lat == 0.0 and lon == 0.0:
        return None
    return lat, lon


def aggregate_threat_sources(
    db: Session,
    *,
    since: datetime,
    severity: str | None = None,
) -> list[Any]:
    sev = func.lower(AlertModel.severity)
    stmt = (
        select(
            AlertModel.src_ip.label("src_ip"),
            func.count().label("count"),
            func.count().filter(sev == "critical").label("critical"),
            func.count().filter(sev == "high").label("high"),
            func.count().filter(sev == "medium").label("medium"),
            func.count().filter(sev == "low").label("low"),
            func.max(AlertModel.created_at).label("last_seen"),
        )
        .where(AlertModel.created_at >= since, AlertModel.src_ip.is_not(None))
        .group_by(AlertModel.src_ip)
        .order_by(func.count().desc())
    )
    if severity:
        stmt = stmt.where(sev == severity.lower())
    return db.execute(stmt).mappings().all()


def aggregate_threat_source_rules(
    db: Session,
    *,
    since: datetime,
    severity: str | None = None,
    src_ips: list[str] | None = None,
) -> list[Any]:
    stmt = (
        select(
            AlertModel.src_ip.label("src_ip"),
            AlertModel.rule_id.label("rule_id"),
            func.count().label("count"),
        )
        .where(AlertModel.created_at >= since, AlertModel.src_ip.is_not(None))
        .group_by(AlertModel.src_ip, AlertModel.rule_id)
    )
    if severity:
        stmt = stmt.where(func.lower(AlertModel.severity) == severity.lower())
    if src_ips:
        stmt = stmt.where(AlertModel.src_ip.in_(src_ips))
    return db.execute(stmt).mappings().all()


def recent_dos_attack_events(
    db: Session,
    *,
    since: datetime,
    limit: int = DOS_EVENT_SCAN_LIMIT,
) -> list[Any]:
    stmt = (
        select(
            NetEventModel.dst_ip.label("dst_ip"),
            NetEventModel.extra["top_src"].label("top_src"),
            NetEventModel.extra["severity"].astext.label("severity"),
            NetEventModel.extra["vector"].astext.label("vector"),
            NetEventModel.timestamp.label("last_seen"),
        )
        .where(
            NetEventModel.timestamp >= since,
            NetEventModel.event_type.in_(DOS_EVENT_TYPES),
            NetEventModel.extra.has_key("top_src"),
        )
        .order_by(NetEventModel.timestamp.desc())
        .limit(int(limit))
    )
    return db.execute(stmt).mappings().all()


def load_geo_cache(db: Session, ips: list[str]) -> dict[str, dict[str, Any]]:
    clean_ips = sorted({str(ip).strip() for ip in ips if str(ip).strip()})
    if not clean_ips:
        return {}
    rows = (
        db.execute(
            select(
                IpEnrichmentCacheModel.ip,
                IpEnrichmentCacheModel.country,
                IpEnrichmentCacheModel.region,
                IpEnrichmentCacheModel.city,
                IpEnrichmentCacheModel.loc,
                IpEnrichmentCacheModel.org,
                IpEnrichmentCacheModel.asn,
                IpEnrichmentCacheModel.asn_org,
            )
            .where(IpEnrichmentCacheModel.ip.in_(clean_ips))
            .where(or_(IpEnrichmentCacheModel.expires_at.is_(None), IpEnrichmentCacheModel.expires_at > func.now()))
        )
        .mappings()
        .all()
    )
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        coords = parse_loc(row.get("loc"))
        if not coords:
            continue
        lat, lon = coords
        out[str(row["ip"])] = {
            "lat": lat,
            "lon": lon,
            "country": row.get("country"),
            "region": row.get("region"),
            "city": row.get("city"),
            "org": row.get("org"),
            "asn": row.get("asn"),
            "asn_org": row.get("asn_org"),
        }
    return out
