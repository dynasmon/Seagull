from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.features.alerts.models import AlertModel
from app.features.events.models import NetEventModel
from app.shared.enrichment.models import IpEnrichmentCacheModel

EVENT_FLOOD_TYPES = ("dos_attack", "ddos_telemetry")
EVENT_SSH_SUSPECT_ACTIONS = ("failed_password", "invalid_user")
EVENT_OUTBOUND_HIGH_TYPES = ("beacon_suspect", "c2_suspect", "exfil_suspect")
EVENT_OUTBOUND_MEDIUM_TYPES = ("egress_anomaly",)
EVENT_OUTBOUND_TYPES = EVENT_OUTBOUND_HIGH_TYPES + EVENT_OUTBOUND_MEDIUM_TYPES
EVENT_RECON_TYPES = ("scan_summary",)

EVENT_SCAN_LIMIT = 2000
EVENT_FLOW_SCAN_LIMIT = 400
DOS_ATTACK_SCAN_LIMIT = 200


def _event_ssh_action():
    return func.coalesce(NetEventModel.ssh_action, NetEventModel.extra["action"].astext)


def _normalize_severity(severity: str | None) -> str | None:
    return (severity or "").strip().lower() or None


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


def aggregate_event_sources(
    db: Session,
    *,
    since: datetime,
    severity: str | None = None,
    limit: int = EVENT_SCAN_LIMIT,
) -> list[Any]:
    sev = _normalize_severity(severity)
    flood = NetEventModel.event_type.in_(EVENT_FLOOD_TYPES)
    ssh_suspect = and_(
        NetEventModel.event_type == "ssh_auth",
        _event_ssh_action().in_(EVENT_SSH_SUSPECT_ACTIONS),
    )
    recon = NetEventModel.event_type.in_(EVENT_RECON_TYPES)
    if sev == "high":
        suspicious = flood
    elif sev == "medium":
        suspicious = ssh_suspect
    elif sev == "low":
        suspicious = recon
    elif sev == "critical":
        return []
    else:
        suspicious = or_(flood, ssh_suspect, recon)

    geo_loc = NetEventModel.extra["geo_loc"].astext
    stmt = (
        select(
            NetEventModel.src_ip.label("src_ip"),
            func.count().label("count"),
            func.count().filter(flood).label("high"),
            func.count().filter(ssh_suspect).label("medium"),
            func.count().filter(recon).label("low"),
            func.max(NetEventModel.timestamp).label("last_seen"),
            func.max(geo_loc).label("geo_loc"),
            func.max(NetEventModel.extra["geo_country"].astext).label("country"),
            func.max(NetEventModel.extra["geo_region"].astext).label("region"),
            func.max(NetEventModel.extra["geo_city"].astext).label("city"),
            func.max(NetEventModel.extra["geo_org"].astext).label("org"),
            func.max(NetEventModel.extra["asn"].astext).label("asn"),
            func.max(NetEventModel.extra["asn_org"].astext).label("asn_org"),
        )
        .where(NetEventModel.timestamp >= since, NetEventModel.src_ip.is_not(None), suspicious)
        .group_by(NetEventModel.src_ip)
        .order_by(func.count().desc())
        .limit(int(limit))
    )
    return db.execute(stmt).mappings().all()


def recent_dos_attack_events(
    db: Session,
    *,
    since: datetime,
    severity: str | None = None,
    limit: int = DOS_ATTACK_SCAN_LIMIT,
) -> list[Any]:
    sev = _normalize_severity(severity)
    if sev in ("critical", "medium", "low"):
        return []
    stmt = (
        select(
            NetEventModel.dst_ip.label("dst_ip"),
            NetEventModel.extra["top_src"].label("top_src"),
            NetEventModel.extra["vector"].astext.label("vector"),
            NetEventModel.timestamp.label("last_seen"),
        )
        .where(
            NetEventModel.timestamp >= since,
            NetEventModel.event_type.in_(EVENT_FLOOD_TYPES),
            NetEventModel.extra.has_key("top_src"),
        )
        .order_by(NetEventModel.timestamp.desc())
        .limit(int(limit))
    )
    return db.execute(stmt).mappings().all()


def aggregate_event_destinations(
    db: Session,
    *,
    since: datetime,
    severity: str | None = None,
    limit: int = EVENT_SCAN_LIMIT,
) -> list[Any]:
    sev = _normalize_severity(severity)
    if sev == "high":
        types = EVENT_OUTBOUND_HIGH_TYPES
    elif sev == "medium":
        types = EVENT_OUTBOUND_MEDIUM_TYPES
    elif sev in ("critical", "low"):
        return []
    else:
        types = EVENT_OUTBOUND_TYPES

    high = NetEventModel.event_type.in_(EVENT_OUTBOUND_HIGH_TYPES)
    medium = NetEventModel.event_type.in_(EVENT_OUTBOUND_MEDIUM_TYPES)
    stmt = (
        select(
            NetEventModel.dst_ip.label("src_ip"),
            func.count().label("count"),
            func.count().filter(high).label("high"),
            func.count().filter(medium).label("medium"),
            func.max(NetEventModel.timestamp).label("last_seen"),
        )
        .where(
            NetEventModel.timestamp >= since,
            NetEventModel.dst_ip.is_not(None),
            NetEventModel.event_type.in_(types),
        )
        .group_by(NetEventModel.dst_ip)
        .order_by(func.count().desc())
        .limit(int(limit))
    )
    return db.execute(stmt).mappings().all()


def aggregate_event_flows(
    db: Session,
    *,
    since: datetime,
    severity: str | None = None,
    limit: int = EVENT_FLOW_SCAN_LIMIT,
) -> list[Any]:
    sev = _normalize_severity(severity)
    flood = NetEventModel.event_type.in_(EVENT_FLOOD_TYPES)
    ssh_suspect = and_(
        NetEventModel.event_type == "ssh_auth",
        _event_ssh_action().in_(EVENT_SSH_SUSPECT_ACTIONS),
    )
    outbound_high = NetEventModel.event_type.in_(EVENT_OUTBOUND_HIGH_TYPES)
    outbound_medium = NetEventModel.event_type.in_(EVENT_OUTBOUND_MEDIUM_TYPES)
    high_pred = or_(flood, outbound_high)
    medium_pred = or_(ssh_suspect, outbound_medium)
    if sev == "high":
        suspicious = high_pred
    elif sev == "medium":
        suspicious = medium_pred
    elif sev in ("critical", "low"):
        return []
    else:
        suspicious = or_(high_pred, medium_pred)

    stmt = (
        select(
            NetEventModel.src_ip.label("src_ip"),
            NetEventModel.dst_ip.label("dst_ip"),
            func.count().label("count"),
            func.count().filter(high_pred).label("high"),
            func.count().filter(medium_pred).label("medium"),
            func.max(NetEventModel.timestamp).label("last_seen"),
            func.max(NetEventModel.extra["geo_loc"].astext).label("src_geo_loc"),
            func.max(NetEventModel.extra["geo_country"].astext).label("src_country"),
            func.max(NetEventModel.extra["geo_region"].astext).label("src_region"),
            func.max(NetEventModel.extra["geo_city"].astext).label("src_city"),
        )
        .where(
            NetEventModel.timestamp >= since,
            NetEventModel.src_ip.is_not(None),
            NetEventModel.dst_ip.is_not(None),
            suspicious,
        )
        .group_by(NetEventModel.src_ip, NetEventModel.dst_ip)
        .order_by(func.count().desc())
        .limit(int(limit))
    )
    return db.execute(stmt).mappings().all()


def aggregate_alert_flows(
    db: Session,
    *,
    since: datetime,
    severity: str | None = None,
    limit: int = EVENT_FLOW_SCAN_LIMIT,
) -> list[Any]:
    sev_expr = func.lower(AlertModel.severity)
    stmt = (
        select(
            AlertModel.src_ip.label("src_ip"),
            AlertModel.dst_ip.label("dst_ip"),
            func.count().label("count"),
            func.count().filter(sev_expr == "critical").label("critical"),
            func.count().filter(sev_expr == "high").label("high"),
            func.count().filter(sev_expr == "medium").label("medium"),
            func.count().filter(sev_expr == "low").label("low"),
            func.max(AlertModel.created_at).label("last_seen"),
        )
        .where(
            AlertModel.created_at >= since,
            AlertModel.src_ip.is_not(None),
            AlertModel.dst_ip.is_not(None),
        )
        .group_by(AlertModel.src_ip, AlertModel.dst_ip)
        .order_by(func.count().desc())
        .limit(int(limit))
    )
    if severity:
        stmt = stmt.where(sev_expr == severity.lower())
    return db.execute(stmt).mappings().all()
