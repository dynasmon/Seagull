from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import and_, func, not_, or_, select
from sqlalchemy.orm import Session

from app.core.integrations.clickhouse import (
    clickhouse_events_table_ref,
    clickhouse_is_available,
    clickhouse_is_enabled,
    get_clickhouse_client,
)
from app.features.alerts.models import AlertModel
from app.features.events.models import NetEventModel
from app.shared.enrichment.models import IpEnrichmentCacheModel

EVENT_FLOOD_TYPES = ("dos_attack", "ddos_telemetry")
EVENT_SSH_SUSPECT_ACTIONS = ("failed_password", "invalid_user")
EVENT_OUTBOUND_HIGH_TYPES = ("beacon_suspect", "c2_suspect", "exfil_suspect")
EVENT_OUTBOUND_MEDIUM_TYPES = ("egress_anomaly",)
EVENT_RECON_TYPES = ("scan_summary",)

SOURCE_SCAN_LIMIT = 4000
DESTINATION_SCAN_LIMIT = 2000
FLOW_SCAN_LIMIT = 1500
DOS_ATTACK_SCAN_LIMIT = 200
ALERT_SOURCE_SCAN_LIMIT = 4000
RECENT_EVENTS_SCAN_LIMIT = 50

CLICKHOUSE_STATEMENT_GUARDS = {
    "max_execution_time": 4,
    "max_memory_usage": 1_000_000_000,
}

SEVERITY_CLASSES = ("critical", "high", "medium", "low", "info")

_PRIVATE_LIKE_PREFIXES = ("10.", "192.168.", "127.", "169.254.", "fe80", "fc", "fd")
_PRIVATE_172_REGEX = r"^172\.(1[6-9]|2[0-9]|3[01])\."

_CH_FLOOD = "event_type IN ('dos_attack','ddos_telemetry')"
_CH_SSH_FAIL = "(event_type = 'ssh_auth' AND ifNull(ssh_action, '') IN ('failed_password','invalid_user'))"
_CH_RECON = "event_type = 'scan_summary'"
_CH_OUT_HIGH = "event_type IN ('beacon_suspect','c2_suspect','exfil_suspect')"
_CH_EGRESS = "event_type = 'egress_anomaly'"
_CH_HIGH = f"({_CH_FLOOD} OR {_CH_OUT_HIGH})"
_CH_MEDIUM = f"({_CH_SSH_FAIL} OR {_CH_EGRESS})"
_CH_LOW = _CH_RECON
_CH_SUSPECT = f"({_CH_HIGH} OR {_CH_MEDIUM} OR {_CH_LOW})"

_CH_CLASS_COLUMNS = (
    f"countIf({_CH_HIGH}) AS high, "
    f"countIf({_CH_MEDIUM}) AS medium, "
    f"countIf({_CH_LOW}) AS low, "
    f"countIf(NOT {_CH_SUSPECT}) AS info"
)


def normalize_severity(severity: str | None) -> str | None:
    value = (severity or "").strip().lower()
    return value if value in SEVERITY_CLASSES else None


def classify_event_severity(event_type: Any, ssh_action: Any) -> str:
    etype = str(event_type or "").strip()
    if etype in EVENT_FLOOD_TYPES or etype in EVENT_OUTBOUND_HIGH_TYPES:
        return "high"
    if etype == "ssh_auth" and str(ssh_action or "").strip() in EVENT_SSH_SUSPECT_ACTIONS:
        return "medium"
    if etype in EVENT_OUTBOUND_MEDIUM_TYPES:
        return "medium"
    if etype in EVENT_RECON_TYPES:
        return "low"
    return "info"


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


def _naive_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def clickhouse_client_or_none() -> Optional[Any]:
    if not clickhouse_is_enabled() or not clickhouse_is_available():
        return None
    try:
        return get_clickhouse_client()
    except Exception:
        return None


def _ch_rows(client: Any, sql: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    res = client.query(sql, parameters=params, settings=CLICKHOUSE_STATEMENT_GUARDS)
    cols = list(getattr(res, "column_names", []) or [])
    return [dict(zip(cols, row, strict=False)) for row in (getattr(res, "result_rows", []) or [])]


def _ch_not_private(col: str) -> str:
    prefixes = " OR ".join(f"startsWith({col}, '{prefix}')" for prefix in _PRIVATE_LIKE_PREFIXES)
    regex = _PRIVATE_172_REGEX.replace("\\", "\\\\")
    return f"NOT ({prefixes} OR {col} = '::1' OR match({col}, '{regex}'))"


def _ch_public_endpoint(col: str) -> str:
    return f"(ifNull({col}, '') != '' AND {_ch_not_private(col)})"


def _ch_severity_predicate(severity: str | None) -> str | None:
    if severity == "high":
        return _CH_HIGH
    if severity == "medium":
        return _CH_MEDIUM
    if severity == "low":
        return _CH_LOW
    if severity == "info":
        return f"NOT {_CH_SUSPECT}"
    return None


def ch_aggregate_event_sources(
    client: Any,
    *,
    since: datetime,
    severity: str | None = None,
    limit: int = SOURCE_SCAN_LIMIT,
) -> list[dict[str, Any]]:
    sev = normalize_severity(severity)
    if sev == "critical":
        return []
    conditions = [
        "timestamp >= {since:DateTime64(3)}",
        _ch_public_endpoint("src_ip"),
    ]
    predicate = _ch_severity_predicate(sev)
    if predicate:
        conditions.append(predicate)
    sql = (
        f"SELECT src_ip, count() AS cnt, {_CH_CLASS_COLUMNS}, max(timestamp) AS last_seen "
        f"FROM {clickhouse_events_table_ref()} "
        f"WHERE {' AND '.join(conditions)} "
        "GROUP BY src_ip ORDER BY cnt DESC "
        f"LIMIT {int(limit)}"
    )
    return [
        {
            "src_ip": row.get("src_ip"),
            "count": int(row.get("cnt") or 0),
            "high": int(row.get("high") or 0),
            "medium": int(row.get("medium") or 0),
            "low": int(row.get("low") or 0),
            "info": int(row.get("info") or 0),
            "last_seen": row.get("last_seen"),
        }
        for row in _ch_rows(client, sql, {"since": _naive_utc(since)})
    ]


def ch_aggregate_event_destinations(
    client: Any,
    *,
    since: datetime,
    severity: str | None = None,
    limit: int = DESTINATION_SCAN_LIMIT,
) -> list[dict[str, Any]]:
    sev = normalize_severity(severity)
    if sev in ("critical", "low"):
        return []
    conditions = [
        "timestamp >= {since:DateTime64(3)}",
        _ch_public_endpoint("dst_ip"),
    ]
    if sev == "high":
        conditions.append(_CH_OUT_HIGH)
    elif sev == "medium":
        conditions.append(_CH_EGRESS)
    elif sev == "info":
        conditions.append(f"NOT {_CH_SUSPECT}")
    sql = (
        f"SELECT dst_ip AS src_ip, count() AS cnt, {_CH_CLASS_COLUMNS}, max(timestamp) AS last_seen "
        f"FROM {clickhouse_events_table_ref()} "
        f"WHERE {' AND '.join(conditions)} "
        "GROUP BY dst_ip ORDER BY cnt DESC "
        f"LIMIT {int(limit)}"
    )
    return [
        {
            "src_ip": row.get("src_ip"),
            "count": int(row.get("cnt") or 0),
            "high": int(row.get("high") or 0),
            "medium": int(row.get("medium") or 0),
            "low": int(row.get("low") or 0),
            "info": int(row.get("info") or 0),
            "last_seen": row.get("last_seen"),
        }
        for row in _ch_rows(client, sql, {"since": _naive_utc(since)})
    ]


def ch_aggregate_event_flows(
    client: Any,
    *,
    since: datetime,
    severity: str | None = None,
    limit: int = FLOW_SCAN_LIMIT,
) -> list[dict[str, Any]]:
    sev = normalize_severity(severity)
    if sev == "critical":
        return []
    conditions = [
        "timestamp >= {since:DateTime64(3)}",
        "ifNull(src_ip, '') != ''",
        "ifNull(dst_ip, '') != ''",
        "src_ip != dst_ip",
        f"({_ch_not_private('src_ip')} OR {_ch_not_private('dst_ip')})",
    ]
    predicate = _ch_severity_predicate(sev)
    if predicate:
        conditions.append(predicate)
    sql = (
        f"SELECT src_ip, dst_ip, count() AS cnt, {_CH_CLASS_COLUMNS}, max(timestamp) AS last_seen "
        f"FROM {clickhouse_events_table_ref()} "
        f"WHERE {' AND '.join(conditions)} "
        "GROUP BY src_ip, dst_ip ORDER BY cnt DESC "
        f"LIMIT {int(limit)}"
    )
    return [
        {
            "src_ip": row.get("src_ip"),
            "dst_ip": row.get("dst_ip"),
            "count": int(row.get("cnt") or 0),
            "high": int(row.get("high") or 0),
            "medium": int(row.get("medium") or 0),
            "low": int(row.get("low") or 0),
            "info": int(row.get("info") or 0),
            "last_seen": row.get("last_seen"),
        }
        for row in _ch_rows(client, sql, {"since": _naive_utc(since)})
    ]


def ch_count_events(client: Any, *, since: datetime, severity: str | None = None) -> int:
    sev = normalize_severity(severity)
    if sev == "critical":
        return 0
    conditions = ["timestamp >= {since:DateTime64(3)}"]
    predicate = _ch_severity_predicate(sev)
    if predicate:
        conditions.append(predicate)
    sql = (
        f"SELECT count() AS total FROM {clickhouse_events_table_ref()} "
        f"WHERE {' AND '.join(conditions)}"
    )
    rows = _ch_rows(client, sql, {"since": _naive_utc(since)})
    return int(rows[0].get("total") or 0) if rows else 0


def ch_recent_events(
    client: Any,
    *,
    since: datetime,
    severity: str | None = None,
    limit: int = RECENT_EVENTS_SCAN_LIMIT,
) -> list[dict[str, Any]]:
    sev = normalize_severity(severity)
    if sev == "critical":
        return []
    conditions = [
        "timestamp >= {since:DateTime64(3)}",
        f"({_ch_public_endpoint('src_ip')} OR {_ch_public_endpoint('dst_ip')})",
    ]
    predicate = _ch_severity_predicate(sev)
    if predicate:
        conditions.append(predicate)
    sql = (
        "SELECT timestamp, event_type, ssh_action, src_ip, dst_ip, dst_port, proto "
        f"FROM {clickhouse_events_table_ref()} "
        f"WHERE {' AND '.join(conditions)} "
        "ORDER BY timestamp DESC "
        f"LIMIT {int(limit)}"
    )
    return _ch_rows(client, sql, {"since": _naive_utc(since)})


def _event_ssh_action():
    return func.coalesce(NetEventModel.ssh_action, NetEventModel.extra["action"].astext)


def _pg_not_private(col):
    return not_(
        or_(
            *[col.like(f"{prefix}%") for prefix in _PRIVATE_LIKE_PREFIXES],
            col == "::1",
            col.op("~")(_PRIVATE_172_REGEX),
        )
    )


def _pg_class_predicates():
    flood = NetEventModel.event_type.in_(EVENT_FLOOD_TYPES)
    ssh_fail = and_(
        NetEventModel.event_type == "ssh_auth",
        _event_ssh_action().in_(EVENT_SSH_SUSPECT_ACTIONS),
    )
    recon = NetEventModel.event_type.in_(EVENT_RECON_TYPES)
    out_high = NetEventModel.event_type.in_(EVENT_OUTBOUND_HIGH_TYPES)
    egress = NetEventModel.event_type.in_(EVENT_OUTBOUND_MEDIUM_TYPES)
    high = or_(flood, out_high)
    medium = or_(ssh_fail, egress)
    low = recon
    suspect = or_(high, medium, low)
    return {
        "high": high,
        "medium": medium,
        "low": low,
        "info": not_(suspect),
        "out_high": out_high,
        "egress": egress,
        "suspect": suspect,
    }


def _pg_class_columns(preds: dict[str, Any]):
    return (
        func.count().filter(preds["high"]).label("high"),
        func.count().filter(preds["medium"]).label("medium"),
        func.count().filter(preds["low"]).label("low"),
        func.count().filter(preds["info"]).label("info"),
    )


def pg_aggregate_event_sources(
    db: Session,
    *,
    since: datetime,
    severity: str | None = None,
    limit: int = SOURCE_SCAN_LIMIT,
) -> list[Any]:
    sev = normalize_severity(severity)
    if sev == "critical":
        return []
    preds = _pg_class_predicates()
    stmt = (
        select(
            NetEventModel.src_ip.label("src_ip"),
            func.count().label("count"),
            *_pg_class_columns(preds),
            func.max(NetEventModel.timestamp).label("last_seen"),
        )
        .where(
            NetEventModel.timestamp >= since,
            NetEventModel.src_ip.is_not(None),
            _pg_not_private(NetEventModel.src_ip),
        )
        .group_by(NetEventModel.src_ip)
        .order_by(func.count().desc())
        .limit(int(limit))
    )
    if sev:
        stmt = stmt.where(preds[sev])
    return db.execute(stmt).mappings().all()


def pg_aggregate_event_destinations(
    db: Session,
    *,
    since: datetime,
    severity: str | None = None,
    limit: int = DESTINATION_SCAN_LIMIT,
) -> list[Any]:
    sev = normalize_severity(severity)
    if sev in ("critical", "low"):
        return []
    preds = _pg_class_predicates()
    stmt = (
        select(
            NetEventModel.dst_ip.label("src_ip"),
            func.count().label("count"),
            *_pg_class_columns(preds),
            func.max(NetEventModel.timestamp).label("last_seen"),
        )
        .where(
            NetEventModel.timestamp >= since,
            NetEventModel.dst_ip.is_not(None),
            _pg_not_private(NetEventModel.dst_ip),
        )
        .group_by(NetEventModel.dst_ip)
        .order_by(func.count().desc())
        .limit(int(limit))
    )
    if sev == "high":
        stmt = stmt.where(preds["out_high"])
    elif sev == "medium":
        stmt = stmt.where(preds["egress"])
    elif sev == "info":
        stmt = stmt.where(preds["info"])
    return db.execute(stmt).mappings().all()


def pg_aggregate_event_flows(
    db: Session,
    *,
    since: datetime,
    severity: str | None = None,
    limit: int = FLOW_SCAN_LIMIT,
) -> list[Any]:
    sev = normalize_severity(severity)
    if sev == "critical":
        return []
    preds = _pg_class_predicates()
    stmt = (
        select(
            NetEventModel.src_ip.label("src_ip"),
            NetEventModel.dst_ip.label("dst_ip"),
            func.count().label("count"),
            *_pg_class_columns(preds),
            func.max(NetEventModel.timestamp).label("last_seen"),
        )
        .where(
            NetEventModel.timestamp >= since,
            NetEventModel.src_ip.is_not(None),
            NetEventModel.dst_ip.is_not(None),
            NetEventModel.src_ip != NetEventModel.dst_ip,
            or_(_pg_not_private(NetEventModel.src_ip), _pg_not_private(NetEventModel.dst_ip)),
        )
        .group_by(NetEventModel.src_ip, NetEventModel.dst_ip)
        .order_by(func.count().desc())
        .limit(int(limit))
    )
    if sev:
        stmt = stmt.where(preds[sev])
    return db.execute(stmt).mappings().all()


def pg_count_events(db: Session, *, since: datetime, severity: str | None = None) -> int:
    sev = normalize_severity(severity)
    if sev == "critical":
        return 0
    stmt = select(func.count()).select_from(NetEventModel).where(NetEventModel.timestamp >= since)
    if sev:
        stmt = stmt.where(_pg_class_predicates()[sev])
    return int(db.execute(stmt).scalar() or 0)


def pg_recent_events(
    db: Session,
    *,
    since: datetime,
    severity: str | None = None,
    limit: int = RECENT_EVENTS_SCAN_LIMIT,
) -> list[Any]:
    sev = normalize_severity(severity)
    if sev == "critical":
        return []
    preds = _pg_class_predicates()
    stmt = (
        select(
            NetEventModel.timestamp.label("timestamp"),
            NetEventModel.event_type.label("event_type"),
            _event_ssh_action().label("ssh_action"),
            NetEventModel.src_ip.label("src_ip"),
            NetEventModel.dst_ip.label("dst_ip"),
            NetEventModel.dst_port.label("dst_port"),
            NetEventModel.proto.label("proto"),
        )
        .where(
            NetEventModel.timestamp >= since,
            or_(
                and_(NetEventModel.src_ip.is_not(None), _pg_not_private(NetEventModel.src_ip)),
                and_(NetEventModel.dst_ip.is_not(None), _pg_not_private(NetEventModel.dst_ip)),
            ),
        )
        .order_by(NetEventModel.timestamp.desc())
        .limit(int(limit))
    )
    if sev:
        stmt = stmt.where(preds[sev])
    return db.execute(stmt).mappings().all()


def recent_dos_attack_events(
    db: Session,
    *,
    since: datetime,
    severity: str | None = None,
    limit: int = DOS_ATTACK_SCAN_LIMIT,
) -> list[Any]:
    sev = normalize_severity(severity)
    if sev in ("critical", "medium", "low", "info"):
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


def aggregate_threat_sources(
    db: Session,
    *,
    since: datetime,
    severity: str | None = None,
    limit: int = ALERT_SOURCE_SCAN_LIMIT,
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
        .where(AlertModel.created_at >= _naive_utc(since), AlertModel.src_ip.is_not(None))
        .group_by(AlertModel.src_ip)
        .order_by(func.count().desc())
        .limit(int(limit))
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
        .where(AlertModel.created_at >= _naive_utc(since), AlertModel.src_ip.is_not(None))
        .group_by(AlertModel.src_ip, AlertModel.rule_id)
    )
    if severity:
        stmt = stmt.where(func.lower(AlertModel.severity) == severity.lower())
    if src_ips:
        stmt = stmt.where(AlertModel.src_ip.in_(src_ips))
    return db.execute(stmt).mappings().all()


def aggregate_alert_flows(
    db: Session,
    *,
    since: datetime,
    severity: str | None = None,
    limit: int = FLOW_SCAN_LIMIT,
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
            AlertModel.created_at >= _naive_utc(since),
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
            ).where(IpEnrichmentCacheModel.ip.in_(clean_ips))
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
