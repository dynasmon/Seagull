from __future__ import annotations

import json
import logging
import threading
import time
import zlib
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Query
from sqlalchemy import Float, and_, case, cast, func, or_, select

from app.core.db import SessionLocal
from app.core.es import es_is_available, get_es_client
from app.core.portal_auth import get_current_user
from app.core.redis_client import get_redis
from app.core.config import settings
from app.core.observability import incr_counter, log_event, observe_hist
from app.models.agents import AgentModel
from app.models.alerts import AlertModel
from app.models.events import EventRollup1mModel, IngestStats1sModel, NetEventModel, NetEventRollup1sModel, SshFailRollup1mModel

router = APIRouter(
    prefix="",
    tags=["overview"],
    dependencies=[Depends(get_current_user)],
)
logger = logging.getLogger("netwatch.api.overview")

_overview_cache_lock = threading.Lock()
_overview_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}


def _env_int(name: str, default: int) -> int:
    raw = getattr(settings, name, None)
    if raw is None:
        return default
    try:
        return int(raw)
    except Exception:
        return default


def _overview_cache_get(key: str) -> Optional[Dict[str, Any]]:
    ttl_s = max(0, _env_int("NETWATCH_OVERVIEW_CACHE_TTL_SECONDS", 3))
    if ttl_s <= 0:
        return None

    redis_key = f"netwatch:overview:v2:{key}"
    r = get_redis()
    if r is not None:
        try:
            cached_raw = r.get(redis_key)
            if cached_raw:
                cached_payload = json.loads(cached_raw)
                if isinstance(cached_payload, dict):
                    return cached_payload
        except Exception:
            pass

    now = time.time()
    with _overview_cache_lock:
        item = _overview_cache.get(key)
        if not item:
            return None
        expires_at, payload = item
        if expires_at <= now:
            _overview_cache.pop(key, None)
            return None
        return payload


def _overview_cache_set(key: str, payload: Dict[str, Any]) -> None:
    ttl_s = max(0, _env_int("NETWATCH_OVERVIEW_CACHE_TTL_SECONDS", 3))
    if ttl_s <= 0:
        return
    redis_key = f"netwatch:overview:v2:{key}"
    r = get_redis()
    if r is not None:
        try:
            r.setex(redis_key, ttl_s, json.dumps(payload, ensure_ascii=True, separators=(",", ":"), default=str))
        except Exception:
            pass
    now = time.time()
    max_entries = max(16, _env_int("NETWATCH_OVERVIEW_CACHE_MAX_ENTRIES", 128))
    with _overview_cache_lock:
        _overview_cache[key] = (now + float(ttl_s), payload)
        if len(_overview_cache) > max_entries:
            keys = sorted(_overview_cache.items(), key=lambda kv: kv[1][0])
            for k, _ in keys[: max(1, len(_overview_cache) - max_entries)]:
                _overview_cache.pop(k, None)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _env_str(name: str, default: str) -> str:
    raw = getattr(settings, name, None)
    if raw is None:
        return default
    raw = str(raw).strip()
    return raw if raw else default


def _to_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _minute_floor(dt: datetime) -> datetime:
    dt = _to_utc(dt) or dt
    return dt.replace(second=0, microsecond=0)


def _minute_buckets(start_ts: datetime, end_ts: datetime) -> List[datetime]:
    start = _minute_floor(start_ts)
    end = _minute_floor(end_ts)
    out: List[datetime] = []
    cur = start
    while cur <= end:
        out.append(cur)
        cur += timedelta(minutes=1)
    return out


def _fmt_hhmm(dt: datetime) -> str:
    dt = _to_utc(dt) or dt
    return dt.strftime("%H:%M")


def _event_type_filter(col):
    return and_(col.is_not(None), ~col.like(r"%\_summary", escape="\\"))


def _ddos_rule_filter(col):
    return or_(
        col == "incident_ddos_correlated_v1",
        col.like(r"ddos\_%", escape="\\"),
        col.like(r"dos\_%", escape="\\"),
        col.like(r"l7\_%", escape="\\"),
    )


def _best_effort_ingest_backlog() -> Tuple[int, int]:
    r = get_redis()
    if r is None:
        return (0, 0)
    try:
        backlog_key = _env_str("NETWATCH_INGEST_BACKLOG_EVENTS_KEY", "netwatch:ingest:backlog_events")
        qk = _env_str("NETWATCH_INGEST_QUEUE_KEY", "netwatch:ingest:queue")
        pk = _env_str("NETWATCH_INGEST_PROCESSING_KEY", f"{qk}:processing")

        ev = int(r.get(backlog_key) or 0)
        msgs = int(r.llen(qk) or 0) + int(r.llen(pk) or 0)
        return (max(0, ev), max(0, msgs))
    except Exception:
        return (0, 0)


def _storm_key_active() -> bool:
    r = get_redis()
    if r is None:
        return False
    try:
        k = _env_str("NETWATCH_INGEST_STORM_ACTIVE_KEY", "netwatch:ingest:storm_active")
        return bool(r.get(k))
    except Exception:
        return False


def _warm_index_prefix() -> str:
    return _env_str(
        "NETWATCH_INGEST_WARM_INDEX_PREFIX",
        _env_str("NETWATCH_ES_INDEX_PREFIX", "netwatch-events") + "-warm",
    )


def _warm_recent_events(*, agent_id: Optional[str], start_ts: datetime, end_ts: datetime, limit: int = 30) -> List[Dict[str, Any]]:
    if not es_is_available():
        return []
    try:
        es = get_es_client()
        must: List[Dict[str, Any]] = []
        if agent_id:
            must.append({"term": {"agent_id": agent_id}})
        must.append({"range": {"timestamp": {"gte": start_ts.isoformat(), "lte": end_ts.isoformat()}}})
        q = {"bool": {"must": must}} if must else {"match_all": {}}

        resp = es.search(
            index=f"{_warm_index_prefix()}-*",
            size=max(1, min(int(limit), 200)),
            sort=[{"timestamp": {"order": "desc"}}],
            query=q,
            track_total_hits=False,
            source=["timestamp", "agent_id", "event_type", "src_ip", "dst_ip", "dst_port"],
        )

        out: List[Dict[str, Any]] = []
        for hit in (resp.get("hits") or {}).get("hits") or []:
            src = hit.get("_source") or {}
            ts = src.get("timestamp")
            aid = src.get("agent_id")
            et = src.get("event_type")
            if not ts or not aid or not et:
                continue

            raw_id = f"{aid}|{et}|{ts}|{src.get('dst_ip','')}|{src.get('dst_port','')}"
            eid = int(zlib.crc32(raw_id.encode("utf-8")) & 0xFFFFFFFF)

            out.append(
                {
                    "id": eid,
                    "timestamp": ts,
                    "agent_id": aid,
                    "event_type": et,
                    "src_ip": src.get("src_ip"),
                    "dst_ip": src.get("dst_ip"),
                    "dst_port": src.get("dst_port"),
                }
            )
        return out
    except Exception:
        return []


def _top_event_types(db, start_ts: datetime, end_ts: datetime, agent_id: Optional[str]) -> List[str]:
    stmt = (
        select(EventRollup1mModel.event_type, func.sum(EventRollup1mModel.count).label("total"))
        .where(
            EventRollup1mModel.bucket_ts >= start_ts,
            EventRollup1mModel.bucket_ts <= end_ts,
            _event_type_filter(EventRollup1mModel.event_type),
        )
        .group_by(EventRollup1mModel.event_type)
        .order_by(func.sum(EventRollup1mModel.count).desc())
        .limit(3)
    )
    if agent_id:
        stmt = stmt.where(EventRollup1mModel.agent_id == agent_id)
    rows = db.execute(stmt).all()
    if rows:
        return [str(r.event_type) for r in rows if r.event_type]

    stmt2 = (
        select(NetEventModel.event_type, func.count().label("total"))
        .where(
            NetEventModel.timestamp >= start_ts,
            NetEventModel.timestamp <= end_ts,
            _event_type_filter(NetEventModel.event_type),
        )
        .group_by(NetEventModel.event_type)
        .order_by(func.count().desc())
        .limit(3)
    )
    if agent_id:
        stmt2 = stmt2.where(NetEventModel.agent_id == agent_id)
    rows2 = db.execute(stmt2).all()
    return [str(r.event_type) for r in rows2 if r.event_type]


@router.get("/overview")
def get_overview(
    window_minutes: int = Query(60, ge=5, le=1440, description="Time window (minutes) for charts"),
    agent_id: Optional[str] = Query(None, description="Optional agent filter for charts/tables"),
    lite: bool = Query(False, description="If true, skip heavy tables for faster first paint"),
):
    started = time.perf_counter()
    cache_key = f"w={int(window_minutes)}|a={agent_id or '*'}|lite={1 if lite else 0}"
    cached = _overview_cache_get(cache_key)
    if cached is not None:
        incr_counter("api_cache_hit_total", route="/overview")
        return cached

    now = _utc_now()
    backlog_ev, backlog_msgs = _best_effort_ingest_backlog()

    db = SessionLocal()
    try:
        pressure_window_s = max(30, _env_int("NETWATCH_OVERVIEW_PRESSURE_LOOKBACK_SECONDS", 120))
        rollup_fresh_s = max(10, _env_int("NETWATCH_OVERVIEW_INGEST_ROLLUP_FRESH_SECONDS", 120))
        draining_ev_threshold = max(0, _env_int("NETWATCH_OVERVIEW_DRAINING_BACKLOG_EVENTS_THRESHOLD", 25_000))
        draining_msg_threshold = max(0, _env_int("NETWATCH_OVERVIEW_DRAINING_BACKLOG_MESSAGES_THRESHOLD", 5))

        protection_active = _storm_key_active()

        try:
            pr_stmt = select(
                func.coalesce(func.max(case((IngestStats1sModel.storm_active.is_(True), 1), else_=0)), 0).label("storm_active"),
                func.coalesce(func.sum(IngestStats1sModel.rollup_only), 0).label("rollup_only"),
                func.coalesce(func.min(IngestStats1sModel.sample_hot_percent), 100).label("min_hot"),
            ).where(IngestStats1sModel.bucket_ts >= now - timedelta(seconds=pressure_window_s))
            pr = db.execute(pr_stmt).mappings().first() or {}
            protection_active = protection_active or int(pr.get("storm_active") or 0) == 1
            protection_active = protection_active or int(pr.get("rollup_only") or 0) > 0
            protection_active = protection_active or int(pr.get("min_hot") or 100) < 100
        except Exception:
            pass

        try:
            last_roll_stmt = select(func.max(NetEventRollup1sModel.bucket_ts).label("last_bucket_ts")).where(
                NetEventRollup1sModel.bucket_ts >= now - timedelta(days=2)
            )
            if agent_id:
                last_roll_stmt = last_roll_stmt.where(NetEventRollup1sModel.agent_id == agent_id)
            last_roll_ts = _to_utc(db.execute(last_roll_stmt).scalar())
        except Exception:
            last_roll_ts = None

        rollups_fresh = False
        if last_roll_ts is not None:
            try:
                rollups_fresh = (now - last_roll_ts).total_seconds() <= float(rollup_fresh_s)
            except Exception:
                rollups_fresh = False

        draining = (backlog_ev >= draining_ev_threshold and draining_ev_threshold > 0) or (
            backlog_msgs >= draining_msg_threshold and draining_msg_threshold > 0
        )
        use_ingest_rollups = bool(rollups_fresh and (protection_active or draining))
        rollup_stuck = False

        # Failsafe: when pressure flags stay high after drain, do not keep overview pinned to stale rollups.
        if use_ingest_rollups and last_roll_ts is not None:
            hot_max_stmt = select(func.max(NetEventModel.timestamp))
            if agent_id:
                hot_max_stmt = hot_max_stmt.where(NetEventModel.agent_id == agent_id)
            hot_last_ts = _to_utc(db.execute(hot_max_stmt).scalar())
            if hot_last_ts is not None:
                drift_s = (hot_last_ts - last_roll_ts).total_seconds()
                if drift_s > float(max(20, rollup_fresh_s)):
                    rollup_stuck = True
                    use_ingest_rollups = False

        data_end_ts = last_roll_ts if (use_ingest_rollups and last_roll_ts is not None) else now
        start_ts = data_end_ts - timedelta(minutes=window_minutes)

        kpi_stmt = select(
            (select(func.count()).select_from(AgentModel)).label("total_agents"),
            (select(func.count()).select_from(AgentModel).where(AgentModel.last_seen_at >= now - timedelta(minutes=5))).label("online_agents"),
            (select(func.count()).select_from(AlertModel).where(AlertModel.created_at >= now - timedelta(minutes=60))).label("alerts_60m"),
        )
        kpi_row = db.execute(kpi_stmt).mappings().one()
        total_agents = int(kpi_row.get("total_agents") or 0)
        online_agents = int(kpi_row.get("online_agents") or 0)
        alerts_60m = int(kpi_row.get("alerts_60m") or 0)

        events_5m = 0
        last_event_ts = None
        if use_ingest_rollups:
            ev_stmt = select(func.coalesce(func.sum(NetEventRollup1sModel.count), 0)).where(
                NetEventRollup1sModel.bucket_ts >= data_end_ts - timedelta(minutes=5),
                NetEventRollup1sModel.bucket_ts <= data_end_ts,
            )
            if agent_id:
                ev_stmt = ev_stmt.where(NetEventRollup1sModel.agent_id == agent_id)
            events_5m = int(db.execute(ev_stmt).scalar() or 0)
            last_event_ts = data_end_ts if last_roll_ts is not None else None
        else:
            ev_stmt2 = select(func.count(), func.max(NetEventModel.timestamp)).where(True)
            if agent_id:
                ev_stmt2 = ev_stmt2.where(NetEventModel.agent_id == agent_id)
            ev_row = db.execute(ev_stmt2).one()
            last_event_ts = _to_utc(ev_row[1])

            ev_5m_stmt = select(func.count()).select_from(NetEventModel).where(NetEventModel.timestamp >= now - timedelta(minutes=5))
            if agent_id:
                ev_5m_stmt = ev_5m_stmt.where(NetEventModel.agent_id == agent_id)
            events_5m = int(db.execute(ev_5m_stmt).scalar() or 0)

        last_event_age_m = None
        if last_event_ts is not None:
            try:
                last_event_age_m = int(((now - last_event_ts).total_seconds()) // 60)
            except Exception:
                last_event_age_m = None

        kpis = {
            "total_agents": total_agents,
            "online_agents": online_agents,
            "events_5m": int(events_5m),
            "alerts_60m": alerts_60m,
            "last_event_age_m": last_event_age_m,
        }

        if use_ingest_rollups:
            top_stmt = (
                select(NetEventRollup1sModel.event_type, func.sum(NetEventRollup1sModel.count).label("total"))
                .where(
                    NetEventRollup1sModel.bucket_ts >= start_ts,
                    NetEventRollup1sModel.bucket_ts <= data_end_ts,
                    _event_type_filter(NetEventRollup1sModel.event_type),
                )
                .group_by(NetEventRollup1sModel.event_type)
                .order_by(func.sum(NetEventRollup1sModel.count).desc())
                .limit(3)
            )
            if agent_id:
                top_stmt = top_stmt.where(NetEventRollup1sModel.agent_id == agent_id)
            top_rows = db.execute(top_stmt).all()
            top_types = [str(r.event_type) for r in top_rows if r.event_type]
        else:
            top_types = _top_event_types(db, start_ts, data_end_ts, agent_id)

        while len(top_types) < 3:
            top_types.append(None)
        t1, t2, t3 = top_types[0], top_types[1], top_types[2]

        if use_ingest_rollups:
            traffic_stmt = (
                select(
                    func.date_trunc("minute", NetEventRollup1sModel.bucket_ts).label("bucket_ts"),
                    NetEventRollup1sModel.event_type.label("event_type"),
                    func.sum(NetEventRollup1sModel.count).label("cnt"),
                )
                .where(
                    NetEventRollup1sModel.bucket_ts >= start_ts,
                    NetEventRollup1sModel.bucket_ts <= data_end_ts,
                    _event_type_filter(NetEventRollup1sModel.event_type),
                )
                .group_by("bucket_ts", NetEventRollup1sModel.event_type)
            )
            if agent_id:
                traffic_stmt = traffic_stmt.where(NetEventRollup1sModel.agent_id == agent_id)
        else:
            traffic_stmt = (
                select(
                    func.date_trunc("minute", EventRollup1mModel.bucket_ts).label("bucket_ts"),
                    EventRollup1mModel.event_type.label("event_type"),
                    func.sum(EventRollup1mModel.count).label("cnt"),
                )
                .where(
                    EventRollup1mModel.bucket_ts >= start_ts,
                    EventRollup1mModel.bucket_ts <= data_end_ts,
                    _event_type_filter(EventRollup1mModel.event_type),
                )
                .group_by("bucket_ts", EventRollup1mModel.event_type)
            )
            if agent_id:
                traffic_stmt = traffic_stmt.where(EventRollup1mModel.agent_id == agent_id)

        traffic_rows = db.execute(traffic_stmt).all()
        traffic_map: Dict[datetime, Dict[str, int]] = {}
        for r in traffic_rows:
            b = _to_utc(r.bucket_ts)
            if b is None:
                continue
            event_type = str(r.event_type)
            bucket_vals = traffic_map.setdefault(b, {})
            bucket_vals[event_type] = bucket_vals.get(event_type, 0) + int(r.cnt or 0)

        traffic_series = [x for x in [t1, t2, t3] if x] + ["other"]
        traffic_data: List[Dict[str, Any]] = []
        for b in _minute_buckets(start_ts, data_end_ts):
            vals = traffic_map.get(b, {})
            row: Dict[str, Any] = {"t": _fmt_hhmm(b)}
            known = 0
            for t in [t1, t2, t3]:
                if t:
                    v = int(vals.get(t, 0))
                    row[t] = v
                    known += v
            row["other"] = max(0, int(sum(vals.values()) - known))
            traffic_data.append(row)

        ssh_stmt = (
            select(
                func.date_trunc("minute", SshFailRollup1mModel.bucket_ts).label("bucket_ts"),
                func.sum(SshFailRollup1mModel.count).label("failures"),
            )
            .where(
                SshFailRollup1mModel.bucket_ts >= start_ts,
                SshFailRollup1mModel.bucket_ts <= data_end_ts,
                SshFailRollup1mModel.action != "accepted",
            )
            .group_by("bucket_ts")
        )
        if agent_id:
            ssh_stmt = ssh_stmt.where(SshFailRollup1mModel.agent_id == agent_id)
        ssh_rows = db.execute(ssh_stmt).all()
        ssh_map = {_to_utc(r.bucket_ts): int(r.failures or 0) for r in ssh_rows if _to_utc(r.bucket_ts) is not None}
        ssh_data = [{"t": _fmt_hhmm(b), "failures": int(ssh_map.get(b, 0))} for b in _minute_buckets(start_ts, data_end_ts)]
        ssh_series = ["failures"]

        sev_stmt = (
            select(
                func.date_trunc("minute", AlertModel.created_at).label("bucket_ts"),
                func.lower(func.coalesce(AlertModel.severity, "unknown")).label("sev"),
                func.count().label("cnt"),
            )
            .where(AlertModel.created_at >= start_ts, AlertModel.created_at <= data_end_ts)
            .group_by("bucket_ts", "sev")
        )
        sev_rows = db.execute(sev_stmt).all()
        sev_map: Dict[datetime, Dict[str, int]] = {}
        for r in sev_rows:
            b = _to_utc(r.bucket_ts)
            if b is None:
                continue
            sev = str(r.sev or "unknown")
            sev_map.setdefault(b, {})[sev] = int(r.cnt or 0)

        sev_series = ["critical", "high", "medium", "low", "unknown"]
        sev_data: List[Dict[str, Any]] = []
        for b in _minute_buckets(start_ts, data_end_ts):
            vals = sev_map.get(b, {})
            row = {
                "t": _fmt_hhmm(b),
                "critical": int(vals.get("critical", 0)),
                "high": int(vals.get("high", 0)),
                "medium": int(vals.get("medium", 0)),
                "low": int(vals.get("low", 0)),
            }
            known = row["critical"] + row["high"] + row["medium"] + row["low"]
            row["unknown"] = max(0, int(sum(vals.values()) - known))
            sev_data.append(row)

        ddos_stmt = (
            select(
                func.date_trunc("minute", AlertModel.created_at).label("bucket_ts"),
                func.lower(AlertModel.severity).label("sev"),
                func.count().label("cnt"),
            )
            .where(
                AlertModel.created_at >= start_ts,
                AlertModel.created_at <= data_end_ts,
                func.lower(AlertModel.severity).in_(["critical", "high"]),
                _ddos_rule_filter(AlertModel.rule_id),
            )
            .group_by("bucket_ts", "sev")
        )
        ddos_rows = db.execute(ddos_stmt).all()
        ddos_map: Dict[datetime, Dict[str, int]] = {}
        for r in ddos_rows:
            b = _to_utc(r.bucket_ts)
            if b is None:
                continue
            ddos_map.setdefault(b, {})[str(r.sev)] = int(r.cnt or 0)

        ddos_series = ["critical", "high"]
        ddos_data = [
            {
                "t": _fmt_hhmm(b),
                "critical": int((ddos_map.get(b) or {}).get("critical", 0)),
                "high": int((ddos_map.get(b) or {}).get("high", 0)),
            }
            for b in _minute_buckets(start_ts, data_end_ts)
        ]

        packets_txt = NetEventModel.extra["packets"].astext
        pps_txt = NetEventModel.extra["pps"].astext
        packet_num = case((packets_txt.op("~")(r"^[0-9]+(\\.[0-9]+)?$"), cast(packets_txt, Float)), else_=0.0)
        pps_num = case((pps_txt.op("~")(r"^[0-9]+(\\.[0-9]+)?$"), cast(pps_txt, Float)), else_=0.0)

        ddos_vol_stmt = (
            select(
                func.date_trunc("minute", NetEventModel.timestamp).label("bucket_ts"),
                func.coalesce(func.sum(packet_num), 0.0).label("packets"),
                func.coalesce(func.max(pps_num), 0.0).label("peak_pps"),
            )
            .where(
                NetEventModel.timestamp >= start_ts,
                NetEventModel.timestamp <= data_end_ts,
                NetEventModel.event_type == "dos_attack",
            )
            .group_by("bucket_ts")
        )
        if agent_id:
            ddos_vol_stmt = ddos_vol_stmt.where(NetEventModel.agent_id == agent_id)
        ddos_vol_rows = db.execute(ddos_vol_stmt).all()
        ddos_vol_map = {
            _to_utc(r.bucket_ts): {"packets": float(r.packets or 0), "peak_pps": float(r.peak_pps or 0)}
            for r in ddos_vol_rows
            if _to_utc(r.bucket_ts) is not None
        }

        ddos_volume_series = ["packets", "peak_pps"]
        ddos_volume_data = []
        for b in _minute_buckets(start_ts, data_end_ts):
            vals = ddos_vol_map.get(b, {"packets": 0.0, "peak_pps": 0.0})
            ddos_volume_data.append(
                {
                    "t": _fmt_hhmm(b),
                    "packets": int(vals.get("packets", 0.0)),
                    "peak_pps": float(vals.get("peak_pps", 0.0)),
                }
            )

        ports: List[Dict[str, Any]] = []
        top_sources: List[Dict[str, Any]] = []
        recent_alerts: List[Dict[str, Any]] = []
        ddos_alerts: List[Dict[str, Any]] = []
        recent_ssh: List[Dict[str, Any]] = []
        raw_events: List[Dict[str, Any]] = []

        if not lite:
            if use_ingest_rollups:
                ports_stmt = (
                    select(NetEventRollup1sModel.dst_port.label("port"), func.sum(NetEventRollup1sModel.count).label("count"))
                    .where(
                        NetEventRollup1sModel.bucket_ts >= start_ts,
                        NetEventRollup1sModel.bucket_ts <= data_end_ts,
                        NetEventRollup1sModel.dst_port.is_not(None),
                    )
                    .group_by(NetEventRollup1sModel.dst_port)
                    .order_by(func.sum(NetEventRollup1sModel.count).desc())
                    .limit(10)
                )
                if agent_id:
                    ports_stmt = ports_stmt.where(NetEventRollup1sModel.agent_id == agent_id)
            else:
                ports_stmt = (
                    select(NetEventModel.dst_port.label("port"), func.count().label("count"))
                    .where(
                        NetEventModel.timestamp >= start_ts,
                        NetEventModel.timestamp <= data_end_ts,
                        NetEventModel.dst_port.is_not(None),
                    )
                    .group_by(NetEventModel.dst_port)
                    .order_by(func.count().desc())
                    .limit(10)
                )
                if agent_id:
                    ports_stmt = ports_stmt.where(NetEventModel.agent_id == agent_id)
            ports_rows = db.execute(ports_stmt).all()
            ports = [{"port": int(r.port), "count": int(r.count or 0)} for r in ports_rows if r.port is not None]

            src_stmt = (
                select(NetEventModel.src_ip, func.count().label("count"))
                .where(
                    NetEventModel.timestamp >= start_ts,
                    NetEventModel.timestamp <= data_end_ts,
                    NetEventModel.src_ip.is_not(None),
                )
                .group_by(NetEventModel.src_ip)
                .order_by(func.count().desc())
                .limit(10)
            )
            if agent_id:
                src_stmt = src_stmt.where(NetEventModel.agent_id == agent_id)
            src_rows = db.execute(src_stmt).all()
            top_sources = [{"src_ip": str(r.src_ip), "count": int(r.count or 0)} for r in src_rows if r.src_ip]

            recent_alerts_stmt = (
                select(
                    AlertModel.id,
                    AlertModel.created_at,
                    AlertModel.rule_id,
                    AlertModel.severity,
                    AlertModel.src_ip,
                    AlertModel.dst_ip,
                    AlertModel.dst_port,
                    AlertModel.description,
                    AlertModel.details,
                )
                .order_by(AlertModel.created_at.desc())
                .limit(25)
            )
            recent_alerts = [dict(r) for r in db.execute(recent_alerts_stmt).mappings().all()]

            ddos_alerts_stmt = (
                select(
                    AlertModel.id,
                    AlertModel.created_at,
                    AlertModel.rule_id,
                    AlertModel.severity,
                    AlertModel.src_ip,
                    AlertModel.dst_ip,
                    AlertModel.dst_port,
                    AlertModel.description,
                    AlertModel.details,
                )
                .where(func.lower(AlertModel.severity).in_(["critical", "high"]), _ddos_rule_filter(AlertModel.rule_id))
                .order_by(AlertModel.created_at.desc())
                .limit(15)
            )
            ddos_alerts = [dict(r) for r in db.execute(ddos_alerts_stmt).mappings().all()]

            ssh_stream_stmt = (
                select(NetEventModel.timestamp.label("ts"), NetEventModel.id, NetEventModel.src_ip, NetEventModel.dst_ip, NetEventModel.extra)
                .where(NetEventModel.event_type == "ssh_auth")
                .order_by(NetEventModel.timestamp.desc(), NetEventModel.id.desc())
                .limit(20)
            )
            if agent_id:
                ssh_stream_stmt = ssh_stream_stmt.where(NetEventModel.agent_id == agent_id)
            ssh_stream_rows = db.execute(ssh_stream_stmt).mappings().all()
            for r in ssh_stream_rows:
                extra = r.get("extra") or {}
                recent_ssh.append(
                    {
                        "ts": _fmt_hhmm(_to_utc(r.get("ts")) or now),
                        "src": str(r.get("src_ip") or "-"),
                        "dst": str(r.get("dst_ip") or "-"),
                        "user": str((extra or {}).get("username") or "-"),
                        "action": str((extra or {}).get("action") or "-"),
                    }
                )

            if use_ingest_rollups:
                raw_events = _warm_recent_events(agent_id=agent_id, start_ts=start_ts, end_ts=data_end_ts, limit=30)
                if not raw_events:
                    hot_fallback_stmt = (
                        select(
                            NetEventModel.id,
                            NetEventModel.timestamp,
                            NetEventModel.agent_id,
                            NetEventModel.event_type,
                            NetEventModel.src_ip,
                            NetEventModel.dst_ip,
                            NetEventModel.dst_port,
                        )
                        .order_by(NetEventModel.timestamp.desc(), NetEventModel.id.desc())
                        .limit(30)
                    )
                    if agent_id:
                        hot_fallback_stmt = hot_fallback_stmt.where(NetEventModel.agent_id == agent_id)
                    raw_events = [dict(r) for r in db.execute(hot_fallback_stmt).mappings().all()]
                if not raw_events and last_roll_ts is not None:
                    raw_events = [
                        {
                            "id": 0,
                            "timestamp": last_roll_ts.isoformat(),
                            "agent_id": agent_id or "-",
                            "event_type": "rollup",
                            "src_ip": None,
                            "dst_ip": None,
                            "dst_port": None,
                        }
                    ]
            else:
                raw_stmt = (
                    select(
                        NetEventModel.id,
                        NetEventModel.timestamp,
                        NetEventModel.agent_id,
                        NetEventModel.event_type,
                        NetEventModel.src_ip,
                        NetEventModel.dst_ip,
                        NetEventModel.dst_port,
                    )
                    .order_by(NetEventModel.timestamp.desc(), NetEventModel.id.desc())
                    .limit(30)
                )
                if agent_id:
                    raw_stmt = raw_stmt.where(NetEventModel.agent_id == agent_id)
                raw_events = [dict(r) for r in db.execute(raw_stmt).mappings().all()]

        data_lag_s = int(max(0.0, (now - data_end_ts).total_seconds()))

        payload = {
            "meta": {
                "lite": bool(lite),
                "use_ingest_rollups": bool(use_ingest_rollups),
                "protection_active": bool(protection_active),
                "draining": bool(draining),
                "rollups_fresh": bool(rollups_fresh),
                "rollup_stuck_fallback": bool(rollup_stuck),
                "rollups_last_bucket": (last_roll_ts.isoformat() if last_roll_ts is not None else None),
                "window_start": start_ts.isoformat(),
                "window_end": data_end_ts.isoformat(),
                "data_lag_seconds": data_lag_s,
                "backlog_events": int(backlog_ev),
                "backlog_messages": int(backlog_msgs),
            },
            "kpis": kpis,
            "traffic": {"series": traffic_series, "data": traffic_data},
            "ssh_failures": {"series": ssh_series, "data": ssh_data},
            "alert_severity": {"series": sev_series, "data": sev_data},
            "ddos": {"series": ddos_series, "data": ddos_data},
            "ddos_volume": {"series": ddos_volume_series, "data": ddos_volume_data},
            "ports": ports,
            "top_sources": top_sources,
            "recent_alerts": recent_alerts,
            "ddos_alerts": ddos_alerts,
            "recent_ssh": recent_ssh,
            "raw_events": raw_events,
        }
        _overview_cache_set(cache_key, payload)
        observe_hist("api_route_latency_seconds", time.perf_counter() - started, route="/overview")
        log_event(logger, "info", "overview_response_ready", window_minutes=int(window_minutes), agent_id=agent_id or "", lite=bool(lite), use_ingest_rollups=bool(use_ingest_rollups))
        return payload
    finally:
        db.close()
