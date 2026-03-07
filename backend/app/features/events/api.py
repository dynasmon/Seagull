from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import Integer, String, and_, cast, func, or_, select

from app.core.config import settings
from app.core.db import SessionLocal
from app.core.es import es_is_available, get_es_client, search_backend_mode
from app.core.pagination import make_cursor_ts_id, parse_cursor_ts_id
from app.core.portal_auth import get_current_user
from app.models.events import NetEventModel, NetEventRollup1sModel
from app.schemas.events import (
    NetEventDB,
    NetEventRollup1s,
    ProtocolIntelSummaryResponse,
    ProtoCount,
    ProtoDnsQueryStat,
    ProtoJa4Stat,
    SshIpStat,
    SshLoginEvent,
    SshSummaryResponse,
    SshUserStat,
    SudoEventSummary,
)
from app.schemas.pagination import CursorPage

router = APIRouter(
    prefix="/events",
    tags=["events"],
    dependencies=[Depends(get_current_user)],
)


def _parse_iso_dt(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    s = value.strip()
    try:
        if s.endswith("Z"):
            return datetime.fromisoformat(s[:-1] + "+00:00")
        return datetime.fromisoformat(s)
    except Exception:
        return datetime.now(timezone.utc)


def _es_index_pattern() -> str:
    prefix = (getattr(settings, "NETWATCH_ES_INDEX_PREFIX", "netwatch-events") or "netwatch-events").strip()
    return f"{prefix}-*"


def _es_client_or_none() -> Any | None:
    mode = search_backend_mode()
    if mode == "postgres":
        return None

    if not es_is_available():
        if mode == "elasticsearch":
            raise HTTPException(status_code=503, detail="Elasticsearch unavailable")
        return None

    return get_es_client()


def _es_failover_allowed() -> bool:
    return search_backend_mode() != "elasticsearch"


def _hit_to_event(hit: Dict[str, Any]) -> NetEventDB:
    src = hit.get("_source") or {}

    # Prefer explicit 'id' stored in _source, fallback to _id.
    try:
        row_id = int(src.get("id") or hit.get("_id"))
    except Exception:
        row_id = 0

    ts_raw = src.get("timestamp") or src.get("@timestamp")
    ts = _parse_iso_dt(ts_raw if isinstance(ts_raw, str) else None)

    return NetEventDB(
        id=row_id,
        agent_id=str(src.get("agent_id") or ""),
        event_type=str(src.get("event_type") or ""),
        schema_version=int(src.get("schema_version") or 1),
        timestamp=ts,
        src_ip=src.get("src_ip"),
        dst_ip=src.get("dst_ip"),
        src_port=src.get("src_port"),
        dst_port=src.get("dst_port"),
        proto=src.get("proto"),
        bytes=src.get("bytes"),
        extra=(src.get("extra") or {}) if isinstance(src.get("extra") or {}, dict) else {},
    )


def _es_base_filters(
    *,
    since: datetime | None = None,
    agent_id: str | None = None,
    event_type: str | None = None,
) -> List[Dict[str, Any]]:
    filters: List[Dict[str, Any]] = []

    if since is not None:
        filters.append({"range": {"timestamp": {"gte": since.isoformat()}}})

    if agent_id:
        filters.append({"term": {"agent_id": agent_id}})

    if event_type:
        filters.append({"term": {"event_type": event_type}})

    return filters


@router.get("", response_model=CursorPage[NetEventDB])
def list_events(
    page_size: int = Query(50, ge=1, le=200, description="Page size (max 200)"),
    cursor: Optional[str] = Query(None, description="Opaque cursor from a previous call"),
    agent_id: Optional[str] = Query(None, min_length=1, max_length=64, description="Filter by agent identifier"),
    event_type: Optional[str] = Query(None, min_length=1, max_length=32, description="Filter by event type"),
):
    """Cursor-paginated event timeline.

    Returns the most recent events first (DESC). To fetch the next page, pass the
    `next_cursor` from the previous response.

    This endpoint is the recommended replacement for `/events/recent` when you
    want an infinite-scroll / paginated UI.
    """

    es = _es_client_or_none()
    if es is not None:
        try:
            body: Dict[str, Any] = {
                "size": int(page_size) + 1,
                "sort": [
                    {"timestamp": {"order": "desc"}},
                    {"id": {"order": "desc"}},
                ],
                "query": {
                    "bool": {
                        "filter": _es_base_filters(agent_id=agent_id, event_type=event_type),
                    }
                },
            }

            if cursor:
                c_ts, c_id = parse_cursor_ts_id(cursor)
                # search_after values correspond to the 'sort' array.
                body["search_after"] = [c_ts.isoformat(), int(c_id)]

            res = es.search(
                index=_es_index_pattern(),
                body=body,
                ignore_unavailable=True,
                allow_no_indices=True,
                track_total_hits=False,
            )

            hits = (res.get("hits") or {}).get("hits") or []
            has_more = len(hits) > int(page_size)
            page_hits = hits[: int(page_size)]

            items = [_hit_to_event(h) for h in page_hits]

            next_cursor = None
            if has_more and page_hits:
                last_evt = items[-1]
                next_cursor = make_cursor_ts_id(last_evt.timestamp, last_evt.id)

            return CursorPage(items=items, next_cursor=next_cursor, has_more=has_more)
        except Exception as e:
            if not _es_failover_allowed():
                raise HTTPException(status_code=503, detail=f"Elasticsearch error: {type(e).__name__}")
            # Fallback to Postgres.

    db = SessionLocal()
    try:
        stmt = select(NetEventModel).order_by(NetEventModel.timestamp.desc(), NetEventModel.id.desc())

        if agent_id:
            stmt = stmt.where(NetEventModel.agent_id == agent_id)
        if event_type:
            stmt = stmt.where(NetEventModel.event_type == event_type)

        if cursor:
            c_ts, c_id = parse_cursor_ts_id(cursor)
            # Keyset pagination for DESC order.
            stmt = stmt.where(
                or_(
                    NetEventModel.timestamp < c_ts,
                    and_(NetEventModel.timestamp == c_ts, NetEventModel.id < c_id),
                )
            )

        rows = db.execute(stmt.limit(int(page_size) + 1)).scalars().all()

        has_more = len(rows) > int(page_size)
        items = rows[: int(page_size)]

        next_cursor = None
        if has_more and items:
            last = items[-1]
            next_cursor = make_cursor_ts_id(last.timestamp, last.id)

        return CursorPage(items=items, next_cursor=next_cursor, has_more=has_more)
    finally:
        db.close()


@router.get("/recent", response_model=List[NetEventDB])
def get_recent_events(
    limit: int = Query(50, ge=1, le=1000, description="Maximum number of events to return"),
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
):
    es = _es_client_or_none()
    if es is not None:
        try:
            body: Dict[str, Any] = {
                "size": int(limit),
                "sort": [
                    {"timestamp": {"order": "desc"}},
                    {"id": {"order": "desc"}},
                ],
                "query": {
                    "bool": {
                        "filter": _es_base_filters(agent_id=agent_id, event_type=event_type),
                    }
                },
            }

            res = es.search(
                index=_es_index_pattern(),
                body=body,
                ignore_unavailable=True,
                allow_no_indices=True,
                track_total_hits=False,
            )
            hits = (res.get("hits") or {}).get("hits") or []
            return [_hit_to_event(h) for h in hits]
        except Exception as e:
            if not _es_failover_allowed():
                raise HTTPException(status_code=503, detail=f"Elasticsearch error: {type(e).__name__}")

    # Postgres fallback
    db = SessionLocal()
    try:
        # Deterministic ordering avoids flicker when many events share the same timestamp.
        stmt = select(NetEventModel).order_by(NetEventModel.timestamp.desc(), NetEventModel.id.desc())
        if agent_id:
            stmt = stmt.where(NetEventModel.agent_id == agent_id)
        if event_type:
            stmt = stmt.where(NetEventModel.event_type == event_type)
        stmt = stmt.limit(int(limit))

        result = db.execute(stmt)
        return result.scalars().all()
    finally:
        db.close()


@router.get("/rollups/1s", response_model=List[NetEventRollup1s])
def list_rollups_1s(
    minutes: int = Query(60, ge=1, le=24 * 60, description="Lookback window in minutes"),
    limit: int = Query(500, ge=1, le=5000, description="Max buckets to return"),
    agent_id: Optional[str] = Query(None, min_length=1, max_length=64),
    event_type: Optional[str] = Query(None, min_length=1, max_length=32),
    dst_ip: Optional[str] = Query(None, min_length=1, max_length=45),
    dst_port: Optional[int] = Query(None, ge=0, le=65535),
):
    """1-second rollups for high-rate telemetry.

    This is especially useful during volumetric attacks when raw events may be sampled.
    """

    since = datetime.now(timezone.utc) - timedelta(minutes=int(minutes))

    db = SessionLocal()
    try:
        stmt = (
            select(
                NetEventRollup1sModel.bucket_ts,
                NetEventRollup1sModel.agent_id,
                NetEventRollup1sModel.event_type,
                NetEventRollup1sModel.dst_ip,
                NetEventRollup1sModel.dst_port,
                NetEventRollup1sModel.proto,
                NetEventRollup1sModel.count,
                NetEventRollup1sModel.bytes_sum,
            )
            .where(NetEventRollup1sModel.bucket_ts >= since)
            .order_by(NetEventRollup1sModel.bucket_ts.desc())
            .limit(int(limit))
        )
        if agent_id:
            stmt = stmt.where(NetEventRollup1sModel.agent_id == agent_id)
        if event_type:
            stmt = stmt.where(NetEventRollup1sModel.event_type == event_type)
        if dst_ip:
            stmt = stmt.where(NetEventRollup1sModel.dst_ip == dst_ip)
        if dst_port is not None:
            stmt = stmt.where(NetEventRollup1sModel.dst_port == dst_port)
        rows = db.execute(stmt).mappings().all()

        return [NetEventRollup1s(**dict(r)) for r in rows]
    finally:
        db.close()


@router.get("/stats/ports")
def get_port_stats(
    limit: int = Query(20, ge=1, le=200, description="Maximum number of ports to return"),
):
    es = _es_client_or_none()
    if es is not None:
        try:
            body = {
                "size": 0,
                "query": {"bool": {"filter": [{"exists": {"field": "dst_port"}}]}},
                "aggs": {
                    "ports": {
                        "terms": {
                            "field": "dst_port",
                            "size": int(limit),
                            "order": {"_count": "desc"},
                        }
                    }
                },
            }
            res = es.search(
                index=_es_index_pattern(),
                body=body,
                ignore_unavailable=True,
                allow_no_indices=True,
                track_total_hits=False,
            )
            buckets = ((res.get("aggregations") or {}).get("ports") or {}).get("buckets") or []
            return [{"port": b.get("key"), "count": b.get("doc_count", 0)} for b in buckets]
        except Exception as e:
            if not _es_failover_allowed():
                raise HTTPException(status_code=503, detail=f"Elasticsearch error: {type(e).__name__}")

    # Postgres fallback
    db = SessionLocal()
    try:
        stmt = (
            select(
                NetEventModel.dst_port.label("port"),
                func.count().label("count"),
            )
            .where(NetEventModel.dst_port.is_not(None))
            .group_by(NetEventModel.dst_port)
            .order_by(func.count().desc())
            .limit(int(limit))
        )

        rows = db.execute(stmt).all()
        return [{"port": row.port, "count": row.count} for row in rows]
    finally:
        db.close()


def _es_terms_top(
    es,
    *,
    field: str,
    size: int,
    base_filters: List[Dict[str, Any]],
) -> List[ProtoCount]:
    body = {
        "size": 0,
        "query": {"bool": {"filter": base_filters}},
        "aggs": {"top": {"terms": {"field": field, "size": int(size), "order": {"_count": "desc"}}}},
    }
    res = es.search(index=_es_index_pattern(), body=body, ignore_unavailable=True, allow_no_indices=True)
    buckets = ((res.get("aggregations") or {}).get("top") or {}).get("buckets") or []
    out: List[ProtoCount] = []
    for b in buckets:
        k = b.get("key")
        if k is None:
            continue
        out.append(ProtoCount(key=str(k), count=int(b.get("doc_count", 0) or 0)))
    return out


@router.get("/ssh/summary", response_model=SshSummaryResponse)
def get_ssh_summary(
    since_minutes: int = Query(60 * 24, ge=1, le=60 * 24 * 30, description="Lookback window in minutes"),
    limit: int = Query(20, ge=1, le=200, description="Top-N limit for aggregations"),
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
):
    """Lupe-style SSH summary.

    Mirrors the original bash script output, but returns structured JSON.
    Works best when the lupe_enricher worker is enabled (geo/asn fields).
    """

    since_ts = datetime.now(timezone.utc) - timedelta(minutes=int(since_minutes))

    es = _es_client_or_none()
    if es is not None:
        try:
            base = _es_base_filters(since=since_ts, agent_id=agent_id)

            def _top_ips(action: str) -> list[SshIpStat]:
                body = {
                    "size": 0,
                    "query": {
                        "bool": {
                            "filter": base
                            + [
                                {"term": {"event_type": "ssh_auth"}},
                                {"term": {"ssh_action": action}},
                                {"exists": {"field": "src_ip"}},
                            ]
                        }
                    },
                    "aggs": {
                        "ips": {
                            "terms": {"field": "src_ip", "size": int(limit), "order": {"_count": "desc"}},
                            "aggs": {
                                "sample": {
                                    "top_hits": {
                                        "size": 1,
                                        "_source": {
                                            "includes": [
                                                "geo_country",
                                                "geo_org",
                                                "asn",
                                                "asn_org",
                                            ]
                                        },
                                        "sort": [{"timestamp": {"order": "desc"}}],
                                    }
                                }
                            },
                        }
                    },
                }
                res = es.search(index=_es_index_pattern(), body=body, ignore_unavailable=True, allow_no_indices=True)
                buckets = ((res.get("aggregations") or {}).get("ips") or {}).get("buckets") or []
                out: list[SshIpStat] = []
                for b in buckets:
                    sample_hits = (((b.get("sample") or {}).get("hits") or {}).get("hits") or [])
                    sample_src = (sample_hits[0].get("_source") if sample_hits else {}) or {}
                    out.append(
                        SshIpStat(
                            src_ip=str(b.get("key")),
                            count=int(b.get("doc_count", 0) or 0),
                            geo_country=sample_src.get("geo_country"),
                            geo_org=sample_src.get("geo_org"),
                            asn=sample_src.get("asn"),
                            asn_org=sample_src.get("asn_org"),
                        )
                    )
                return out

            successful_logins = _top_ips("accepted")
            failed_attempts = _top_ips("failed_password")
            invalid_user_attempts = _top_ips("invalid_user")

            # Most active IPs across the main SSH actions
            body = {
                "size": 0,
                "query": {
                    "bool": {
                        "filter": base
                        + [
                            {"term": {"event_type": "ssh_auth"}},
                            {"terms": {"ssh_action": ["accepted", "failed_password", "invalid_user"]}},
                            {"exists": {"field": "src_ip"}},
                        ]
                    }
                },
                "aggs": {
                    "ips": {
                        "terms": {"field": "src_ip", "size": int(limit), "order": {"_count": "desc"}},
                        "aggs": {
                            "sample": {
                                "top_hits": {
                                    "size": 1,
                                    "_source": {
                                        "includes": [
                                            "geo_country",
                                            "geo_org",
                                            "asn",
                                            "asn_org",
                                        ]
                                    },
                                    "sort": [{"timestamp": {"order": "desc"}}],
                                }
                            }
                        },
                    }
                },
            }
            res = es.search(index=_es_index_pattern(), body=body, ignore_unavailable=True, allow_no_indices=True)
            buckets = ((res.get("aggregations") or {}).get("ips") or {}).get("buckets") or []
            most_active_ips: list[SshIpStat] = []
            for b in buckets:
                sample_hits = (((b.get("sample") or {}).get("hits") or {}).get("hits") or [])
                sample_src = (sample_hits[0].get("_source") if sample_hits else {}) or {}
                most_active_ips.append(
                    SshIpStat(
                        src_ip=str(b.get("key")),
                        count=int(b.get("doc_count", 0) or 0),
                        geo_country=sample_src.get("geo_country"),
                        geo_org=sample_src.get("geo_org"),
                        asn=sample_src.get("asn"),
                        asn_org=sample_src.get("asn_org"),
                    )
                )

            # Root logins
            body = {
                "size": int(limit),
                "sort": [{"timestamp": {"order": "desc"}}, {"id": {"order": "desc"}}],
                "query": {
                    "bool": {
                        "filter": base
                        + [
                            {"term": {"event_type": "ssh_auth"}},
                            {"term": {"ssh_action": "accepted"}},
                            {"term": {"ssh_username": "root"}},
                        ]
                    }
                },
                "_source": {"includes": ["timestamp", "agent_id", "src_ip", "ssh_username", "geo_country", "geo_org", "asn", "asn_org"]},
            }
            res = es.search(index=_es_index_pattern(), body=body, ignore_unavailable=True, allow_no_indices=True)
            root_logins: list[SshLoginEvent] = []
            for h in ((res.get("hits") or {}).get("hits") or []):
                src = h.get("_source") or {}
                root_logins.append(
                    SshLoginEvent(
                        timestamp=_parse_iso_dt(src.get("timestamp") if isinstance(src.get("timestamp"), str) else None),
                        agent_id=str(src.get("agent_id") or ""),
                        src_ip=src.get("src_ip"),
                        username=src.get("ssh_username") or "root",
                        geo_country=src.get("geo_country"),
                        geo_org=src.get("geo_org"),
                        asn=src.get("asn"),
                        asn_org=src.get("asn_org"),
                    )
                )

            # Users that attempted to log in (failed/invalid)
            body = {
                "size": 0,
                "query": {
                    "bool": {
                        "filter": base
                        + [
                            {"term": {"event_type": "ssh_auth"}},
                            {"terms": {"ssh_action": ["failed_password", "invalid_user"]}},
                            {"exists": {"field": "ssh_username"}},
                        ]
                    }
                },
                "aggs": {
                    "users": {
                        "terms": {"field": "ssh_username", "size": int(limit), "order": {"_count": "desc"}}
                    }
                },
            }
            res = es.search(index=_es_index_pattern(), body=body, ignore_unavailable=True, allow_no_indices=True)
            buckets = ((res.get("aggregations") or {}).get("users") or {}).get("buckets") or []
            users_attempted = [SshUserStat(username=str(b.get("key")), count=int(b.get("doc_count", 0) or 0)) for b in buckets]

            # Recent sudo commands (from auth.log)
            body = {
                "size": int(limit),
                "sort": [{"timestamp": {"order": "desc"}}, {"id": {"order": "desc"}}],
                "query": {
                    "bool": {
                        "filter": base + [{"term": {"event_type": "sudo_cmd"}}]
                    }
                },
                "_source": {
                    "includes": [
                        "timestamp",
                        "agent_id",
                        "sudo_username",
                        "sudo_target_user",
                        "sudo_command",
                        "sudo_tty",
                        "sudo_pwd",
                    ]
                },
            }
            res = es.search(index=_es_index_pattern(), body=body, ignore_unavailable=True, allow_no_indices=True)
            sudo_recent: list[SudoEventSummary] = []
            for h in ((res.get("hits") or {}).get("hits") or []):
                src = h.get("_source") or {}
                sudo_recent.append(
                    SudoEventSummary(
                        timestamp=_parse_iso_dt(src.get("timestamp") if isinstance(src.get("timestamp"), str) else None),
                        agent_id=str(src.get("agent_id") or ""),
                        username=src.get("sudo_username"),
                        target_user=src.get("sudo_target_user"),
                        command=src.get("sudo_command"),
                        tty=src.get("sudo_tty"),
                        pwd=src.get("sudo_pwd"),
                    )
                )

            return SshSummaryResponse(
                generated_at=datetime.now(timezone.utc),
                since_minutes=int(since_minutes),
                agent_id=agent_id,
                successful_logins=successful_logins,
                failed_attempts=failed_attempts,
                invalid_user_attempts=invalid_user_attempts,
                most_active_ips=most_active_ips,
                root_logins=root_logins,
                users_attempted=users_attempted,
                sudo_recent=sudo_recent,
            )
        except Exception as e:
            if not _es_failover_allowed():
                raise HTTPException(status_code=503, detail=f"Elasticsearch error: {type(e).__name__}")

    # Postgres fallback (original implementation)
    db = SessionLocal()
    try:
        def _top_ips(action: str) -> list[SshIpStat]:
            stmt = (
                select(
                    NetEventModel.src_ip.label("src_ip"),
                    func.count().label("count"),
                    func.max(NetEventModel.extra["geo_country"].astext).label("geo_country"),
                    func.max(NetEventModel.extra["geo_org"].astext).label("geo_org"),
                    func.max(NetEventModel.extra["asn"].astext).label("asn"),
                    func.max(NetEventModel.extra["asn_org"].astext).label("asn_org"),
                )
                .where(
                    NetEventModel.event_type == "ssh_auth",
                    NetEventModel.extra["action"].astext == action,
                    NetEventModel.timestamp >= since_ts,
                    NetEventModel.src_ip.is_not(None),
                )
                .group_by(NetEventModel.src_ip)
                .order_by(func.count().desc())
                .limit(int(limit))
            )
            if agent_id:
                stmt = stmt.where(NetEventModel.agent_id == agent_id)
            rows = db.execute(stmt).mappings().all()
            return [SshIpStat(**dict(r)) for r in rows]

        successful_logins = _top_ips("accepted")
        failed_attempts = _top_ips("failed_password")
        invalid_user_attempts = _top_ips("invalid_user")

        # Most active IPs across the main SSH actions
        stmt = (
            select(
                NetEventModel.src_ip.label("src_ip"),
                func.count().label("count"),
                func.max(NetEventModel.extra["geo_country"].astext).label("geo_country"),
                func.max(NetEventModel.extra["geo_org"].astext).label("geo_org"),
                func.max(NetEventModel.extra["asn"].astext).label("asn"),
                func.max(NetEventModel.extra["asn_org"].astext).label("asn_org"),
            )
            .where(
                NetEventModel.event_type == "ssh_auth",
                NetEventModel.extra["action"].astext.in_(["accepted", "failed_password", "invalid_user"]),
                NetEventModel.timestamp >= since_ts,
                NetEventModel.src_ip.is_not(None),
            )
            .group_by(NetEventModel.src_ip)
            .order_by(func.count().desc())
            .limit(int(limit))
        )
        if agent_id:
            stmt = stmt.where(NetEventModel.agent_id == agent_id)
        rows = db.execute(stmt).mappings().all()
        most_active_ips = [SshIpStat(**dict(r)) for r in rows]

        # Root logins
        stmt = (
            select(
                NetEventModel.timestamp.label("timestamp"),
                NetEventModel.agent_id.label("agent_id"),
                NetEventModel.src_ip.label("src_ip"),
                NetEventModel.extra["username"].astext.label("username"),
                NetEventModel.extra["geo_country"].astext.label("geo_country"),
                NetEventModel.extra["geo_org"].astext.label("geo_org"),
                NetEventModel.extra["asn"].astext.label("asn"),
                NetEventModel.extra["asn_org"].astext.label("asn_org"),
            )
            .where(
                NetEventModel.event_type == "ssh_auth",
                NetEventModel.extra["action"].astext == "accepted",
                NetEventModel.extra["username"].astext == "root",
                NetEventModel.timestamp >= since_ts,
            )
            .order_by(NetEventModel.timestamp.desc())
            .limit(int(limit))
        )
        if agent_id:
            stmt = stmt.where(NetEventModel.agent_id == agent_id)
        rows = db.execute(stmt).mappings().all()
        root_logins = [SshLoginEvent(**dict(r)) for r in rows]

        # Users that attempted to log in (failed/invalid)
        stmt = (
            select(
                NetEventModel.extra["username"].astext.label("username"),
                func.count().label("count"),
            )
            .where(
                NetEventModel.event_type == "ssh_auth",
                NetEventModel.extra["action"].astext.in_(["failed_password", "invalid_user"]),
                NetEventModel.timestamp >= since_ts,
                NetEventModel.extra.has_key("username"),
            )
            .group_by(NetEventModel.extra["username"].astext)
            .order_by(func.count().desc())
            .limit(int(limit))
        )
        if agent_id:
            stmt = stmt.where(NetEventModel.agent_id == agent_id)
        rows = db.execute(stmt).mappings().all()
        users_attempted = [SshUserStat(**dict(r)) for r in rows]

        # Recent sudo commands (from auth.log)
        stmt = (
            select(
                NetEventModel.timestamp.label("timestamp"),
                NetEventModel.agent_id.label("agent_id"),
                NetEventModel.extra["username"].astext.label("username"),
                NetEventModel.extra["target_user"].astext.label("target_user"),
                NetEventModel.extra["command"].astext.label("command"),
                NetEventModel.extra["tty"].astext.label("tty"),
                NetEventModel.extra["pwd"].astext.label("pwd"),
            )
            .where(
                NetEventModel.event_type == "sudo_cmd",
                NetEventModel.timestamp >= since_ts,
            )
            .order_by(NetEventModel.timestamp.desc())
            .limit(int(limit))
        )
        if agent_id:
            stmt = stmt.where(NetEventModel.agent_id == agent_id)
        rows = db.execute(stmt).mappings().all()
        sudo_recent = [SudoEventSummary(**dict(r)) for r in rows]

        return SshSummaryResponse(
            generated_at=datetime.now(timezone.utc),
            since_minutes=int(since_minutes),
            agent_id=agent_id,
            successful_logins=successful_logins,
            failed_attempts=failed_attempts,
            invalid_user_attempts=invalid_user_attempts,
            most_active_ips=most_active_ips,
            root_logins=root_logins,
            users_attempted=users_attempted,
            sudo_recent=sudo_recent,
        )
    finally:
        db.close()


def _strip_large_extra(extra: dict) -> dict:
    """Remove large payload fields before returning samples to the UI."""

    if not isinstance(extra, dict):
        return {}
    out = dict(extra)
    for k in ["payload_b64", "l7_payload_b64", "raw_payload_b64", "packet_b64", "pcap_b64"]:
        if k in out:
            out.pop(k, None)
    return out


@router.get("/network/summary", response_model=ProtocolIntelSummaryResponse)
def get_protocol_intel_summary(
    since_minutes: int = Query(60 * 12, ge=1, le=60 * 24 * 30, description="Lookback window in minutes"),
    limit: int = Query(25, ge=1, le=200, description="Top-N limit for aggregations"),
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
):
    """Protocol Intelligence summary.

    Aggregates protocol-aware metadata produced by the protocol_intel worker.

    Note: when Elasticsearch is available, this endpoint uses ES aggregations
    to reduce load on Postgres.
    """

    since_ts = datetime.now(timezone.utc) - timedelta(minutes=int(since_minutes))

    es = _es_client_or_none()
    if es is not None:
        try:
            base = _es_base_filters(since=since_ts, agent_id=agent_id)

            # Single query with filter aggs + terms aggs (efficient on ES).
            body: Dict[str, Any] = {
                "size": 0,
                "query": {"bool": {"filter": base}},
                "aggs": {
                    "with_proto_metadata": {
                        "filter": {
                            "bool": {
                                "should": [
                                    {"exists": {"field": "app_proto"}},
                                    {"exists": {"field": "dns_qname"}},
                                    {"exists": {"field": "http_host"}},
                                    {"exists": {"field": "http_method"}},
                                    {"exists": {"field": "ja4"}},
                                    {"exists": {"field": "ja3"}},
                                    {"exists": {"field": "tls_sni"}},
                                ],
                                "minimum_should_match": 1,
                            }
                        }
                    },
                    "dns_events": {"filter": {"exists": {"field": "dns_qname"}}},
                    "http_events": {
                        "filter": {
                            "bool": {
                                "should": [
                                    {"exists": {"field": "http_host"}},
                                    {"exists": {"field": "http_method"}},
                                ],
                                "minimum_should_match": 1,
                            }
                        }
                    },
                    "tls_events": {
                        "filter": {
                            "bool": {
                                "should": [
                                    {"exists": {"field": "ja4"}},
                                    {"exists": {"field": "ja3"}},
                                    {"exists": {"field": "tls_sni"}},
                                ],
                                "minimum_should_match": 1,
                            }
                        }
                    },
                    "app_protocols": {"terms": {"field": "app_proto", "size": int(limit), "order": {"_count": "desc"}}},
                    "transport_protocols": {"terms": {"field": "proto", "size": int(limit), "order": {"_count": "desc"}}},
                    "top_dst_ports": {"terms": {"field": "dst_port", "size": int(limit), "order": {"_count": "desc"}}},
                    "top_src_ports": {"terms": {"field": "src_port", "size": int(limit), "order": {"_count": "desc"}}},
                    "app_proto_reasons": {"terms": {"field": "app_proto_reason", "size": int(limit), "order": {"_count": "desc"}}},
                    "app_proto_conf_bands": {
                        "terms": {"field": "app_proto_conf_band", "size": int(limit), "order": {"_count": "desc"}}
                    },
                    "ja4_ptypes": {"terms": {"field": "ja4_ptype", "size": int(limit), "order": {"_count": "desc"}}},
                    "http_methods": {"terms": {"field": "http_method", "size": int(limit), "order": {"_count": "desc"}}},
                    "top_dns_queries": {
                        "terms": {"field": "dns_qname", "size": int(limit), "order": {"_count": "desc"}},
                        "aggs": {"risk": {"max": {"field": "dns_risk"}}},
                    },
                    "top_http_hosts": {"terms": {"field": "http_host", "size": int(limit), "order": {"_count": "desc"}}},
                    "top_tls_sni": {"terms": {"field": "tls_sni", "size": int(limit), "order": {"_count": "desc"}}},
                    "top_alpn": {"terms": {"field": "tls_alpn_first", "size": int(limit), "order": {"_count": "desc"}}},
                    "top_ja4": {
                        "terms": {"field": "ja4", "size": int(limit), "order": {"_count": "desc"}},
                        "aggs": {"ptype": {"terms": {"field": "ja4_ptype", "size": 1, "order": {"_count": "desc"}}}},
                    },
                    "top_ja3": {"terms": {"field": "ja3", "size": int(limit), "order": {"_count": "desc"}}},
                },
            }

            res = es.search(index=_es_index_pattern(), body=body, ignore_unavailable=True, allow_no_indices=True)

            total_events = int(((res.get("hits") or {}).get("total") or {}).get("value", 0) or 0)
            # When track_total_hits=False, total may be missing. Use count API for correctness.
            if total_events == 0:
                total_events = int(
                    es.count(
                        index=_es_index_pattern(),
                        body={"query": {"bool": {"filter": base}}},
                        ignore_unavailable=True,
                        allow_no_indices=True,
                    ).get("count", 0)
                )

            aggs = res.get("aggregations") or {}

            with_proto_metadata = int(((aggs.get("with_proto_metadata") or {}).get("doc_count", 0)) or 0)
            dns_events = int(((aggs.get("dns_events") or {}).get("doc_count", 0)) or 0)
            http_events = int(((aggs.get("http_events") or {}).get("doc_count", 0)) or 0)
            tls_events = int(((aggs.get("tls_events") or {}).get("doc_count", 0)) or 0)

            def _buckets(name: str) -> list[dict]:
                return ((aggs.get(name) or {}).get("buckets") or [])

            app_protocols = [ProtoCount(key=str(b.get("key")), count=int(b.get("doc_count", 0) or 0)) for b in _buckets("app_protocols") if b.get("key") is not None]
            transport_protocols = [ProtoCount(key=str(b.get("key")), count=int(b.get("doc_count", 0) or 0)) for b in _buckets("transport_protocols") if b.get("key") is not None]
            top_dst_ports = [ProtoCount(key=str(b.get("key")), count=int(b.get("doc_count", 0) or 0)) for b in _buckets("top_dst_ports") if b.get("key") is not None]
            top_src_ports = [ProtoCount(key=str(b.get("key")), count=int(b.get("doc_count", 0) or 0)) for b in _buckets("top_src_ports") if b.get("key") is not None]
            app_proto_reasons = [ProtoCount(key=str(b.get("key")), count=int(b.get("doc_count", 0) or 0)) for b in _buckets("app_proto_reasons") if b.get("key") is not None]
            app_proto_conf_bands = [ProtoCount(key=str(b.get("key")), count=int(b.get("doc_count", 0) or 0)) for b in _buckets("app_proto_conf_bands") if b.get("key") is not None]
            ja4_ptypes = [ProtoCount(key=str(b.get("key")), count=int(b.get("doc_count", 0) or 0)) for b in _buckets("ja4_ptypes") if b.get("key") is not None]
            http_methods = [ProtoCount(key=str(b.get("key")), count=int(b.get("doc_count", 0) or 0)) for b in _buckets("http_methods") if b.get("key") is not None]

            top_dns_queries: list[ProtoDnsQueryStat] = []
            for b in _buckets("top_dns_queries"):
                k = b.get("key")
                if k is None:
                    continue
                risk_val = ((b.get("risk") or {}).get("value") or 0) or 0
                top_dns_queries.append(ProtoDnsQueryStat(qname=str(k), risk=int(risk_val), count=int(b.get("doc_count", 0) or 0)))

            top_http_hosts = [ProtoCount(key=str(b.get("key")), count=int(b.get("doc_count", 0) or 0)) for b in _buckets("top_http_hosts") if b.get("key") is not None]
            top_tls_sni = [ProtoCount(key=str(b.get("key")), count=int(b.get("doc_count", 0) or 0)) for b in _buckets("top_tls_sni") if b.get("key") is not None]
            top_alpn = [ProtoCount(key=str(b.get("key")), count=int(b.get("doc_count", 0) or 0)) for b in _buckets("top_alpn") if b.get("key") is not None]

            top_ja4: list[ProtoJa4Stat] = []
            for b in _buckets("top_ja4"):
                k = b.get("key")
                if k is None:
                    continue
                ptype_buckets = ((b.get("ptype") or {}).get("buckets") or [])
                ptype = str(ptype_buckets[0].get("key")) if ptype_buckets else "t"
                top_ja4.append(ProtoJa4Stat(ja4=str(k), ptype=ptype, count=int(b.get("doc_count", 0) or 0)))

            top_ja3 = [ProtoCount(key=str(b.get("key")), count=int(b.get("doc_count", 0) or 0)) for b in _buckets("top_ja3") if b.get("key") is not None]

            return ProtocolIntelSummaryResponse(
                generated_at=datetime.now(timezone.utc),
                since_minutes=int(since_minutes),
                agent_id=agent_id,
                total_events=total_events,
                with_proto_metadata=with_proto_metadata,
                dns_events=dns_events,
                http_events=http_events,
                tls_events=tls_events,
                app_protocols=app_protocols,
                transport_protocols=transport_protocols,
                top_dst_ports=top_dst_ports,
                top_src_ports=top_src_ports,
                app_proto_reasons=app_proto_reasons,
                app_proto_conf_bands=app_proto_conf_bands,
                ja4_ptypes=ja4_ptypes,
                http_methods=http_methods,
                top_dns_queries=top_dns_queries,
                top_http_hosts=top_http_hosts,
                top_tls_sni=top_tls_sni,
                top_alpn=top_alpn,
                top_ja4=top_ja4,
                top_ja3=top_ja3,
            )
        except Exception as e:
            if not _es_failover_allowed():
                raise HTTPException(status_code=503, detail=f"Elasticsearch error: {type(e).__name__}")

    # Postgres fallback (original implementation)
    db = SessionLocal()
    try:
        base_conds = [NetEventModel.timestamp >= since_ts]
        if agent_id:
            base_conds.append(NetEventModel.agent_id == agent_id)

        def _count_where(*conds) -> int:
            stmt = select(func.count()).select_from(NetEventModel).where(*base_conds, *conds)
            return int(db.execute(stmt).scalar() or 0)

        total_events = _count_where()
        with_proto_metadata = _count_where(
            or_(
                NetEventModel.extra.has_key("app_proto"),
                NetEventModel.extra.has_key("dns_qname"),
                NetEventModel.extra.has_key("http_host"),
                NetEventModel.extra.has_key("ja4"),
                NetEventModel.extra.has_key("ja3"),
                NetEventModel.extra.has_key("tls_sni"),
            )
        )
        dns_events = _count_where(NetEventModel.extra.has_key("dns_qname"))
        http_events = _count_where(or_(NetEventModel.extra.has_key("http_host"), NetEventModel.extra.has_key("http_method")))
        tls_events = _count_where(
            or_(NetEventModel.extra.has_key("ja4"), NetEventModel.extra.has_key("ja3"), NetEventModel.extra.has_key("tls_sni"))
        )

        def _top_k(expr, *, ensure_key: str | None = None, nonempty: bool = True) -> list[ProtoCount]:
            stmt = select(expr.label("key"), func.count().label("count")).where(*base_conds)
            if ensure_key:
                stmt = stmt.where(NetEventModel.extra.has_key(ensure_key))
            if nonempty:
                stmt = stmt.where(expr.is_not(None), expr != "")
            stmt = stmt.group_by(expr).order_by(func.count().desc()).limit(int(limit))
            rows = db.execute(stmt).all()
            return [ProtoCount(key=str(r.key), count=int(r.count or 0)) for r in rows if r.key is not None]

        app_protocols = _top_k(NetEventModel.extra["app_proto"].astext, ensure_key="app_proto")
        transport_protocols = _top_k(func.lower(NetEventModel.proto))
        top_dst_ports = _top_k(cast(NetEventModel.dst_port, String))
        top_src_ports = _top_k(cast(NetEventModel.src_port, String))
        app_proto_reasons = _top_k(NetEventModel.extra["app_proto_reason"].astext, ensure_key="app_proto_reason")
        app_proto_conf_bands = _top_k(NetEventModel.extra["app_proto_conf_band"].astext, ensure_key="app_proto_conf_band")
        ja4_ptypes = _top_k(
            func.coalesce(func.nullif(NetEventModel.extra["ja4_ptype"].astext, ""), "t"),
            nonempty=False,
        )
        http_methods = _top_k(func.upper(NetEventModel.extra["http_method"].astext), ensure_key="http_method")

        dns_qname = NetEventModel.extra["dns_qname"].astext
        dns_risk_txt = NetEventModel.extra["dns_risk"].astext
        dns_risk_int = cast(
            func.coalesce(
                func.nullif(
                    func.regexp_replace(func.coalesce(dns_risk_txt, ""), r"[^0-9-]", "", "g"),
                    "",
                ),
                "0",
            ),
            Integer,
        )
        dns_rows = db.execute(
            select(
                dns_qname.label("qname"),
                func.coalesce(func.max(dns_risk_int), 0).label("risk"),
                func.count().label("count"),
            )
            .where(*base_conds, NetEventModel.extra.has_key("dns_qname"), dns_qname.is_not(None), dns_qname != "")
            .group_by(dns_qname)
            .order_by(func.count().desc())
            .limit(int(limit))
        ).all()
        top_dns_queries = [ProtoDnsQueryStat(qname=str(r.qname), risk=int(r.risk or 0), count=int(r.count or 0)) for r in dns_rows]

        top_http_hosts = _top_k(func.lower(NetEventModel.extra["http_host"].astext), ensure_key="http_host")
        top_tls_sni = _top_k(func.lower(NetEventModel.extra["tls_sni"].astext), ensure_key="tls_sni")
        top_alpn = _top_k(func.lower(NetEventModel.extra["tls_alpn_first"].astext), ensure_key="tls_alpn_first")

        ja4_expr = NetEventModel.extra["ja4"].astext
        ja4_rows = db.execute(
            select(
                ja4_expr.label("ja4"),
                func.coalesce(func.nullif(func.max(NetEventModel.extra["ja4_ptype"].astext), ""), "t").label("ptype"),
                func.count().label("count"),
            )
            .where(*base_conds, NetEventModel.extra.has_key("ja4"), ja4_expr.is_not(None), ja4_expr != "")
            .group_by(ja4_expr)
            .order_by(func.count().desc())
            .limit(int(limit))
        ).all()
        top_ja4 = [ProtoJa4Stat(ja4=str(r.ja4), ptype=str(r.ptype or "t"), count=int(r.count or 0)) for r in ja4_rows]

        top_ja3 = _top_k(NetEventModel.extra["ja3"].astext, ensure_key="ja3")

        return ProtocolIntelSummaryResponse(
            generated_at=datetime.now(timezone.utc),
            since_minutes=int(since_minutes),
            agent_id=agent_id,
            total_events=total_events,
            with_proto_metadata=with_proto_metadata,
            dns_events=dns_events,
            http_events=http_events,
            tls_events=tls_events,
            app_protocols=app_protocols,
            transport_protocols=transport_protocols,
            top_dst_ports=top_dst_ports,
            top_src_ports=top_src_ports,
            app_proto_reasons=app_proto_reasons,
            app_proto_conf_bands=app_proto_conf_bands,
            ja4_ptypes=ja4_ptypes,
            http_methods=http_methods,
            top_dns_queries=top_dns_queries,
            top_http_hosts=top_http_hosts,
            top_tls_sni=top_tls_sni,
            top_alpn=top_alpn,
            top_ja4=top_ja4,
            top_ja3=top_ja3,
        )
    finally:
        db.close()


@router.get("/network/samples", response_model=List[NetEventDB])
def get_protocol_intel_samples(
    kind: str = Query(..., min_length=2, max_length=32, description="Which field to filter on"),
    value: str = Query(..., min_length=1, max_length=512, description="Exact value for the selected field"),
    since_minutes: int = Query(60 * 12, ge=1, le=60 * 24 * 30, description="Lookback window in minutes"),
    limit: int = Query(50, ge=1, le=200, description="Maximum number of events to return"),
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
):
    """Return recent events matching a specific protocol-intel indicator.

    This endpoint is designed for the UI drawer and intentionally strips raw payload fields.
    """

    since_ts = datetime.now(timezone.utc) - timedelta(minutes=int(since_minutes))

    # Whitelist (avoid field injection)
    kind_map = {
        "app_proto": "app_proto",
        "transport": "proto",
        "dst_port": "dst_port",
        "src_port": "src_port",
        "app_proto_reason": "app_proto_reason",
        "app_proto_conf_band": "app_proto_conf_band",
        "dns_qname": "dns_qname",
        "http_host": "http_host",
        "http_method": "http_method",
        "tls_sni": "tls_sni",
        "tls_alpn_first": "tls_alpn_first",
        "ja4": "ja4",
        "ja4_ptype": "ja4_ptype",
        "ja3": "ja3",
    }
    es_field = kind_map.get(kind)
    if not es_field:
        return []

    value_norm: Any = value
    if kind in {"http_host", "tls_sni", "tls_alpn_first", "dns_qname"}:
        value_norm = value.lower()
    elif kind == "http_method":
        value_norm = value.upper()
    elif kind == "transport":
        value_norm = value.lower()
    elif kind in {"dst_port", "src_port"}:
        try:
            value_norm = int(value)
        except Exception:
            return []

    es = _es_client_or_none()
    if es is not None:
        try:
            base = _es_base_filters(since=since_ts, agent_id=agent_id)
            body = {
                "size": int(limit),
                "sort": [{"timestamp": {"order": "desc"}}, {"id": {"order": "desc"}}],
                "query": {
                    "bool": {
                        "filter": base + [{"term": {es_field: value_norm}}],
                    }
                },
            }
            res = es.search(index=_es_index_pattern(), body=body, ignore_unavailable=True, allow_no_indices=True)
            hits = (res.get("hits") or {}).get("hits") or []
            out: list[NetEventDB] = []
            for h in hits:
                item = _hit_to_event(h)
                item.extra = _strip_large_extra(item.extra)
                out.append(item)
            return out
        except Exception as e:
            if not _es_failover_allowed():
                raise HTTPException(status_code=503, detail=f"Elasticsearch error: {type(e).__name__}")

    # Postgres fallback (ORM/expressions)
    kind_map_pg = {
        "app_proto": NetEventModel.extra["app_proto"].astext,
        "transport": func.lower(NetEventModel.proto),
        "dst_port": NetEventModel.dst_port,
        "src_port": NetEventModel.src_port,
        "app_proto_reason": NetEventModel.extra["app_proto_reason"].astext,
        "app_proto_conf_band": NetEventModel.extra["app_proto_conf_band"].astext,
        "dns_qname": NetEventModel.extra["dns_qname"].astext,
        "http_host": func.lower(NetEventModel.extra["http_host"].astext),
        "http_method": func.upper(NetEventModel.extra["http_method"].astext),
        "tls_sni": func.lower(NetEventModel.extra["tls_sni"].astext),
        "tls_alpn_first": func.lower(NetEventModel.extra["tls_alpn_first"].astext),
        "ja4": NetEventModel.extra["ja4"].astext,
        "ja4_ptype": func.coalesce(func.nullif(NetEventModel.extra["ja4_ptype"].astext, ""), "t"),
        "ja3": NetEventModel.extra["ja3"].astext,
    }
    expr = kind_map_pg.get(kind)
    if not expr:
        return []

    db = SessionLocal()
    try:
        stmt = (
            select(
                NetEventModel.id,
                NetEventModel.agent_id,
                NetEventModel.event_type,
                NetEventModel.schema_version,
                NetEventModel.timestamp,
                NetEventModel.src_ip,
                NetEventModel.dst_ip,
                NetEventModel.src_port,
                NetEventModel.dst_port,
                NetEventModel.proto,
                NetEventModel.bytes,
                NetEventModel.extra,
            )
            .where(
                NetEventModel.timestamp >= since_ts,
                expr == value_norm,
            )
            .order_by(NetEventModel.timestamp.desc())
            .limit(int(limit))
        )
        if agent_id:
            stmt = stmt.where(NetEventModel.agent_id == agent_id)
        rows = db.execute(stmt).mappings().all()

        out: list[NetEventDB] = []
        for r in rows:
            item = NetEventDB(**dict(r))
            item.extra = _strip_large_extra(item.extra)
            out.append(item)
        return out
    finally:
        db.close()
