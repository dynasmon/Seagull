from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, text

from app.core.portal_auth import get_current_user
from app.core.db import SessionLocal
from app.models.events import NetEventModel
from app.schemas.events import (
    NetEventDB,
    SshIpStat,
    SshLoginEvent,
    SshSummaryResponse,
    SshUserStat,
    SudoEventSummary,
)
router = APIRouter(
    prefix="/events",
    tags=["events"],
    dependencies=[Depends(get_current_user)],
)


@router.get("/recent", response_model=List[NetEventDB])
def get_recent_events(
    limit: int = Query(50, ge=1, le=1000, description="Maximum number of events to return"),
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
):
    # Return the most recent events, optionally filtered by agent_id and event_type.
    db = SessionLocal()
    try:
        stmt = select(NetEventModel).order_by(NetEventModel.timestamp.desc())
        if agent_id:
            stmt = stmt.where(NetEventModel.agent_id == agent_id)
        if event_type:
            stmt = stmt.where(NetEventModel.event_type == event_type)
        stmt = stmt.limit(limit)

        result = db.execute(stmt)
        return result.scalars().all()
    finally:
        db.close()


@router.get("/stats/ports")
def get_port_stats(
    limit: int = Query(20, ge=1, le=200, description="Maximum number of ports to return"),
):
    # Return a simple distribution of events by destination port.
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
            .limit(limit)
        )

        rows = db.execute(stmt).all()
        return [{"port": row.port, "count": row.count} for row in rows]
    finally:
        db.close()


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

    db = SessionLocal()
    try:
        params_base = {
            "since": since_ts,
            "limit": int(limit),
            "agent_id": agent_id,
        }

        def _top_ips(action: str) -> list[SshIpStat]:
            rows = db.execute(
                text(
                    """
                    SELECT
                        src_ip,
                        COUNT(*)::bigint AS count,
                        MAX(extra->>'geo_country') AS geo_country,
                        MAX(extra->>'geo_org') AS geo_org,
                        MAX(extra->>'asn') AS asn,
                        MAX(extra->>'asn_org') AS asn_org
                    FROM net_events
                    WHERE event_type = 'ssh_auth'
                      AND (extra->>'action') = :action
                      AND "timestamp" >= :since
                      AND (:agent_id IS NULL OR agent_id = :agent_id)
                      AND src_ip IS NOT NULL
                    GROUP BY src_ip
                    ORDER BY count DESC
                    LIMIT :limit;
                    """
                ),
                {**params_base, "action": action},
            ).mappings().all()
            return [SshIpStat(**dict(r)) for r in rows]

        successful_logins = _top_ips("accepted")
        failed_attempts = _top_ips("failed_password")
        invalid_user_attempts = _top_ips("invalid_user")

        # Most active IPs across the main SSH actions
        rows = db.execute(
            text(
                """
                SELECT
                    src_ip,
                    COUNT(*)::bigint AS count,
                    MAX(extra->>'geo_country') AS geo_country,
                    MAX(extra->>'geo_org') AS geo_org,
                    MAX(extra->>'asn') AS asn,
                    MAX(extra->>'asn_org') AS asn_org
                FROM net_events
                WHERE event_type = 'ssh_auth'
                  AND (extra->>'action') = ANY(:actions)
                  AND "timestamp" >= :since
                  AND (:agent_id IS NULL OR agent_id = :agent_id)
                  AND src_ip IS NOT NULL
                GROUP BY src_ip
                ORDER BY count DESC
                LIMIT :limit;
                """
            ),
            {**params_base, "actions": ["accepted", "failed_password", "invalid_user"]},
        ).mappings().all()
        most_active_ips = [SshIpStat(**dict(r)) for r in rows]

        # Root logins
        rows = db.execute(
            text(
                """
                SELECT
                    "timestamp" AS timestamp,
                    agent_id,
                    src_ip,
                    (extra->>'username') AS username,
                    (extra->>'geo_country') AS geo_country,
                    (extra->>'geo_org') AS geo_org,
                    (extra->>'asn') AS asn,
                    (extra->>'asn_org') AS asn_org
                FROM net_events
                WHERE event_type = 'ssh_auth'
                  AND (extra->>'action') = 'accepted'
                  AND (extra->>'username') = 'root'
                  AND "timestamp" >= :since
                  AND (:agent_id IS NULL OR agent_id = :agent_id)
                ORDER BY "timestamp" DESC
                LIMIT :limit;
                """
            ),
            params_base,
        ).mappings().all()
        root_logins = [SshLoginEvent(**dict(r)) for r in rows]

        # Users that attempted to log in (failed/invalid)
        rows = db.execute(
            text(
                """
                SELECT
                    (extra->>'username') AS username,
                    COUNT(*)::bigint AS count
                FROM net_events
                WHERE event_type = 'ssh_auth'
                  AND (extra->>'action') = ANY(:actions)
                  AND "timestamp" >= :since
                  AND (:agent_id IS NULL OR agent_id = :agent_id)
                  AND (extra ? 'username')
                GROUP BY (extra->>'username')
                ORDER BY count DESC
                LIMIT :limit;
                """
            ),
            {**params_base, "actions": ["failed_password", "invalid_user"]},
        ).mappings().all()
        users_attempted = [SshUserStat(**dict(r)) for r in rows]

        # Recent sudo commands (from auth.log)
        rows = db.execute(
            text(
                """
                SELECT
                    "timestamp" AS timestamp,
                    agent_id,
                    (extra->>'username') AS username,
                    (extra->>'target_user') AS target_user,
                    (extra->>'command') AS command,
                    (extra->>'tty') AS tty,
                    (extra->>'pwd') AS pwd
                FROM net_events
                WHERE event_type = 'sudo_cmd'
                  AND "timestamp" >= :since
                  AND (:agent_id IS NULL OR agent_id = :agent_id)
                ORDER BY "timestamp" DESC
                LIMIT :limit;
                """
            ),
            params_base,
        ).mappings().all()
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
