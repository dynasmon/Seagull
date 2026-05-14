from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert

from app.core.cache import get_redis
from app.core.db import engine
from app.features.alerts.models import AlertModel
from app.features.alerts.realtime import publish_alert_created_payload, publish_alert_updated_payload
from app.features.events.models import IngestStats1sModel
from app.features.ingest.control.queue_keys import (
    _env_int,
    storm_active_key,
    storm_alert_id_key,
    storm_session_key,
    storm_since_key,
)


def mark_storm_active(*, reason: str, sample_hot: int, sample_warm: int) -> None:
    r = get_redis()
    if r is None:
        return

    ttl_s = _env_int("SEAGULL_INGEST_STORM_TTL_SECONDS", 20)

    try:
        pipe = r.pipeline()
        pipe.setex(storm_active_key(), ttl_s, "1")
        pipe.setex("seagull:ingest:storm_reason", ttl_s, (reason or "storm")[:64])
        pipe.setex("seagull:ingest:storm_sample_hot", ttl_s, str(int(sample_hot)))
        pipe.setex("seagull:ingest:storm_sample_warm", ttl_s, str(int(sample_warm)))
        pipe.execute()
    except Exception:
        return


def storm_maybe_open_alert(*, reason: str, sample_hot: int, sample_warm: int) -> None:
    """Open a single 'Ingest Storm Detected' alert per storm session."""

    r = get_redis()
    if r is None:
        return

    try:
        existing = (r.get(storm_alert_id_key()) or "").strip()
        if existing:
            try:
                eid = int(existing)
                with engine.begin() as conn:
                    ok = conn.execute(select(AlertModel.id).where(AlertModel.id == eid).limit(1)).first()
                if ok:
                    return
                r.delete(storm_alert_id_key())
            except Exception:
                try:
                    r.delete(storm_alert_id_key())
                except Exception:
                    pass
    except Exception:
        return

    lock_key = "seagull:ingest:storm_alert_open_lock"
    try:
        if not r.set(lock_key, "1", nx=True, ex=5):
            return
    except Exception:
        return

    now = datetime.now(timezone.utc)

    try:
        session_id = (r.get(storm_session_key()) or "").strip()
        since_iso = (r.get(storm_since_key()) or "").strip()
    except Exception:
        session_id, since_iso = "", ""

    if not session_id:
        session_id = str(uuid.uuid4())
        try:
            r.setnx(storm_session_key(), session_id)
        except Exception:
            pass

    if not since_iso:
        since_iso = now.isoformat()
        try:
            r.setnx(storm_since_key(), since_iso)
        except Exception:
            pass

    details = {
        "storm": {
            "session_id": session_id,
            "started_at": since_iso,
            "reason": reason,
            "sample_hot_percent": int(sample_hot),
            "sample_warm_percent": int(sample_warm),
        },
        "timeline": [],
    }

    try:
        with engine.begin() as conn:
            row = conn.execute(
                insert(AlertModel)
                .values(
                    created_at=now,
                    rule_id="system.ingest_storm",
                    severity="high",
                    mitre_tactic="impact",
                    mitre_technique_id="T1498",
                    mitre_technique="Network Denial of Service",
                    confidence=85,
                    description="Ingest Storm Detected",
                    details=details,
                )
                .returning(AlertModel.id)
            ).fetchone()
            alert_id = int(row[0]) if row else 0

        if alert_id:
            r.setex(storm_alert_id_key(), _env_int("SEAGULL_INGEST_STORM_ALERT_TTL_SECONDS", 3600), str(alert_id))
            publish_alert_created_payload(
                {
                    "alert_id": int(alert_id),
                    "created_at": now.isoformat(),
                    "rule_id": "system.ingest_storm",
                    "severity": "high",
                    "description": "Ingest Storm Detected",
                }
            )
    except Exception:
        return
    finally:
        try:
            r.delete(lock_key)
        except Exception:
            pass


def storm_maybe_close_alert() -> None:
    """Finalize an open storm alert if the storm has ended."""

    r = get_redis()
    if r is None:
        return

    try:
        active = bool(r.get(storm_active_key()))
        alert_id_raw = r.get(storm_alert_id_key())
        since_iso = r.get(storm_since_key())
    except Exception:
        return

    if active or not alert_id_raw or not since_iso:
        return

    try:
        alert_id = int(alert_id_raw)
    except Exception:
        return

    try:
        start = datetime.fromisoformat(since_iso)
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
    except Exception:
        start = datetime.now(timezone.utc) - timedelta(minutes=10)

    end = datetime.now(timezone.utc)

    try:
        with engine.begin() as conn:
            rows = conn.execute(
                select(
                    IngestStats1sModel.bucket_ts,
                    IngestStats1sModel.received,
                    IngestStats1sModel.hot_stored,
                    IngestStats1sModel.warm_indexed,
                    IngestStats1sModel.dropped,
                    IngestStats1sModel.rejected,
                    IngestStats1sModel.rollup_only,
                    IngestStats1sModel.backlog_events,
                    IngestStats1sModel.backlog_messages,
                    IngestStats1sModel.storm_active,
                    IngestStats1sModel.sample_hot_percent,
                    IngestStats1sModel.sample_warm_percent,
                )
                .where(IngestStats1sModel.bucket_ts >= start, IngestStats1sModel.bucket_ts <= end)
                .order_by(IngestStats1sModel.bucket_ts.asc())
                .limit(1200)
            ).mappings().all()

            timeline = []
            for rr in rows:
                timeline.append(
                    {
                        "ts": (rr.get("bucket_ts").isoformat() if rr.get("bucket_ts") else None),
                        "eps": int(rr.get("received") or 0),
                        "hot": int(rr.get("hot_stored") or 0),
                        "warm": int(rr.get("warm_indexed") or 0),
                        "dropped": int(rr.get("dropped") or 0),
                        "rejected": int(rr.get("rejected") or 0),
                        "backlog_events": int(rr.get("backlog_events") or 0),
                        "backlog_messages": int(rr.get("backlog_messages") or 0),
                        "sample_hot_percent": int(rr.get("sample_hot_percent") or 100),
                        "sample_warm_percent": int(rr.get("sample_warm_percent") or 0),
                    }
                )

            patch = {
                "storm": {
                    "ended_at": end.isoformat(),
                },
                "timeline": timeline,
            }

            conn.execute(
                AlertModel.__table__.update()
                .where(AlertModel.id == alert_id)
                .values(details=AlertModel.details.op("||")(patch))
            )

        publish_alert_updated_payload(
            {
                "alert_id": int(alert_id),
                "rule_id": "system.ingest_storm",
                "severity": "high",
                "status": "closed",
                "updated_at": end.isoformat(),
            }
        )

        try:
            r.delete(storm_alert_id_key(), storm_session_key(), storm_since_key())
        except Exception:
            pass

    except Exception:
        return
