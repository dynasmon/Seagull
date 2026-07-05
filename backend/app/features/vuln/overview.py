from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.observability import observe_hist
from app.features.vuln.presentation import serialize_risk_item
from app.features.vuln.repository import posture_data, summary_counts
from app.features.vuln.schemas import (
    VulnAssetRiskOut,
    VulnPostureOut,
    VulnRiskItemOut,
    VulnSummaryOut,
)
from app.shared.analytics import (
    AnalyticalReadModel,
    SnapshotPage,
    register_read_model,
    register_snapshot_page,
    serve_read_model,
)

VULN_DEFAULT_ACTIVE_WITHIN_DAYS = 30
VULN_DEFAULT_INCLUDE_SUPPRESSED = False
VULN_POSTURE_DEFAULT_TOP_N = 15


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def summary(db: Session, *, active_within_days: int, include_suppressed: bool) -> VulnSummaryOut:
    now = _utc_now()
    since = now - timedelta(days=int(active_within_days))
    (
        total_open,
        total_observed,
        total_awaiting_verification,
        total_resolved,
        total_suppressed,
        by_severity,
        by_status,
        by_observation_state,
        by_disposition,
    ) = summary_counts(
        db,
        since=since,
        include_suppressed=include_suppressed,
    )
    return VulnSummaryOut(
        generated_at=now,
        total_open=total_open,
        total_observed=total_observed,
        total_awaiting_verification=total_awaiting_verification,
        total_resolved=total_resolved,
        total_suppressed=total_suppressed,
        by_severity=by_severity,
        by_status=by_status,
        by_observation_state=by_observation_state,
        by_disposition=by_disposition,
    )


def _vuln_summary_cache_key(params: dict) -> str:
    return (
        "seagull:vuln:summary:v1:"
        f"awd={int(params['active_within_days'])}:supp={1 if params.get('include_suppressed') else 0}"
    )


def _resolve_vuln_summary_blocking(*, active_within_days: int, include_suppressed: bool) -> VulnSummaryOut:
    from app.core.db import SessionLocal

    db = SessionLocal()
    try:
        return summary(db, active_within_days=active_within_days, include_suppressed=include_suppressed)
    finally:
        db.close()


async def _compute_vuln_summary(params: dict) -> dict:
    payload = await asyncio.to_thread(
        _resolve_vuln_summary_blocking,
        active_within_days=int(params["active_within_days"]),
        include_suppressed=bool(params.get("include_suppressed")),
    )
    return payload.model_dump(mode="json")


def _vuln_summary_snapshotable(params: dict) -> bool:
    try:
        active_within_days = int(params.get("active_within_days") or 0)
    except (TypeError, ValueError):
        return False
    return (
        active_within_days == VULN_DEFAULT_ACTIVE_WITHIN_DAYS
        and bool(params.get("include_suppressed")) == VULN_DEFAULT_INCLUDE_SUPPRESSED
    )


def _vuln_summary_snapshot_scopes() -> list[dict]:
    return [
        {
            "active_within_days": VULN_DEFAULT_ACTIVE_WITHIN_DAYS,
            "include_suppressed": VULN_DEFAULT_INCLUDE_SUPPRESSED,
        }
    ]


VULN_SUMMARY_SNAPSHOT_PAGE = register_snapshot_page(
    SnapshotPage(
        page="vuln_summary",
        flag_env="SEAGULL_SNAPSHOT_VULN_SUMMARY_ENABLED",
        schema_version=1,
        raw_compute=_compute_vuln_summary,
        scope_key_builder=_vuln_summary_cache_key,
        static_scopes=_vuln_summary_snapshot_scopes,
        snapshotable=_vuln_summary_snapshotable,
    )
)


VULN_SUMMARY_READ_MODEL = register_read_model(
    AnalyticalReadModel(
        name="vuln_summary",
        schema_version=1,
        fresh_s=int(getattr(settings, "SEAGULL_VULN_SUMMARY_FRESH_SECONDS", 60) or 60),
        stale_s=int(getattr(settings, "SEAGULL_VULN_SUMMARY_STALE_SECONDS", 900) or 900),
        key_builder=_vuln_summary_cache_key,
        compute=VULN_SUMMARY_SNAPSHOT_PAGE.compute,
    )
)


async def get_vuln_summary_async(*, active_within_days: int, include_suppressed: bool) -> tuple[dict, str, str]:
    started = time.perf_counter()
    params = {
        "active_within_days": int(active_within_days),
        "include_suppressed": bool(include_suppressed),
    }
    payload, etag, outcome = await serve_read_model(VULN_SUMMARY_READ_MODEL, params)
    payload = dict(payload)
    meta = dict(payload.get("meta") or {})
    meta["cache_hit"] = outcome != "miss"
    meta["query_latency_ms"] = round((time.perf_counter() - started) * 1000.0, 2)
    payload["meta"] = meta
    observe_hist(
        "api_route_latency_seconds",
        time.perf_counter() - started,
        route="/vuln/summary",
        source=str(meta.get("source") or "compute"),
    )
    return payload, etag, outcome


def posture(
    db: Session,
    *,
    active_within_days: int,
    include_suppressed: bool,
    top_n: int,
) -> VulnPostureOut:
    now = _utc_now()
    since = now - timedelta(days=int(active_within_days))
    totals, top_rows, asset_rows = posture_data(
        db,
        now=now,
        since=since,
        include_suppressed=include_suppressed,
        top_n=top_n,
    )

    return VulnPostureOut(
        generated_at=now,
        active_within_days=int(active_within_days),
        total_open=int(totals.get("total_open") or 0),
        critical_open=int(totals.get("critical_open") or 0),
        high_open=int(totals.get("high_open") or 0),
        exploitable_open=int(totals.get("exploitable_open") or 0),
        fixable_open=int(totals.get("fixable_open") or 0),
        stale_open=int(totals.get("stale_open") or 0),
        mean_risk=float(totals.get("mean_risk") or 0.0),
        p95_risk=float(totals.get("p95_risk") or 0.0),
        top_risks=[VulnRiskItemOut(**serialize_risk_item(row)) for row in top_rows],
        top_assets=[VulnAssetRiskOut(**row) for row in asset_rows],
    )


def _vuln_posture_cache_key(params: dict) -> str:
    return (
        "seagull:vuln:posture:v1:"
        f"awd={int(params['active_within_days'])}:supp={1 if params.get('include_suppressed') else 0}:"
        f"top={int(params['top_n'])}"
    )


def _resolve_vuln_posture_blocking(
    *,
    active_within_days: int,
    include_suppressed: bool,
    top_n: int,
) -> VulnPostureOut:
    from app.core.db import SessionLocal

    db = SessionLocal()
    try:
        return posture(
            db,
            active_within_days=active_within_days,
            include_suppressed=include_suppressed,
            top_n=top_n,
        )
    finally:
        db.close()


async def _compute_vuln_posture(params: dict) -> dict:
    payload = await asyncio.to_thread(
        _resolve_vuln_posture_blocking,
        active_within_days=int(params["active_within_days"]),
        include_suppressed=bool(params.get("include_suppressed")),
        top_n=int(params["top_n"]),
    )
    return payload.model_dump(mode="json")


def _vuln_posture_snapshotable(params: dict) -> bool:
    if not _vuln_summary_snapshotable(params):
        return False
    try:
        top_n = int(params.get("top_n") or 0)
    except (TypeError, ValueError):
        return False
    return top_n == VULN_POSTURE_DEFAULT_TOP_N


def _vuln_posture_snapshot_scopes() -> list[dict]:
    return [
        {
            "active_within_days": VULN_DEFAULT_ACTIVE_WITHIN_DAYS,
            "include_suppressed": VULN_DEFAULT_INCLUDE_SUPPRESSED,
            "top_n": VULN_POSTURE_DEFAULT_TOP_N,
        }
    ]


VULN_POSTURE_SNAPSHOT_PAGE = register_snapshot_page(
    SnapshotPage(
        page="vuln_posture",
        flag_env="SEAGULL_SNAPSHOT_VULN_POSTURE_ENABLED",
        schema_version=1,
        raw_compute=_compute_vuln_posture,
        scope_key_builder=_vuln_posture_cache_key,
        static_scopes=_vuln_posture_snapshot_scopes,
        snapshotable=_vuln_posture_snapshotable,
    )
)


VULN_POSTURE_READ_MODEL = register_read_model(
    AnalyticalReadModel(
        name="vuln_posture",
        schema_version=1,
        fresh_s=int(getattr(settings, "SEAGULL_VULN_POSTURE_FRESH_SECONDS", 60) or 60),
        stale_s=int(getattr(settings, "SEAGULL_VULN_POSTURE_STALE_SECONDS", 900) or 900),
        key_builder=_vuln_posture_cache_key,
        compute=VULN_POSTURE_SNAPSHOT_PAGE.compute,
    )
)


async def get_vuln_posture_async(
    *,
    active_within_days: int,
    include_suppressed: bool,
    top_n: int,
) -> tuple[dict, str, str]:
    started = time.perf_counter()
    params = {
        "active_within_days": int(active_within_days),
        "include_suppressed": bool(include_suppressed),
        "top_n": int(top_n),
    }
    payload, etag, outcome = await serve_read_model(VULN_POSTURE_READ_MODEL, params)
    payload = dict(payload)
    meta = dict(payload.get("meta") or {})
    meta["cache_hit"] = outcome != "miss"
    meta["query_latency_ms"] = round((time.perf_counter() - started) * 1000.0, 2)
    payload["meta"] = meta
    observe_hist(
        "api_route_latency_seconds",
        time.perf_counter() - started,
        route="/vuln/posture",
        source=str(meta.get("source") or "compute"),
    )
    return payload, etag, outcome
