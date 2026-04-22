from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.features.vuln.presentation import serialize_risk_item
from app.features.vuln.repository import posture_data, summary_counts
from app.features.vuln.schemas import (
    VulnAssetRiskOut,
    VulnPostureOut,
    VulnRiskItemOut,
    VulnSummaryOut,
)


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
