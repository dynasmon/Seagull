from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.features.correlations.engines.base import to_utc_naive
from app.features.correlations.models import EntityBaselineModel

_WINDOW_7D = timedelta(days=7)
_WINDOW_30D = timedelta(days=30)


def upsert_entity_observations(db: Session, observations: list[tuple[str, str, datetime]]) -> None:
    if not observations:
        return

    aggregated: dict[tuple[str, str], list[datetime]] = {}
    for entity_type, entity_value, observed_at in observations:
        etype = str(entity_type or "").strip()
        evalue = str(entity_value or "").strip()
        if not etype or not evalue or observed_at is None:
            continue
        aggregated.setdefault((etype[:64], evalue[:255]), []).append(to_utc_naive(observed_at))
    if not aggregated:
        return

    now = datetime.utcnow()
    records: list[dict] = []
    for (etype, evalue), times in aggregated.items():
        first_seen = min(times)
        last_seen = max(times)
        cutoff_7d = last_seen - _WINDOW_7D
        cutoff_30d = last_seen - _WINDOW_30D
        records.append(
            {
                "entity_type": etype,
                "entity_value": evalue,
                "feature": "presence",
                "first_seen_at": first_seen,
                "last_seen_at": last_seen,
                "count_7d": sum(1 for ts in times if ts >= cutoff_7d),
                "count_30d": sum(1 for ts in times if ts >= cutoff_30d),
                "updated_at": now,
            }
        )

    stmt = pg_insert(EntityBaselineModel.__table__).values(records)
    excluded = stmt.excluded
    db.execute(
        stmt.on_conflict_do_update(
            index_elements=["entity_type", "entity_value", "feature"],
            set_={
                "first_seen_at": func.least(EntityBaselineModel.first_seen_at, excluded.first_seen_at),
                "last_seen_at": func.greatest(EntityBaselineModel.last_seen_at, excluded.last_seen_at),
                "count_7d": EntityBaselineModel.count_7d + excluded.count_7d,
                "count_30d": EntityBaselineModel.count_30d + excluded.count_30d,
                "updated_at": excluded.updated_at,
            },
        )
    )


def load_entity_baseline(db: Session, entity_type: str, entity_values: list[str]) -> dict[str, EntityBaselineModel]:
    etype = str(entity_type or "").strip()
    values = sorted({str(value or "").strip() for value in (entity_values or []) if str(value or "").strip()})
    if not etype or not values:
        return {}
    stmt = select(EntityBaselineModel).where(
        EntityBaselineModel.entity_type == etype,
        EntityBaselineModel.entity_value.in_(values),
    )
    return {str(row.entity_value): row for row in db.execute(stmt).scalars().all()}
