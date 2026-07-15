from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.features.detections.models import DetectionRuleHealthModel


def get_rule_health_map(db: Session) -> dict[str, DetectionRuleHealthModel]:
    rows = db.execute(select(DetectionRuleHealthModel)).scalars().all()
    return {row.rule_id: row for row in rows}


def upsert_rule_health_batch(db: Session, records: list[dict[str, Any]]) -> None:
    if not records:
        return
    stmt = pg_insert(DetectionRuleHealthModel.__table__).values(records)
    update_cols = {col: stmt.excluded[col] for col in records[0] if col != "rule_id"}
    db.execute(stmt.on_conflict_do_update(index_elements=["rule_id"], set_=update_cols))
