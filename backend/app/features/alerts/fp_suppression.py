from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.features.alerts.models import AlertModel, AlertRuleSuppressionModel


def suggest_suppressions_from_fp_feedback(db: Session, *, threshold: int = 3) -> list[AlertRuleSuppressionModel]:
    min_count = max(1, int(threshold))
    grouped = (
        select(
            AlertModel.rule_id,
            AlertModel.false_positive_reason,
            AlertModel.src_ip,
            func.count().label("hits"),
        )
        .where(
            AlertModel.disposition == "false_positive",
            AlertModel.false_positive_reason.is_not(None),
            AlertModel.src_ip.is_not(None),
        )
        .group_by(AlertModel.rule_id, AlertModel.false_positive_reason, AlertModel.src_ip)
        .having(func.count() >= min_count)
    )
    candidates = db.execute(grouped).all()
    if not candidates:
        return []

    rule_ids = {str(row.rule_id) for row in candidates}
    existing_rows = db.execute(
        select(AlertRuleSuppressionModel).where(AlertRuleSuppressionModel.rule_id.in_(rule_ids))
    ).scalars().all()
    existing_scopes = {
        (str(row.rule_id), str((row.when or {}).get("src_ip") or ""))
        for row in existing_rows
    }

    created: list[AlertRuleSuppressionModel] = []
    for row in candidates:
        rule_id = str(row.rule_id)
        src_ip = str(row.src_ip)
        if (rule_id, src_ip) in existing_scopes:
            continue
        suggestion = AlertRuleSuppressionModel(
            rule_id=rule_id,
            enabled=False,
            reason=str(row.false_positive_reason),
            when={"src_ip": src_ip},
        )
        db.add(suggestion)
        created.append(suggestion)
        existing_scopes.add((rule_id, src_ip))

    if created:
        db.flush()
    return created
