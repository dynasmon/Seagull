from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from app.features.detections.pipeline.types import AlertCandidate
from app.workers.intelligence.rules.conditions import (
    _ALLOWED_EVENT_FIELDS,
    _build_match_filters,
    _evaluate_condition,
    _parse_window,
    _safe_col,
)
from app.workers.intelligence.rules.health import _content_hash
from app.workers.intelligence.rules.mitre import _extract_mitre_meta

_AGG_TYPE = {
    "aggregate_count": "threshold",
    "distinct_count": "cardinality",
    "multi_distinct": "multi_cardinality",
}


def _group_fields(rule: dict[str, Any]) -> list[str]:
    group_by = rule.get("group_by")
    fields = group_by if isinstance(group_by, list) else [group_by] if isinstance(group_by, str) else []
    return [f for f in fields if isinstance(f, str) and f in _ALLOWED_EVENT_FIELDS]


def _base_extra(
    rule: dict[str, Any],
    *,
    agg_type: str,
    group_fields: list[str],
    condition: dict[str, Any],
    min_events: int,
    since: datetime,
    until: datetime,
) -> dict[str, Any]:
    try:
        cooldown = timedelta(seconds=_parse_window(rule.get("cooldown", "10m")))
    except Exception:
        cooldown = timedelta(minutes=10)
    return {
        "schema_version": 1,
        "agg_type": agg_type,
        "group_by": group_fields,
        "severity": str(rule.get("severity", "low") or "low").strip().lower(),
        "base_condition": condition,
        "base_min_events": int(min_events),
        "base_cooldown_seconds": int(cooldown.total_seconds()),
        "window_seconds": int((until - since).total_seconds()),
        "mitre": _extract_mitre_meta(rule),
        "description": rule.get("description", ""),
        "rule_hash": _content_hash(rule),
        "effective_suppressions": list(rule.get("suppressions") or []),
    }


class V1RuleExecutor:
    def can_execute(self, rule: dict[str, Any]) -> bool:
        return int(rule.get("schema_version") or 1) == 1

    def execute(
        self, rule: dict[str, Any], *, db: Session, since: datetime, until: datetime
    ) -> list[AlertCandidate]:
        rule_type = rule.get("type")
        if rule_type == "aggregate_count":
            return self._run_aggregate_count(rule, db=db, since=since, until=until)
        if rule_type == "distinct_count":
            return self._run_distinct_count(rule, db=db, since=since, until=until)
        if rule_type == "multi_distinct":
            return self._run_multi_distinct(rule, db=db, since=since, until=until)
        return []

    def _run_aggregate_count(
        self, rule: dict[str, Any], *, db: Session, since: datetime, until: datetime
    ) -> list[AlertCandidate]:
        rule_id = str(rule.get("id") or "")
        match = rule.get("match") or {}
        group_fields = _group_fields(rule)
        if not group_fields:
            return []
        group_cols = [_safe_col(f) for f in group_fields]
        condition = rule.get("condition", {}) or {}
        min_events = int(rule.get("min_events") or condition.get("min_events") or 0)

        filters = _build_match_filters(match, since, until)
        stmt = (
            select(
                *[c.label(f) for c, f in zip(group_cols, group_fields, strict=False)],
                func.count().label("count"),
            )
            .where(and_(*filters))
            .group_by(*group_cols)
        )
        rows = db.execute(stmt).all()
        base = _base_extra(
            rule, agg_type="threshold", group_fields=group_fields, condition=condition, min_events=min_events, since=since, until=until
        )

        out: list[AlertCandidate] = []
        for row in rows:
            group_key = {f: row._mapping.get(f) for f in group_fields}
            count = int(row.count)
            extra = dict(base)
            extra["count"] = count
            out.append(
                AlertCandidate(
                    rule_id=rule_id,
                    rule=rule,
                    group_key=group_key,
                    match_hints=match,
                    count_value=count,
                    min_events_check=count,
                    since=since,
                    until=until,
                    extra=extra,
                )
            )
        return out

    def _run_distinct_count(
        self, rule: dict[str, Any], *, db: Session, since: datetime, until: datetime
    ) -> list[AlertCandidate]:
        rule_id = str(rule.get("id") or "")
        match = rule.get("match") or {}
        condition = rule.get("condition", {}) or {}
        min_events = int(rule.get("min_events") or condition.get("min_events") or 0)

        distinct_field = rule.get("distinct_field")
        if not isinstance(distinct_field, str) or distinct_field not in _ALLOWED_EVENT_FIELDS:
            return []
        group_fields = _group_fields(rule)
        if not group_fields:
            return []

        distinct_col = _safe_col(distinct_field)
        group_cols = [_safe_col(f) for f in group_fields]
        filters = _build_match_filters(match, since, until)
        filters.append(distinct_col.is_not(None))

        stmt = (
            select(
                *[c.label(f) for c, f in zip(group_cols, group_fields, strict=False)],
                func.count(func.distinct(distinct_col)).label("distinct_count"),
                func.count().label("event_count"),
            )
            .where(and_(*filters))
            .group_by(*group_cols)
        )
        rows = db.execute(stmt).all()
        base = _base_extra(
            rule, agg_type="cardinality", group_fields=group_fields, condition=condition, min_events=min_events, since=since, until=until
        )

        out: list[AlertCandidate] = []
        for row in rows:
            group_key = {f: row._mapping.get(f) for f in group_fields}
            distinct_count = int(row.distinct_count)
            event_count = int(row.event_count)
            extra = dict(base)
            extra["distinct_field"] = distinct_field
            extra["distinct_count"] = distinct_count
            extra["event_count"] = event_count
            out.append(
                AlertCandidate(
                    rule_id=rule_id,
                    rule=rule,
                    group_key=group_key,
                    match_hints=match,
                    count_value=distinct_count,
                    min_events_check=event_count,
                    since=since,
                    until=until,
                    extra=extra,
                )
            )
        return out

    def _run_multi_distinct(
        self, rule: dict[str, Any], *, db: Session, since: datetime, until: datetime
    ) -> list[AlertCandidate]:
        rule_id = str(rule.get("id") or "")
        match = rule.get("match") or {}
        condition = rule.get("condition", {}) or {}
        min_events = int(rule.get("min_events") or condition.get("min_events") or 0)

        group_fields = _group_fields(rule)
        if not group_fields:
            return []

        distinct_conditions = rule.get("distinct_conditions") or []
        if not isinstance(distinct_conditions, list) or len(distinct_conditions) == 0:
            return []
        dcs = [
            dc
            for dc in distinct_conditions
            if isinstance(dc, dict) and isinstance(dc.get("field"), str) and dc.get("field") in _ALLOWED_EVENT_FIELDS
        ]
        if not dcs:
            return []

        group_cols = [_safe_col(f) for f in group_fields]
        filters = _build_match_filters(match, since, until)
        sel = [c.label(f) for c, f in zip(group_cols, group_fields, strict=False)]
        sel.append(func.count().label("event_count"))
        for i, dc in enumerate(dcs):
            sel.append(func.count(func.distinct(_safe_col(dc.get("field")))).label(f"d{i}"))

        stmt = select(*sel).where(and_(*filters)).group_by(*group_cols)
        rows = db.execute(stmt).all()
        base = _base_extra(
            rule, agg_type="multi_cardinality", group_fields=group_fields, condition=condition, min_events=min_events, since=since, until=until
        )

        out: list[AlertCandidate] = []
        for row in rows:
            group_key = {f: row._mapping.get(f) for f in group_fields}
            event_count = int(row.event_count)

            distinct_results: dict[str, int] = {}
            ok = True
            for i, dc in enumerate(dcs):
                value = int(row._mapping.get(f"d{i}") or 0)
                distinct_results[dc.get("field")] = value
                if not _evaluate_condition(value, dc):
                    ok = False
                    break
            if not ok:
                continue

            extra = dict(base)
            extra["event_count"] = event_count
            extra["distinct_results"] = distinct_results
            out.append(
                AlertCandidate(
                    rule_id=rule_id,
                    rule=rule,
                    group_key=group_key,
                    match_hints=match,
                    count_value=event_count,
                    min_events_check=event_count,
                    since=since,
                    until=until,
                    extra=extra,
                )
            )
        return out
