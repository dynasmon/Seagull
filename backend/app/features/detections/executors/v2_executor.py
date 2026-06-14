from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from app.features.detections.domain.condition_ast import DetectionBlock
from app.features.detections.pipeline.types import AlertCandidate
from app.features.detections.rules.compiler import (
    _v2_mitre_meta,
    _v2_resolve_params,
    _v2_suppressions,
    compile_detection_filters,
)
from app.workers.intelligence.rules.conditions import _ALLOWED_EVENT_FIELDS, _evaluate_condition, _safe_col
from app.workers.intelligence.rules.health import _content_hash


class V2RuleExecutor:
    def can_execute(self, rule: dict[str, Any]) -> bool:
        return int(rule.get("schema_version") or 1) == 2

    def execute(
        self, rule: dict[str, Any], *, db: Session, since: datetime, until: datetime
    ) -> list[AlertCandidate]:
        detection = rule.get("detection")
        if not isinstance(detection, DetectionBlock):
            return []

        agg = rule.get("aggregation") or {}
        agg_type = str(agg.get("type") or "").strip().lower()
        if agg_type not in ("threshold", "cardinality", "multi_cardinality"):
            return []

        rule_id = str(rule.get("id") or "").strip()
        if not rule_id:
            return []

        window, cooldown, base_condition, base_min_events, severity = _v2_resolve_params(rule)

        try:
            filters = compile_detection_filters(detection, since, until)
        except Exception:
            return []

        group_by_raw = agg.get("group_by")
        group_fields = (
            group_by_raw if isinstance(group_by_raw, list)
            else [group_by_raw] if isinstance(group_by_raw, str)
            else []
        )
        group_fields = [f for f in group_fields if isinstance(f, str) and f in _ALLOWED_EVENT_FIELDS]
        if not group_fields:
            return []

        group_cols = [_safe_col(f) for f in group_fields]

        logsource = rule.get("logsource") or {}
        match_hints: dict[str, Any] = {}
        if logsource.get("event_type"):
            match_hints["event_type"] = logsource["event_type"]

        base = {
            "schema_version": 2,
            "agg_type": agg_type,
            "group_by": group_fields,
            "severity": severity,
            "base_condition": base_condition,
            "base_min_events": int(base_min_events),
            "base_cooldown_seconds": int(cooldown.total_seconds()),
            "window_seconds": int((until - since).total_seconds()),
            "mitre": _v2_mitre_meta(rule),
            "description": str(rule.get("description") or ""),
            "rule_hash": _content_hash(rule),
            "effective_suppressions": _v2_suppressions(rule),
        }

        def _candidate(group_key, *, count_value, min_events_check, extra_fields):
            extra = dict(base)
            extra.update(extra_fields)
            return AlertCandidate(
                rule_id=rule_id,
                rule=rule,
                group_key=group_key,
                match_hints=match_hints,
                count_value=count_value,
                min_events_check=min_events_check,
                since=since,
                until=until,
                extra=extra,
            )

        out: list[AlertCandidate] = []

        if agg_type == "threshold":
            stmt = (
                select(
                    *[c.label(f) for c, f in zip(group_cols, group_fields, strict=False)],
                    func.count().label("count"),
                )
                .where(and_(*filters))
                .group_by(*group_cols)
            )
            for row in db.execute(stmt).all():
                group_key = {f: row._mapping.get(f) for f in group_fields}
                count = int(row.count)
                out.append(_candidate(group_key, count_value=count, min_events_check=count, extra_fields={"count": count}))
            return out

        if agg_type == "cardinality":
            distinct_field = str(agg.get("field") or "").strip()
            if not distinct_field or distinct_field not in _ALLOWED_EVENT_FIELDS:
                return []
            distinct_col = _safe_col(distinct_field)
            card_filters = list(filters) + [distinct_col.is_not(None)]
            stmt = (
                select(
                    *[c.label(f) for c, f in zip(group_cols, group_fields, strict=False)],
                    func.count(func.distinct(distinct_col)).label("distinct_count"),
                    func.count().label("event_count"),
                )
                .where(and_(*card_filters))
                .group_by(*group_cols)
            )
            for row in db.execute(stmt).all():
                group_key = {f: row._mapping.get(f) for f in group_fields}
                distinct_count = int(row.distinct_count)
                event_count = int(row.event_count)
                out.append(
                    _candidate(
                        group_key,
                        count_value=distinct_count,
                        min_events_check=event_count,
                        extra_fields={
                            "distinct_field": distinct_field,
                            "distinct_count": distinct_count,
                            "event_count": event_count,
                        },
                    )
                )
            return out

        distinct_conditions_raw = agg.get("distinct_conditions") or []
        if not isinstance(distinct_conditions_raw, list) or not distinct_conditions_raw:
            return []
        dcs = [
            dc for dc in distinct_conditions_raw
            if isinstance(dc, dict) and isinstance(dc.get("field"), str) and dc["field"] in _ALLOWED_EVENT_FIELDS
        ]
        if not dcs:
            return []

        sel = [c.label(f) for c, f in zip(group_cols, group_fields, strict=False)]
        sel.append(func.count().label("event_count"))
        for i, dc in enumerate(dcs):
            sel.append(func.count(func.distinct(_safe_col(dc["field"]))).label(f"d{i}"))

        stmt = select(*sel).where(and_(*filters)).group_by(*group_cols)
        for row in db.execute(stmt).all():
            group_key = {f: row._mapping.get(f) for f in group_fields}
            event_count = int(row.event_count)
            distinct_results: dict[str, int] = {}
            ok = True
            for i, dc in enumerate(dcs):
                dc_value = int(row._mapping.get(f"d{i}") or 0)
                distinct_results[dc["field"]] = dc_value
                if not _evaluate_condition(dc_value, dc):
                    ok = False
                    break
            if not ok:
                continue
            out.append(
                _candidate(
                    group_key,
                    count_value=event_count,
                    min_events_check=event_count,
                    extra_fields={"event_count": event_count, "distinct_results": distinct_results},
                )
            )
        return out
