from __future__ import annotations

from collections import Counter
from typing import Any

from app.features.correlations.engines.base import (
    BaseCorrelationEngine,
    CorrelationDataset,
    CorrelationMatch,
    build_evidence_item,
    dedupe_alert_rows,
    extract_source_value,
    filter_records,
    record_timestamp,
    resolve_entity,
    select_records,
    severity_score,
    summarize_timedelta_seconds,
)


def _latest_cardinality_window(
    rows: list[Any],
    *,
    source: str,
    dataset: CorrelationDataset,
    value_field: str,
    window_seconds: int,
    threshold: int,
    min_alerts: int,
) -> tuple[list[Any], int, list[str]]:
    if not rows:
        return [], 0, []

    ordered = sorted(rows, key=lambda row: record_timestamp(row, source, dataset))
    left = 0
    counts: Counter[str] = Counter()
    best_rows: list[Any] = []
    best_values: list[str] = []
    best_distinct = 0
    window = max(1, int(window_seconds))
    min_count = max(1, int(min_alerts))
    distinct_threshold = max(1, int(threshold))

    for right, row in enumerate(ordered):
        right_ts = record_timestamp(row, source, dataset)
        value = str(extract_source_value(row, value_field, source, dataset) or "").strip()
        if value:
            counts[value] += 1

        while left <= right:
            left_ts = record_timestamp(ordered[left], source, dataset)
            if (right_ts - left_ts).total_seconds() <= window:
                break
            left_value = str(extract_source_value(ordered[left], value_field, source, dataset) or "").strip()
            if left_value:
                counts[left_value] -= 1
                if counts[left_value] <= 0:
                    counts.pop(left_value, None)
            left += 1

        current_rows = ordered[left:right + 1]
        distinct_values = sorted(counts.keys())
        if len(current_rows) >= min_count and len(distinct_values) >= distinct_threshold:
            best_rows = current_rows
            best_values = distinct_values
            best_distinct = len(distinct_values)

    return best_rows, best_distinct, best_values


class CardinalityEngine(BaseCorrelationEngine):
    strategy_names = ("cardinality",)

    def build(self, *, rule: Any, dataset: CorrelationDataset, sample_limit: int) -> list[CorrelationMatch]:
        cfg = getattr(rule, "strategy_config", None) or {}
        source = str(cfg.get("source") or "alerts").strip().lower()
        value_field = str(cfg.get("field") or cfg.get("distinct_field") or "dst_ip").strip()
        threshold = int(cfg.get("threshold") or getattr(rule, "min_alerts", 2) or 2)
        source_records = select_records(dataset, source)
        filtered = filter_records(
            records=source_records,
            source=source,
            dataset=dataset,
            include_patterns=getattr(rule, "include_patterns", None) or [],
            exclude_patterns=getattr(rule, "exclude_patterns", None) or [],
            field_filters=cfg.get("field_filters") or [],
        )

        grouped: dict[tuple[str, str, str, str], list[Any]] = {}
        for record in filtered:
            group_by, group_value, entity_type, entity_value = resolve_entity(rule, record, source, dataset)
            grouped.setdefault((group_by, group_value, entity_type, entity_value), []).append(record)

        out: list[CorrelationMatch] = []
        window_seconds = int(getattr(rule, "window_seconds", 600) or 600)
        min_alerts = int(getattr(rule, "min_alerts", 2) or 2)

        for (group_by, group_value, entity_type, entity_value), rows in grouped.items():
            selected, distinct_count, distinct_values = _latest_cardinality_window(
                rows,
                source=source,
                dataset=dataset,
                value_field=value_field,
                window_seconds=window_seconds,
                threshold=threshold,
                min_alerts=min_alerts,
            )
            if not selected:
                continue

            started_at = record_timestamp(selected[0], source, dataset)
            ended_at = record_timestamp(selected[-1], source, dataset)
            sample_alert_rows = dedupe_alert_rows([row for row in selected if hasattr(row, "rule_id")], sample_limit) if source == "alerts" else []

            evidence = [build_evidence_item(record=row, source=source, dataset=dataset) for row in selected]
            out.append(
                CorrelationMatch(
                    correlation_rule_id=int(rule.id),
                    correlation_rule_name=str(rule.name),
                    severity=str(getattr(rule, "severity", "high") or "high"),
                    group_by=group_by,
                    group_value=group_value,
                    entity_type=entity_type,
                    entity_value=entity_value,
                    started_at=started_at,
                    ended_at=ended_at,
                    alert_count=len(selected) if source == "alerts" else max(len(selected), distinct_count),
                    unique_rules=sorted({
                        str(getattr(row, "rule_id", "") or "")
                        for row in selected
                        if str(getattr(row, "rule_id", "") or "").strip()
                    }),
                    risk_score=min(100, severity_score(getattr(rule, "severity", "high")) + distinct_count * 4),
                    confidence=min(99, 58 + min(34, distinct_count * 5)),
                    summary=(
                        f"{entity_type} {group_value} touched {distinct_count} distinct {value_field} values "
                        f"within {summarize_timedelta_seconds(window_seconds)}."
                    ),
                    context={
                        "strategy": "cardinality",
                        "source": source,
                        "value_field": value_field,
                        "distinct_count": distinct_count,
                        "distinct_values": distinct_values[:25],
                        "window_seconds": window_seconds,
                        "threshold": threshold,
                    },
                    sample_alert_rows=sample_alert_rows,
                    evidence_items=evidence,
                )
            )

        return out
