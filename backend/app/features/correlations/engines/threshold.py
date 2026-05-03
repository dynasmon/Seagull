from __future__ import annotations

from typing import Any

from app.features.correlations.engines.base import (
    BaseCorrelationEngine,
    CorrelationMatch,
    CorrelationDataset,
    build_evidence_item,
    dedupe_alert_rows,
    filter_records,
    record_timestamp,
    resolve_entity,
    segment_by_window,
    severity_score,
    summarize_timedelta_seconds,
)


def _latest_rolling_alert_window(rows: list[Any], *, dataset: CorrelationDataset, window_seconds: int, min_alerts: int) -> list[Any]:
    if not rows:
        return []

    ordered = sorted(rows, key=lambda row: record_timestamp(row, "alerts", dataset))
    best: list[Any] = []
    left = 0
    window = max(1, int(window_seconds))
    threshold = max(1, int(min_alerts))

    for right, row in enumerate(ordered):
        right_ts = record_timestamp(row, "alerts", dataset)
        while left <= right:
            left_ts = record_timestamp(ordered[left], "alerts", dataset)
            if (right_ts - left_ts).total_seconds() <= window:
                break
            left += 1
        current = ordered[left:right + 1]
        if len(current) >= threshold:
            best = current
    return best


class ThresholdEngine(BaseCorrelationEngine):
    strategy_names = ("threshold", "burst")

    def __init__(self, *, compatibility_mode: bool = False) -> None:
        self.compatibility_mode = compatibility_mode

    def build(self, *, rule: Any, dataset: CorrelationDataset, sample_limit: int) -> list[CorrelationMatch]:
        filtered = filter_records(
            records=dataset.alerts,
            source="alerts",
            dataset=dataset,
            include_patterns=getattr(rule, "include_patterns", None) or [],
            exclude_patterns=getattr(rule, "exclude_patterns", None) or [],
            field_filters=((getattr(rule, "strategy_config", None) or {}).get("field_filters") or []),
        )
        grouped: dict[tuple[str, str, str, str], list[Any]] = {}

        for alert in filtered:
            group_by, group_value, entity_type, entity_value = resolve_entity(rule, alert, "alerts", dataset)
            grouped.setdefault((group_by, group_value, entity_type, entity_value), []).append(alert)

        out: list[CorrelationMatch] = []
        window_seconds = int(getattr(rule, "window_seconds", 600) or 600)
        min_alerts = int(getattr(rule, "min_alerts", 2) or 2)

        for (group_by, group_value, entity_type, entity_value), rows in grouped.items():
            if self.compatibility_mode:
                segments = [seg for seg in segment_by_window(rows, window_seconds) if len(seg) >= min_alerts]
                selected = segments[-1] if segments else []
            else:
                selected = _latest_rolling_alert_window(
                    rows,
                    dataset=dataset,
                    window_seconds=window_seconds,
                    min_alerts=min_alerts,
                )
            if len(selected) < min_alerts:
                continue

            started_at = record_timestamp(selected[0], "alerts", dataset)
            ended_at = record_timestamp(selected[-1], "alerts", dataset)
            sample_rows = dedupe_alert_rows(selected, sample_limit)
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
                    alert_count=len(selected),
                    unique_rules=sorted({str(alert.rule_id) for alert in selected if str(getattr(alert, "rule_id", "") or "").strip()}),
                    risk_score=min(100, severity_score(getattr(rule, "severity", "high")) + max(0, len(selected) - min_alerts) * 3),
                    confidence=min(99, 55 + min(35, len(selected) * 4)),
                    summary=(
                        f"{len(selected)} matching alerts for {entity_type} {group_value} "
                        f"within {summarize_timedelta_seconds(window_seconds)}."
                    ),
                    context={
                        "strategy": "burst" if self.compatibility_mode else "threshold",
                        "window_seconds": window_seconds,
                        "min_alerts": min_alerts,
                    },
                    sample_alert_rows=sample_rows,
                    evidence_items=[build_evidence_item(record=alert, source="alerts", dataset=dataset) for alert in selected],
                )
            )

        return out
