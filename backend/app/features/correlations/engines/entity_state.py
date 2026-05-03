from __future__ import annotations

from collections import defaultdict
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


def _latest_window(rows: list[Any], *, source: str, dataset: CorrelationDataset, window_seconds: int, min_items: int) -> list[Any]:
    if not rows:
        return []
    ordered = sorted(rows, key=lambda row: record_timestamp(row, source, dataset))
    left = 0
    best: list[Any] = []
    for right, row in enumerate(ordered):
        right_ts = record_timestamp(row, source, dataset)
        while left <= right:
            left_ts = record_timestamp(ordered[left], source, dataset)
            if (right_ts - left_ts).total_seconds() <= max(1, int(window_seconds)):
                break
            left += 1
        current = ordered[left:right + 1]
        if len(current) >= max(1, int(min_items)):
            best = current
    return best


class NewEntityEngine(BaseCorrelationEngine):
    strategy_names = ("new_entity",)

    def build(self, *, rule: Any, dataset: CorrelationDataset, sample_limit: int) -> list[CorrelationMatch]:
        cfg = getattr(rule, "strategy_config", None) or {}
        source = str(cfg.get("source") or "alerts").strip().lower()
        long_absent_seconds = int(cfg.get("long_absent_seconds") or cfg.get("absent_seconds") or 0)
        window_seconds = int(getattr(rule, "window_seconds", 600) or 600)
        min_alerts = int(getattr(rule, "min_alerts", 1) or 1)

        filtered = filter_records(
            records=select_records(dataset, source),
            source=source,
            dataset=dataset,
            include_patterns=getattr(rule, "include_patterns", None) or [],
            exclude_patterns=getattr(rule, "exclude_patterns", None) or [],
            field_filters=cfg.get("field_filters") or [],
        )

        grouped: dict[tuple[str, str, str, str], list[Any]] = defaultdict(list)
        for record in filtered:
            group_by, group_value, entity_type, entity_value = resolve_entity(rule, record, source, dataset)
            grouped[(group_by, group_value, entity_type, entity_value)].append(record)

        out: list[CorrelationMatch] = []
        for (group_by, group_value, entity_type, entity_value), rows in grouped.items():
            selected = _latest_window(rows, source=source, dataset=dataset, window_seconds=window_seconds, min_items=min_alerts)
            if not selected:
                continue

            state = dataset.entity_state_for(entity_type, entity_value)
            latest_ts = record_timestamp(selected[-1], source, dataset)
            reason = None
            if state is None:
                reason = "first_seen"
            elif long_absent_seconds > 0:
                last_seen_at = getattr(state, "last_seen_at", None)
                if last_seen_at is not None:
                    gap_seconds = int((latest_ts - last_seen_at).total_seconds())
                    if gap_seconds >= long_absent_seconds:
                        reason = "long_absent"
            if reason is None:
                continue

            alert_rows = [row for row in selected if hasattr(row, "rule_id")]
            summary = (
                f"Entity {entity_value} is first seen in correlation scope."
                if reason == "first_seen"
                else f"Entity {entity_value} reappeared after {summarize_timedelta_seconds(long_absent_seconds)} of inactivity."
            )
            out.append(
                CorrelationMatch(
                    correlation_rule_id=int(rule.id),
                    correlation_rule_name=str(rule.name),
                    severity=str(getattr(rule, "severity", "medium") or "medium"),
                    group_by=group_by,
                    group_value=group_value,
                    entity_type=entity_type,
                    entity_value=entity_value,
                    started_at=record_timestamp(selected[0], source, dataset),
                    ended_at=latest_ts,
                    alert_count=len(alert_rows) if alert_rows else len(selected),
                    unique_rules=sorted({
                        str(getattr(row, "rule_id", "") or "")
                        for row in alert_rows
                        if str(getattr(row, "rule_id", "") or "").strip()
                    }),
                    risk_score=min(100, severity_score(getattr(rule, "severity", "medium")) + (20 if reason == "first_seen" else 28)),
                    confidence=74 if reason == "first_seen" else 80,
                    summary=summary,
                    context={
                        "strategy": "new_entity",
                        "source": source,
                        "reason": reason,
                        "long_absent_seconds": long_absent_seconds,
                        "previous_last_seen_at": getattr(state, "last_seen_at", None).isoformat() if state and getattr(state, "last_seen_at", None) else None,
                    },
                    sample_alert_rows=dedupe_alert_rows(alert_rows, sample_limit) if alert_rows else [],
                    evidence_items=[build_evidence_item(record=row, source=source, dataset=dataset) for row in selected],
                )
            )

        return out


class RareEntityEngine(BaseCorrelationEngine):
    strategy_names = ("rare_entity",)

    def build(self, *, rule: Any, dataset: CorrelationDataset, sample_limit: int) -> list[CorrelationMatch]:
        cfg = getattr(rule, "strategy_config", None) or {}
        source = str(cfg.get("source") or "alerts").strip().lower()
        scope_field = str(cfg.get("scope_field") or "").strip()
        target_field = str(cfg.get("target_field") or cfg.get("field") or getattr(rule, "group_by", "dst_ip")).strip()
        max_occurrences = max(1, int(cfg.get("max_occurrences") or 1))
        min_baseline_observations = max(1, int(cfg.get("min_baseline_observations") or 25))
        min_distinct_values = max(1, int(cfg.get("min_distinct_values") or 8))
        window_seconds = int(cfg.get("baseline_window_seconds") or getattr(rule, "window_seconds", 3600) or 3600)
        min_alerts = int(getattr(rule, "min_alerts", 1) or 1)

        filtered = filter_records(
            records=select_records(dataset, source),
            source=source,
            dataset=dataset,
            include_patterns=getattr(rule, "include_patterns", None) or [],
            exclude_patterns=getattr(rule, "exclude_patterns", None) or [],
            field_filters=cfg.get("field_filters") or [],
        )

        buckets: dict[str, list[Any]] = defaultdict(list)
        for record in filtered:
            scope_value = str(extract_source_value(record, scope_field, source, dataset) or "__global__").strip() or "__global__"
            buckets[scope_value].append(record)

        out: list[CorrelationMatch] = []
        for scope_value, rows in buckets.items():
            window_rows = _latest_window(rows, source=source, dataset=dataset, window_seconds=window_seconds, min_items=min_alerts)
            if len(window_rows) < min_baseline_observations:
                continue

            value_to_rows: dict[str, list[Any]] = defaultdict(list)
            for record in window_rows:
                target_value = str(extract_source_value(record, target_field, source, dataset) or "").strip()
                if not target_value:
                    continue
                value_to_rows[target_value].append(record)

            if len(value_to_rows) < min_distinct_values:
                continue

            for target_value, target_rows in value_to_rows.items():
                if len(target_rows) > max_occurrences:
                    continue
                representative = target_rows[-1]
                group_by, group_value, entity_type, entity_value = resolve_entity(rule, representative, source, dataset)
                if group_value == "-" and scope_field:
                    group_value = f"{scope_value} | {target_value}"
                    entity_value = group_value

                alert_rows = [row for row in target_rows if hasattr(row, "rule_id")]
                out.append(
                    CorrelationMatch(
                        correlation_rule_id=int(rule.id),
                        correlation_rule_name=str(rule.name),
                        severity=str(getattr(rule, "severity", "medium") or "medium"),
                        group_by=group_by,
                        group_value=group_value,
                        entity_type=entity_type,
                        entity_value=entity_value,
                        started_at=record_timestamp(target_rows[0], source, dataset),
                        ended_at=record_timestamp(target_rows[-1], source, dataset),
                        alert_count=len(alert_rows) if alert_rows else len(target_rows),
                        unique_rules=sorted({
                            str(getattr(row, "rule_id", "") or "")
                            for row in alert_rows
                            if str(getattr(row, "rule_id", "") or "").strip()
                        }),
                        risk_score=min(100, severity_score(getattr(rule, "severity", "medium")) + 18),
                        confidence=76,
                        summary=(
                            f"Rare {target_field} value {target_value} observed within scope {scope_value}. "
                            f"Only {len(target_rows)} occurrence(s) in {len(window_rows)} observations."
                        ),
                        context={
                            "strategy": "rare_entity",
                            "source": source,
                            "scope_field": scope_field,
                            "scope_value": scope_value,
                            "target_field": target_field,
                            "target_value": target_value,
                            "observed_count": len(target_rows),
                            "baseline_observations": len(window_rows),
                            "distinct_values": len(value_to_rows),
                            "max_occurrences": max_occurrences,
                            "baseline_window_seconds": window_seconds,
                        },
                        sample_alert_rows=dedupe_alert_rows(alert_rows, sample_limit) if alert_rows else [],
                        evidence_items=[build_evidence_item(record=row, source=source, dataset=dataset) for row in target_rows],
                    )
                )

        return out
