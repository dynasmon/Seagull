from __future__ import annotations

from collections import defaultdict
from typing import Any

from app.features.correlations.engines.base import (
    BaseCorrelationEngine,
    CorrelationDataset,
    CorrelationMatch,
    build_evidence_item,
    dedupe_alert_rows,
    extract_alert_value,
    filter_records,
    record_timestamp,
    resolve_entity,
    to_utc_naive,
    severity_score,
    summarize_timedelta_seconds,
)


def _alert_rule_risk_score(alert: Any) -> int:
    details = getattr(alert, "details", {}) or {}
    for candidate in (
        details.get("risk_score"),
        (details.get("rule_meta") or {}).get("risk_score"),
        (details.get("rule") or {}).get("risk_score"),
    ):
        try:
            if candidate is not None:
                return max(0, min(100, int(candidate)))
        except Exception:
            continue
    return severity_score(getattr(alert, "severity", None))


def _tactic_weight(tactic: str | None, weights: dict[str, Any]) -> float:
    if not tactic:
        return 1.0
    try:
        return max(0.1, float(weights.get(str(tactic).lower(), 1.0)))
    except Exception:
        return 1.0


def _score_window(rows: list[Any], cfg: dict[str, Any]) -> tuple[int, dict[str, Any], list[Any]]:
    dedup_fields = [str(item) for item in list(cfg.get("dedup_fields") or ["rule_id", "src_ip", "dst_ip", "dst_port"])]
    rule_caps = cfg.get("rule_caps") if isinstance(cfg.get("rule_caps"), dict) else {}
    default_rule_cap = int(cfg.get("default_rule_cap") or 100)
    tactic_weights = cfg.get("tactic_weights") if isinstance(cfg.get("tactic_weights"), dict) else {}

    per_dedup: dict[str, tuple[int, Any]] = {}
    for alert in rows:
        dedup_key = "|".join(str(extract_alert_value(alert, field) or "-") for field in dedup_fields)
        rule_id = str(getattr(alert, "rule_id", "") or "")
        base_score = _alert_rule_risk_score(alert)
        confidence = max(0, min(100, int(getattr(alert, "confidence", 50) or 50)))
        tactic = str(getattr(alert, "mitre_tactic", "") or "").strip().lower() or None
        weighted = int(round(base_score * (confidence / 100.0) * _tactic_weight(tactic, tactic_weights)))
        previous = per_dedup.get(dedup_key)
        if previous is None or weighted > previous[0]:
            per_dedup[dedup_key] = (weighted, alert)

    rule_totals: dict[str, int] = defaultdict(int)
    total = 0
    selected: list[Any] = []
    contributions: list[dict[str, Any]] = []
    ordered = sorted(per_dedup.values(), key=lambda item: to_utc_naive(getattr(item[1], "created_at")))

    for weighted, alert in ordered:
        rule_id = str(getattr(alert, "rule_id", "") or "")
        cap = int(rule_caps.get(rule_id, default_rule_cap) or default_rule_cap)
        if cap <= rule_totals[rule_id]:
            continue
        applied = min(weighted, max(0, cap - rule_totals[rule_id]))
        if applied <= 0:
            continue
        rule_totals[rule_id] += applied
        total += applied
        selected.append(alert)
        contributions.append(
            {
                "rule_id": rule_id,
                "applied_score": applied,
                "base_score": _alert_rule_risk_score(alert),
                "confidence": int(getattr(alert, "confidence", 50) or 50),
                "mitre_tactic": getattr(alert, "mitre_tactic", None),
            }
        )

    return min(100, total), {"contributions": contributions, "deduped_alerts": len(per_dedup), "rule_caps": rule_caps}, selected


class RiskAggregationEngine(BaseCorrelationEngine):
    strategy_names = ("risk_aggregation",)

    def build(self, *, rule: Any, dataset: CorrelationDataset, sample_limit: int) -> list[CorrelationMatch]:
        cfg = getattr(rule, "risk_config", None) or {}
        threshold = int(cfg.get("threshold") or cfg.get("min_risk_score") or 70)
        window_seconds = int(cfg.get("window_seconds") or getattr(rule, "window_seconds", 900) or 900)
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
        for (group_by, group_value, entity_type, entity_value), rows in grouped.items():
            ordered = sorted(rows, key=lambda row: record_timestamp(row, "alerts", dataset))
            best_rows: list[Any] = []
            best_score = 0
            best_context: dict[str, Any] = {}
            left = 0

            for right, alert in enumerate(ordered):
                right_ts = record_timestamp(alert, "alerts", dataset)
                while left <= right:
                    left_ts = record_timestamp(ordered[left], "alerts", dataset)
                    if (right_ts - left_ts).total_seconds() <= window_seconds:
                        break
                    left += 1
                current = ordered[left:right + 1]
                score, context, selected = _score_window(current, cfg)
                if score >= threshold:
                    best_rows = selected
                    best_score = score
                    best_context = context

            if not best_rows:
                continue

            started_at = record_timestamp(best_rows[0], "alerts", dataset)
            ended_at = record_timestamp(best_rows[-1], "alerts", dataset)
            avg_conf = int(round(sum(int(getattr(row, "confidence", 50) or 50) for row in best_rows) / max(1, len(best_rows))))
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
                    alert_count=len(best_rows),
                    unique_rules=sorted({str(row.rule_id) for row in best_rows if str(getattr(row, "rule_id", "") or "").strip()}),
                    risk_score=best_score,
                    confidence=avg_conf,
                    summary=(
                        f"Aggregated entity risk for {entity_type} {group_value} reached {best_score} "
                        f"within {summarize_timedelta_seconds(window_seconds)}."
                    ),
                    context={
                        "strategy": "risk_aggregation",
                        "threshold": threshold,
                        "window_seconds": window_seconds,
                        **best_context,
                    },
                    sample_alert_rows=dedupe_alert_rows(best_rows, sample_limit),
                    evidence_items=[build_evidence_item(record=row, source="alerts", dataset=dataset) for row in best_rows],
                )
            )

        return out
