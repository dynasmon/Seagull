from __future__ import annotations

from typing import Any

from app.features.correlations.engines.base import (
    BaseCorrelationEngine,
    CorrelationDataset,
    CorrelationMatch,
    build_evidence_item,
    dedupe_alert_rows,
    match_any,
    norm_patterns,
    passes_filter,
    record_timestamp,
    resolve_entity,
    segment_by_window,
    severity_score,
    summarize_timedelta_seconds,
)


def _stage_id(stage: dict[str, Any], index: int) -> str:
    raw = str(stage.get("id") or "").strip()
    if raw:
        return raw
    name = str(stage.get("name") or f"stage_{index + 1}").strip().lower().replace(" ", "_")
    return name or f"stage_{index + 1}"


def _normalize_stage(stage: dict[str, Any], index: int, *, compatibility_mode: bool, window_seconds: int, previous_stage_id: str | None) -> dict[str, Any]:
    include = norm_patterns(stage.get("include_patterns") or [])
    if not include:
        include = norm_patterns(stage.get("patterns") or [])

    return {
        "id": _stage_id(stage, index),
        "name": str(stage.get("name") or f"Stage {index + 1}").strip() or f"Stage {index + 1}",
        "include_patterns": include,
        "exclude_patterns": norm_patterns(stage.get("exclude_patterns") or []),
        "min_count": max(1, int(stage.get("min_count") or 1)),
        "after": str(stage.get("after") or previous_stage_id or "").strip() or None,
        "within_seconds": int(stage.get("within_seconds") or window_seconds or 0) or None,
        "required": bool(stage.get("required", True)) if not compatibility_mode else True,
        "maxspan_seconds": int(stage.get("maxspan_seconds") or window_seconds or 0) or None,
    }


def _alert_matches_stage(alert: Any, stage: dict[str, Any]) -> bool:
    include = list(stage.get("include_patterns") or [])
    exclude = list(stage.get("exclude_patterns") or [])
    return passes_filter(str(getattr(alert, "rule_id", "") or ""), include, exclude)


def _select_stage_slice(rows: list[Any], stage: dict[str, Any], *, dataset: CorrelationDataset, anchor_end: Any) -> list[Any]:
    selected: list[Any] = []
    min_count = max(1, int(stage.get("min_count") or 1))
    maxspan_seconds = int(stage.get("maxspan_seconds") or 0) or None
    within_seconds = int(stage.get("within_seconds") or 0) or None
    anchor_ts = record_timestamp(anchor_end, "alerts", dataset) if anchor_end is not None else None

    candidates: list[Any] = []
    for row in rows:
        if not _alert_matches_stage(row, stage):
            continue
        row_ts = record_timestamp(row, "alerts", dataset)
        if anchor_ts is not None and row_ts < anchor_ts:
            continue
        if anchor_ts is not None and within_seconds is not None and (row_ts - anchor_ts).total_seconds() > within_seconds:
            continue
        candidates.append(row)

    for idx, row in enumerate(candidates):
        window = candidates[idx:idx + min_count]
        if len(window) < min_count:
            break
        if maxspan_seconds is not None:
            span = (record_timestamp(window[-1], "alerts", dataset) - record_timestamp(window[0], "alerts", dataset)).total_seconds()
            if span > maxspan_seconds:
                continue
        selected = window
        break
    return selected


class SequenceEngine(BaseCorrelationEngine):
    strategy_names = ("sequence", "chain")

    def __init__(self, *, compatibility_mode: bool = False) -> None:
        self.compatibility_mode = compatibility_mode

    def build(self, *, rule: Any, dataset: CorrelationDataset, sample_limit: int) -> list[CorrelationMatch]:
        alerts = [
            alert
            for alert in dataset.alerts
            if passes_filter(
                str(getattr(alert, "rule_id", "") or ""),
                norm_patterns(getattr(rule, "include_patterns", None) or []),
                norm_patterns(getattr(rule, "exclude_patterns", None) or []),
            )
        ]
        stages_raw = list(getattr(rule, "stages", None) or [])
        if not stages_raw:
            return []

        stages: list[dict[str, Any]] = []
        previous_stage_id: str | None = None
        window_seconds = int(getattr(rule, "window_seconds", 600) or 600)
        for idx, raw in enumerate(stages_raw):
            stage = _normalize_stage(
                dict(raw or {}),
                idx,
                compatibility_mode=self.compatibility_mode,
                window_seconds=window_seconds,
                previous_stage_id=previous_stage_id,
            )
            stages.append(stage)
            previous_stage_id = stage["id"]

        grouped: dict[tuple[str, str, str, str], list[Any]] = {}
        for alert in alerts:
            group_by, group_value, entity_type, entity_value = resolve_entity(rule, alert, "alerts", dataset)
            grouped.setdefault((group_by, group_value, entity_type, entity_value), []).append(alert)

        out: list[CorrelationMatch] = []
        for (group_by, group_value, entity_type, entity_value), rows in grouped.items():
            segments = segment_by_window(rows, window_seconds)
            matched_segment: list[Any] = []
            selected_stages: dict[str, list[Any]] = {}
            stage_hits: dict[str, int] = {}

            for segment in segments:
                anchor_map: dict[str, Any] = {}
                chosen: dict[str, list[Any]] = {}
                hits = {
                    str(stage.get("name")): sum(1 for alert in segment if _alert_matches_stage(alert, stage))
                    for stage in stages
                }

                valid = True
                for stage in stages:
                    after_id = stage.get("after")
                    anchor = None
                    if after_id:
                        prior = chosen.get(str(after_id))
                        if prior:
                            anchor = prior[-1]
                        elif stage.get("required", True):
                            valid = False
                            break
                    stage_slice = _select_stage_slice(segment, stage, dataset=dataset, anchor_end=anchor)
                    if not stage_slice:
                        if stage.get("required", True):
                            valid = False
                            break
                        continue
                    chosen[str(stage["id"])] = stage_slice
                    anchor_map[str(stage["id"])] = stage_slice[-1]

                if not valid:
                    continue
                if not chosen:
                    continue
                matched_segment = segment
                selected_stages = chosen
                stage_hits = hits

            if not matched_segment or not selected_stages:
                continue

            selected_alerts: list[Any] = []
            for rows_for_stage in selected_stages.values():
                selected_alerts.extend(rows_for_stage)
            selected_alerts = sorted(
                {int(getattr(alert, "id", idx)): alert for idx, alert in enumerate(selected_alerts)}.values(),
                key=lambda alert: record_timestamp(alert, "alerts", dataset),
            )
            started_at = record_timestamp(selected_alerts[0], "alerts", dataset)
            ended_at = record_timestamp(selected_alerts[-1], "alerts", dataset)
            sample_rows = dedupe_alert_rows(selected_alerts, sample_limit)
            evidence = []
            for stage in stages:
                for alert in selected_stages.get(str(stage["id"]), []):
                    evidence.append(
                        build_evidence_item(
                            record=alert,
                            source="alerts",
                            dataset=dataset,
                            stage=str(stage.get("name") or stage["id"]),
                        )
                    )

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
                    alert_count=len(selected_alerts),
                    unique_rules=sorted({str(alert.rule_id) for alert in selected_alerts if str(getattr(alert, "rule_id", "") or "").strip()}),
                    stage_hits=stage_hits,
                    risk_score=min(100, severity_score(getattr(rule, "severity", "high")) + len(selected_stages) * 5),
                    confidence=min(99, 62 + min(30, len(selected_stages) * 8)),
                    summary=(
                        f"Ordered sequence for {entity_type} {group_value} matched {len(selected_stages)} stages "
                        f"within {summarize_timedelta_seconds(window_seconds)}."
                    ),
                    context={
                        "strategy": "chain" if self.compatibility_mode else "sequence",
                        "window_seconds": window_seconds,
                        "stages": [
                            {
                                "id": stage["id"],
                                "name": stage["name"],
                                "after": stage["after"],
                                "within_seconds": stage["within_seconds"],
                                "required": stage["required"],
                                "maxspan_seconds": stage["maxspan_seconds"],
                            }
                            for stage in stages
                        ],
                    },
                    sample_alert_rows=sample_rows,
                    evidence_items=evidence,
                )
            )

        return out
