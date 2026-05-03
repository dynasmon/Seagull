from __future__ import annotations

from typing import Any

from app.features.correlations.engines.base import (
    BaseCorrelationEngine,
    CorrelationDataset,
    CorrelationMatch,
    build_evidence_item,
    dedupe_alert_rows,
    filter_records,
    record_timestamp,
    resolve_entity,
    select_records,
    severity_score,
    summarize_timedelta_seconds,
)


def _family_id(family: dict[str, Any], index: int) -> str:
    raw = str(family.get("id") or "").strip()
    if raw:
        return raw
    name = str(family.get("name") or f"family_{index + 1}").strip().lower().replace(" ", "_")
    return name or f"family_{index + 1}"


def _normalize_family(family: dict[str, Any], index: int, *, previous_family_id: str | None, window_seconds: int) -> dict[str, Any]:
    return {
        "id": _family_id(family, index),
        "name": str(family.get("name") or f"Family {index + 1}").strip() or f"Family {index + 1}",
        "source": str(family.get("source") or "alerts").strip().lower(),
        "include_patterns": list(family.get("include_patterns") or []),
        "exclude_patterns": list(family.get("exclude_patterns") or []),
        "field_filters": list(family.get("field_filters") or []),
        "min_count": max(1, int(family.get("min_count") or 1)),
        "after": str(family.get("after") or previous_family_id or "").strip() or None,
        "within_seconds": int(family.get("within_seconds") or window_seconds or 0) or None,
        "required": bool(family.get("required", True)),
        "maxspan_seconds": int(family.get("maxspan_seconds") or window_seconds or 0) or None,
    }


def _select_family_slice(
    rows: list[Any],
    *,
    source: str,
    dataset: CorrelationDataset,
    family: dict[str, Any],
    anchor_ts: Any,
) -> list[Any]:
    selected: list[Any] = []
    min_count = max(1, int(family.get("min_count") or 1))
    maxspan_seconds = int(family.get("maxspan_seconds") or 0) or None
    within_seconds = int(family.get("within_seconds") or 0) or None

    candidates: list[Any] = []
    for row in rows:
        row_ts = record_timestamp(row, source, dataset)
        if anchor_ts is not None and row_ts < anchor_ts:
            continue
        if anchor_ts is not None and within_seconds is not None and (row_ts - anchor_ts).total_seconds() > within_seconds:
            continue
        candidates.append(row)

    for idx, _row in enumerate(candidates):
        window = candidates[idx:idx + min_count]
        if len(window) < min_count:
            break
        if maxspan_seconds is not None:
            span = (record_timestamp(window[-1], source, dataset) - record_timestamp(window[0], source, dataset)).total_seconds()
            if span > maxspan_seconds:
                continue
        selected = window
        break
    return selected


class TemporalJoinEngine(BaseCorrelationEngine):
    strategy_names = ("temporal_join",)

    def build(self, *, rule: Any, dataset: CorrelationDataset, sample_limit: int) -> list[CorrelationMatch]:
        raw_families = (
            (getattr(rule, "evidence_config", None) or {}).get("families")
            or (getattr(rule, "strategy_config", None) or {}).get("families")
            or []
        )
        if not raw_families:
            return []

        families: list[dict[str, Any]] = []
        previous_family_id: str | None = None
        window_seconds = int(getattr(rule, "window_seconds", 600) or 600)
        for idx, raw in enumerate(raw_families):
            family = _normalize_family(dict(raw or {}), idx, previous_family_id=previous_family_id, window_seconds=window_seconds)
            families.append(family)
            previous_family_id = family["id"]

        grouped: dict[tuple[str, str, str, str], dict[str, list[Any]]] = {}
        family_counts: dict[str, str] = {}

        for family in families:
            source = str(family["source"])
            family_counts[family["id"]] = source
            records = filter_records(
                records=select_records(dataset, source),
                source=source,
                dataset=dataset,
                include_patterns=family.get("include_patterns") or [],
                exclude_patterns=family.get("exclude_patterns") or [],
                field_filters=family.get("field_filters") or [],
            )
            for record in records:
                group_by, group_value, entity_type, entity_value = resolve_entity(rule, record, source, dataset)
                grouped.setdefault((group_by, group_value, entity_type, entity_value), {}).setdefault(family["id"], []).append(record)

        out: list[CorrelationMatch] = []
        for (group_by, group_value, entity_type, entity_value), family_map in grouped.items():
            combined_rows: list[tuple[str, Any]] = []
            for family in families:
                source = family_counts[family["id"]]
                for row in family_map.get(family["id"], []):
                    combined_rows.append((source, row))
            if not combined_rows:
                continue

            ordered_pairs = sorted(combined_rows, key=lambda item: record_timestamp(item[1], item[0], dataset))
            segments: list[list[tuple[str, Any]]] = []
            current: list[tuple[str, Any]] = []
            current_start = None
            for source, row in ordered_pairs:
                row_ts = record_timestamp(row, source, dataset)
                if current_start is None:
                    current = [(source, row)]
                    current_start = row_ts
                    continue
                if (row_ts - current_start).total_seconds() <= max(1, int(window_seconds)):
                    current.append((source, row))
                    continue
                segments.append(current)
                current = [(source, row)]
                current_start = row_ts
            if current:
                segments.append(current)

            matched_evidence: list[Any] = []
            matched_families: dict[str, list[Any]] = {}
            stage_hits: dict[str, int] = {}

            for segment in segments:
                per_family_rows = {
                    family["id"]: sorted(
                        [row for src, row in segment if family_counts[family["id"]] == src and row in family_map.get(family["id"], [])],
                        key=lambda row: record_timestamp(row, family_counts[family["id"]], dataset),
                    )
                    for family in families
                }

                valid = True
                chosen: dict[str, list[Any]] = {}
                hits = {family["name"]: len(per_family_rows.get(family["id"], [])) for family in families}

                for family in families:
                    family_id = str(family["id"])
                    anchor_ts = None
                    after_id = family.get("after")
                    if after_id:
                        prior = chosen.get(str(after_id))
                        if prior:
                            prior_source = family_counts[str(after_id)]
                            anchor_ts = record_timestamp(prior[-1], prior_source, dataset)
                        elif family.get("required", True):
                            valid = False
                            break
                    source = family_counts[family_id]
                    family_slice = _select_family_slice(
                        per_family_rows.get(family_id, []),
                        source=source,
                        dataset=dataset,
                        family=family,
                        anchor_ts=anchor_ts,
                    )
                    if not family_slice:
                        if family.get("required", True):
                            valid = False
                            break
                        continue
                    chosen[family_id] = family_slice

                if not valid or not chosen:
                    continue

                matched_families = chosen
                stage_hits = hits
                break

            if not matched_families:
                continue

            selected_pairs: list[tuple[str, Any, str]] = []
            for family in families:
                family_id = str(family["id"])
                source = family_counts[family_id]
                for row in matched_families.get(family_id, []):
                    selected_pairs.append((source, row, str(family["name"])))
            selected_pairs.sort(key=lambda item: record_timestamp(item[1], item[0], dataset))
            if not selected_pairs:
                continue

            alert_rows = [row for source, row, _stage in selected_pairs if source == "alerts"]
            evidence = [
                build_evidence_item(record=row, source=source, dataset=dataset, stage=stage_name)
                for source, row, stage_name in selected_pairs
            ]
            matched_evidence = [row for _source, row, _stage in selected_pairs]

            started_at = record_timestamp(selected_pairs[0][1], selected_pairs[0][0], dataset)
            ended_at = record_timestamp(selected_pairs[-1][1], selected_pairs[-1][0], dataset)
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
                    alert_count=len(alert_rows) if alert_rows else len(matched_evidence),
                    unique_rules=sorted({
                        str(getattr(row, "rule_id", "") or "")
                        for row in alert_rows
                        if str(getattr(row, "rule_id", "") or "").strip()
                    }),
                    stage_hits=stage_hits,
                    risk_score=min(100, severity_score(getattr(rule, "severity", "high")) + len(matched_families) * 6),
                    confidence=min(99, 64 + min(28, len(matched_families) * 8)),
                    summary=(
                        f"Temporal join matched {len(matched_families)} evidence families for {entity_type} {group_value} "
                        f"within {summarize_timedelta_seconds(window_seconds)}."
                    ),
                    context={
                        "strategy": "temporal_join",
                        "window_seconds": window_seconds,
                        "families": [
                            {
                                "id": family["id"],
                                "name": family["name"],
                                "source": family["source"],
                                "after": family["after"],
                                "within_seconds": family["within_seconds"],
                                "required": family["required"],
                                "maxspan_seconds": family["maxspan_seconds"],
                            }
                            for family in families
                        ],
                    },
                    sample_alert_rows=dedupe_alert_rows(alert_rows, sample_limit) if alert_rows else [],
                    evidence_items=evidence,
                )
            )

        return out
