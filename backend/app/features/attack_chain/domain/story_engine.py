from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, Mapping, Sequence

from .story_schemas import AttackStoryStage, AttackStoryTemplate
from .types import StepCandidate


@dataclass
class StoryEvidenceRecord:
    source: str
    timestamp: datetime
    first_seen_at: datetime
    fields: dict[str, str] = field(default_factory=dict)
    kind: str | None = None
    event_type: str | None = None
    rule_ids: tuple[str, ...] = ()
    correlation_rule_id: int | None = None
    confidence: int = 50
    label: str = ""


@dataclass
class AttackStoryEvaluation:
    score_delta: int = 0
    matched_story_ids: list[str] = field(default_factory=list)
    matched_story_names: list[str] = field(default_factory=list)
    story_stage_hits: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)
    story_confidence: int | None = None
    story_reasoning: list[str] = field(default_factory=list)
    context_patch: dict[str, Any] = field(default_factory=dict)
    detail_patch: dict[str, Any] = field(default_factory=dict)


def _safe_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _to_int(value: Any, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return int(default)
        return int(float(value))
    except Exception:
        return int(default)


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return float(default)
        return float(value)
    except Exception:
        return float(default)


def _parse_dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            parsed = datetime.fromisoformat(text)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except Exception:
            return None
    return None


def _norm_text(value: Any, *, max_len: int = 256) -> str:
    return str(value or "").strip()[:max_len]


def _norm_str_list(value: Any, *, max_items: int = 16) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in value:
        text = _norm_text(item)
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
        if len(out) >= max_items:
            break
    return out


def _norm_int_list(value: Any, *, max_items: int = 16) -> list[int]:
    if not isinstance(value, list):
        return []
    out: list[int] = []
    seen: set[int] = set()
    for item in value:
        try:
            parsed = int(item)
        except Exception:
            continue
        if parsed in seen:
            continue
        seen.add(parsed)
        out.append(parsed)
        if len(out) >= max_items:
            break
    return out


def _dedupe_strs(values: Iterable[str], *, max_items: int = 16) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in values:
        text = _norm_text(item)
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
        if len(out) >= max_items:
            break
    return out


def _deep_get(value: Any, path: str) -> Any:
    current = value
    for raw_part in str(path or "").split("."):
        part = raw_part.strip()
        if not part:
            continue
        if isinstance(current, Mapping):
            current = current.get(part)
            continue
        if isinstance(current, list):
            try:
                current = current[int(part)]
            except Exception:
                return None
            continue
        current = getattr(current, part, None)
    return current


def attack_story_maxspan_seconds(stories: Sequence[AttackStoryTemplate]) -> int:
    maxspan = 0
    for story in stories:
        if story.enabled is False:
            continue
        maxspan = max(maxspan, int(story.maxspan_seconds or 0))
    return maxspan


def _normalize_story_stage_hits(raw: Any) -> dict[str, dict[str, dict[str, Any]]]:
    out: dict[str, dict[str, dict[str, Any]]] = {}
    if not isinstance(raw, dict):
        return out

    for raw_story_id, raw_stage_map in raw.items():
        story_id = _norm_text(raw_story_id, max_len=96)
        if not story_id or not isinstance(raw_stage_map, dict):
            continue

        stage_hits: dict[str, dict[str, Any]] = {}
        for raw_stage_id, raw_hit in raw_stage_map.items():
            stage_id = _norm_text(raw_stage_id, max_len=64)
            hit = _safe_dict(raw_hit)
            if not stage_id or not hit:
                continue

            matched_at = _parse_dt(hit.get("matched_at")) or _parse_dt(hit.get("last_seen_at"))
            if matched_at is None:
                continue
            first_seen_at = _parse_dt(hit.get("first_seen_at")) or matched_at

            stage_hits[stage_id] = {
                "story_id": story_id,
                "stage_id": stage_id,
                "story_name": _norm_text(hit.get("story_name"), max_len=128),
                "stage_name": _norm_text(hit.get("stage_name"), max_len=96),
                "tactic": _norm_text(hit.get("tactic"), max_len=64),
                "technique_id": _norm_text(hit.get("technique_id"), max_len=32) or None,
                "matched_at": matched_at.isoformat(),
                "first_seen_at": first_seen_at.isoformat(),
                "signal_count": max(1, _to_int(hit.get("signal_count"), 1)),
                "confidence": max(0, min(100, _to_int(hit.get("confidence"), 0))),
                "sources": _norm_str_list(hit.get("sources"), max_items=6),
                "kind_samples": _norm_str_list(hit.get("kind_samples"), max_items=6),
                "event_types": _norm_str_list(hit.get("event_types"), max_items=6),
                "rule_ids": _norm_str_list(hit.get("rule_ids"), max_items=12),
                "correlation_rule_ids": _norm_int_list(hit.get("correlation_rule_ids"), max_items=8),
            }

        if stage_hits:
            out[story_id] = stage_hits
    return out


def _record_fields_from_case(entity_values: Mapping[str, Any] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in dict(entity_values or {}).items():
        text = _norm_text(value)
        if text:
            out[_norm_text(key)] = text
    return out


def _record_from_step(row: Any, *, entity_values: Mapping[str, Any] | None, now: datetime) -> StoryEvidenceRecord:
    details = _safe_dict(_deep_get(row, "details"))
    timestamp = _parse_dt(_deep_get(row, "timestamp")) or now
    fields = _record_fields_from_case(entity_values)

    for key in ("agent_id", "suspect_ip", "src_ip", "dst_ip"):
        value = details.get(key)
        if value is None:
            value = _deep_get(row, key)
        text = _norm_text(value)
        if text:
            fields[key] = text

    raw_rule = details.get("rule_id")
    rule_ids = tuple(_dedupe_strs([raw_rule] if raw_rule else []))

    return StoryEvidenceRecord(
        source="attack_step",
        timestamp=timestamp,
        first_seen_at=timestamp,
        fields=fields,
        kind=_norm_text(details.get("kind")) or None,
        event_type=_norm_text(_deep_get(row, "event_type")) or None,
        rule_ids=rule_ids,
        confidence=max(0, min(100, _to_int(details.get("confidence"), 50))),
        label=_norm_text(_deep_get(row, "label"), max_len=128),
    )


def _record_from_candidate(
    candidate: StepCandidate,
    *,
    event: Mapping[str, Any],
    entity_values: Mapping[str, Any] | None,
    now: datetime,
    confidence: int | None = None,
) -> StoryEvidenceRecord:
    details = dict(candidate.details or {})
    timestamp = _parse_dt(event.get("timestamp")) or now
    fields = _record_fields_from_case(entity_values)

    for key, value in (
        ("agent_id", event.get("agent_id")),
        ("suspect_ip", candidate.suspect_ip or details.get("src_ip")),
        ("src_ip", event.get("src_ip") or details.get("src_ip")),
        ("dst_ip", event.get("dst_ip") or details.get("dst_ip")),
    ):
        text = _norm_text(value)
        if text:
            fields[key] = text

    raw_rule = details.get("rule_id")
    rule_ids = tuple(_dedupe_strs([raw_rule] if raw_rule else []))

    return StoryEvidenceRecord(
        source="current_candidate",
        timestamp=timestamp,
        first_seen_at=timestamp,
        fields=fields,
        kind=_norm_text(candidate.kind) or None,
        event_type=_norm_text(event.get("event_type")) or None,
        rule_ids=rule_ids,
        confidence=max(0, min(100, int(confidence if confidence is not None else _to_int(candidate.confidence, 50)))),
        label=_norm_text(candidate.title, max_len=128),
    )


def _record_from_alert(row: Any, *, now: datetime) -> StoryEvidenceRecord:
    details = _safe_dict(_deep_get(row, "details"))
    timestamp = _parse_dt(_deep_get(row, "created_at")) or now
    fields: dict[str, str] = {}
    for key, value in (
        ("agent_id", details.get("agent_id")),
        ("suspect_ip", details.get("suspect_ip")),
        ("src_ip", _deep_get(row, "src_ip")),
        ("dst_ip", _deep_get(row, "dst_ip")),
    ):
        text = _norm_text(value)
        if text:
            fields[key] = text

    extra_rule = details.get("rule_id")
    rule_ids = tuple(_dedupe_strs([_deep_get(row, "rule_id"), extra_rule] if extra_rule else [_deep_get(row, "rule_id")]))

    return StoryEvidenceRecord(
        source="alert",
        timestamp=timestamp,
        first_seen_at=timestamp,
        fields=fields,
        kind=_norm_text(details.get("kind")) or None,
        event_type=_norm_text(details.get("event_type")) or None,
        rule_ids=rule_ids,
        confidence=max(0, min(100, _to_int(_deep_get(row, "confidence"), 50))),
        label=_norm_text(_deep_get(row, "description"), max_len=128),
    )


def _record_from_incident(row: Any, *, now: datetime) -> StoryEvidenceRecord:
    context = _safe_dict(_deep_get(row, "context"))
    entity_type = _norm_text(_deep_get(row, "entity_type"))
    entity_value = _norm_text(_deep_get(row, "entity_value"))
    group_by = _norm_text(_deep_get(row, "group_by"))
    group_value = _norm_text(_deep_get(row, "group_value"))
    last_seen_at = _parse_dt(_deep_get(row, "last_seen_at")) or now
    started_at = _parse_dt(_deep_get(row, "started_at")) or last_seen_at

    fields: dict[str, str] = {}
    if entity_type and entity_value:
        fields[entity_type] = entity_value
    if group_by and group_value:
        fields[group_by] = group_value
    for key, value in (
        ("agent_id", context.get("agent_id")),
        ("suspect_ip", context.get("suspect_ip")),
        ("src_ip", context.get("src_ip")),
        ("dst_ip", context.get("dst_ip")),
    ):
        text = _norm_text(value)
        if text:
            fields[key] = text

    rule_ids = list(_norm_str_list(_deep_get(row, "unique_rules"), max_items=12))
    correlation_rule_name = _norm_text(_deep_get(row, "correlation_rule_name"), max_len=128)
    if correlation_rule_name:
        rule_ids.append(correlation_rule_name)

    return StoryEvidenceRecord(
        source="correlation_incident",
        timestamp=last_seen_at,
        first_seen_at=started_at,
        fields=fields,
        rule_ids=tuple(_dedupe_strs(rule_ids, max_items=12)),
        correlation_rule_id=(
            _to_int(_deep_get(row, "correlation_rule_id"), 0)
            if _to_int(_deep_get(row, "correlation_rule_id"), 0) > 0
            else None
        ),
        confidence=max(0, min(100, _to_int(_deep_get(row, "confidence"), 60))),
        label=correlation_rule_name or _norm_text(_deep_get(row, "summary"), max_len=128),
    )


def _build_records(
    *,
    existing_steps: Sequence[Any],
    alerts: Sequence[Any],
    correlation_incidents: Sequence[Any],
    candidate: StepCandidate,
    event: Mapping[str, Any],
    entity_values: Mapping[str, Any] | None,
    now: datetime,
    candidate_confidence: int | None,
) -> list[StoryEvidenceRecord]:
    records: list[StoryEvidenceRecord] = []
    for row in existing_steps:
        records.append(_record_from_step(row, entity_values=entity_values, now=now))
    for row in alerts:
        records.append(_record_from_alert(row, now=now))
    for row in correlation_incidents:
        records.append(_record_from_incident(row, now=now))
    records.append(
        _record_from_candidate(
            candidate,
            event=event,
            entity_values=entity_values,
            now=now,
            confidence=candidate_confidence,
        )
    )
    records.sort(key=lambda item: (item.timestamp, item.source, item.label))
    return records


def _record_matches_entity(record: StoryEvidenceRecord, *, entity_field: str, entity_value: str | None) -> bool:
    if not entity_field or not entity_value:
        return True
    return _norm_text(record.fields.get(entity_field)) == entity_value


def _record_matches_stage(record: StoryEvidenceRecord, stage: AttackStoryStage) -> bool:
    matched = False
    selectors = stage.match

    if selectors.attack_step_kinds:
        matched = matched or (_norm_text(record.kind) in set(selectors.attack_step_kinds))
    if selectors.event_types:
        matched = matched or (_norm_text(record.event_type) in set(selectors.event_types))
    if selectors.rule_ids:
        record_rule_ids = {item for item in record.rule_ids if item}
        matched = matched or bool(record_rule_ids & set(selectors.rule_ids))
    if selectors.correlation_rule_ids:
        matched = matched or (
            record.correlation_rule_id is not None and int(record.correlation_rule_id) in set(selectors.correlation_rule_ids)
        )

    return matched


def _select_stage_records(
    *,
    story: AttackStoryTemplate,
    stage: AttackStoryStage,
    records: Sequence[StoryEvidenceRecord],
    entity_value: str | None,
    anchor_first_seen_at: datetime | None,
    after_ts: datetime | None,
) -> list[StoryEvidenceRecord]:
    matching: list[StoryEvidenceRecord] = []
    entity_field = _norm_text(story.entity.field)

    for record in records:
        if not _record_matches_entity(record, entity_field=entity_field, entity_value=entity_value):
            continue
        if not _record_matches_stage(record, stage):
            continue
        if after_ts is not None and record.timestamp < after_ts:
            continue
        matching.append(record)

    if len(matching) < int(stage.min_signals):
        return []

    story_deadline = None
    if anchor_first_seen_at is not None and int(story.maxspan_seconds or 0) > 0:
        story_deadline = anchor_first_seen_at + timedelta(seconds=int(story.maxspan_seconds))

    required_count = int(stage.min_signals)
    for index in range(0, len(matching) - required_count + 1):
        window = matching[index:index + required_count]
        min(item.first_seen_at for item in window)
        matched_at = max(item.timestamp for item in window)
        if after_ts is not None and stage.within_seconds is not None:
            if matched_at > (after_ts + timedelta(seconds=int(stage.within_seconds))):
                continue
        if story_deadline is not None and matched_at > story_deadline:
            continue
        return window

    return []


def _build_stage_hit(
    *,
    story: AttackStoryTemplate,
    stage: AttackStoryStage,
    records: Sequence[StoryEvidenceRecord],
) -> dict[str, Any]:
    first_seen_at = min(item.first_seen_at for item in records)
    matched_at = max(item.timestamp for item in records)
    confidence_values = [max(0, min(100, _to_int(item.confidence, 0))) for item in records]
    confidence = int(round(sum(confidence_values) / max(1, len(confidence_values))))

    return {
        "story_id": story.id,
        "stage_id": stage.id,
        "story_name": story.name,
        "stage_name": stage.name,
        "tactic": stage.tactic,
        "technique_id": stage.technique_id,
        "matched_at": matched_at.isoformat(),
        "first_seen_at": first_seen_at.isoformat(),
        "signal_count": len(records),
        "confidence": confidence,
        "sources": _dedupe_strs((item.source for item in records), max_items=6),
        "kind_samples": _dedupe_strs((item.kind or "" for item in records), max_items=6),
        "event_types": _dedupe_strs((item.event_type or "" for item in records), max_items=6),
        "rule_ids": _dedupe_strs(
            (
                rule_id
                for item in records
                for rule_id in item.rule_ids
                if rule_id
            ),
            max_items=12,
        ),
        "correlation_rule_ids": _norm_int_list(
            [item.correlation_rule_id for item in records if item.correlation_rule_id is not None],
            max_items=8,
        ),
    }


def _stage_first_seen_at(hit: Mapping[str, Any]) -> datetime | None:
    return _parse_dt(hit.get("first_seen_at")) or _parse_dt(hit.get("matched_at"))


def _stage_matched_at(hit: Mapping[str, Any]) -> datetime | None:
    return _parse_dt(hit.get("matched_at"))


def _story_confidence(story: AttackStoryTemplate, stage_hits: Mapping[str, Mapping[str, Any]]) -> int:
    total_weight = 0.0
    weighted_sum = 0.0
    for stage in story.stages:
        hit = stage_hits.get(stage.id)
        if not hit:
            continue
        weight = max(0.0, _to_float(stage.confidence_weight, 0.0))
        if weight <= 0.0:
            continue
        weighted_sum += float(max(0, min(100, _to_int(hit.get("confidence"), 0)))) * weight
        total_weight += weight
    if total_weight <= 0.0:
        return 0
    return int(round(weighted_sum / total_weight))


def _story_reasoning_line(story: AttackStoryTemplate, stage_hits: Mapping[str, Mapping[str, Any]], *, entity_value: str | None) -> str:
    stage_names = [
        _norm_text((stage_hits.get(stage.id) or {}).get("stage_name"), max_len=96) or stage.name
        for stage in story.stages
        if stage.id in stage_hits
    ]
    if not stage_names:
        return ""
    progression = " -> ".join(stage_names[:4])
    if entity_value:
        return f"{story.name}: {progression} ({story.entity.type} {entity_value})"
    return f"{story.name}: {progression}"


def evaluate_attack_stories(
    *,
    stories: Sequence[AttackStoryTemplate],
    case_context: Mapping[str, Any] | None,
    existing_steps: Sequence[Any],
    alerts: Sequence[Any],
    correlation_incidents: Sequence[Any],
    candidate: StepCandidate,
    event: Mapping[str, Any],
    now: datetime,
    entity_values: Mapping[str, Any] | None = None,
    candidate_confidence: int | None = None,
) -> AttackStoryEvaluation:
    enabled_stories = [story for story in stories if story.enabled is not False]
    if not enabled_stories:
        return AttackStoryEvaluation()

    ctx = _safe_dict(case_context)
    existing_stage_hits = _normalize_story_stage_hits(ctx.get("story_stage_hits"))
    matched_story_ids = _norm_str_list(ctx.get("matched_story_ids"), max_items=64)
    matched_story_names = _norm_str_list(ctx.get("matched_story_names"), max_items=64)
    story_reasoning = _norm_str_list(ctx.get("story_reasoning"), max_items=64)

    records = _build_records(
        existing_steps=existing_steps,
        alerts=alerts,
        correlation_incidents=correlation_incidents,
        candidate=candidate,
        event=event,
        entity_values=entity_values,
        now=now,
        candidate_confidence=candidate_confidence,
    )

    merged_stage_hits = {
        story_id: {stage_id: dict(hit) for stage_id, hit in stage_map.items()}
        for story_id, stage_map in existing_stage_hits.items()
    }

    new_stage_matches: list[dict[str, Any]] = []
    new_story_matches: list[dict[str, Any]] = []
    total_story_score = 0

    entity_map = _record_fields_from_case(entity_values)

    for story in enabled_stories:
        entity_field = _norm_text(story.entity.field)
        entity_value = entity_map.get(entity_field) or None
        story_hits = {
            stage_id: dict(hit)
            for stage_id, hit in (merged_stage_hits.get(story.id) or {}).items()
        }
        newly_hit_stage_ids: list[str] = []

        anchor_first_seen_at = None
        for stage in story.stages:
            if stage.id in story_hits:
                if anchor_first_seen_at is None:
                    anchor_first_seen_at = _stage_first_seen_at(story_hits[stage.id])
                continue

            if stage.after:
                prior_hit = story_hits.get(stage.after)
                if not prior_hit:
                    if stage.required:
                        break
                    continue
                after_ts = _stage_matched_at(prior_hit)
                if after_ts is None:
                    if stage.required:
                        break
                    continue
            else:
                after_ts = None

            if anchor_first_seen_at is None and stage.after:
                prior_hit = story_hits.get(stage.after)
                anchor_first_seen_at = _stage_first_seen_at(prior_hit) if prior_hit else None

            selected = _select_stage_records(
                story=story,
                stage=stage,
                records=records,
                entity_value=entity_value,
                anchor_first_seen_at=anchor_first_seen_at,
                after_ts=after_ts,
            )

            if not selected:
                if stage.required:
                    break
                continue

            hit = _build_stage_hit(story=story, stage=stage, records=selected)
            story_hits[stage.id] = hit
            newly_hit_stage_ids.append(stage.id)
            new_stage_matches.append(
                {
                    "story_id": story.id,
                    "story_name": story.name,
                    "stage_id": stage.id,
                    "stage_name": stage.name,
                    "confidence": int(hit.get("confidence") or 0),
                    "score_delta": int(stage.score_delta or 0),
                }
            )

            if anchor_first_seen_at is None:
                anchor_first_seen_at = _stage_first_seen_at(hit)

        if not story_hits:
            continue

        merged_stage_hits[story.id] = story_hits
        required_stage_ids = [stage.id for stage in story.stages if stage.required]
        story_fully_matched = bool(required_stage_ids) and all(stage_id in story_hits for stage_id in required_stage_ids)

        existing_story_score = sum(
            int(stage.score_delta or 0)
            for stage in story.stages
            if stage.id in (existing_stage_hits.get(story.id) or {})
        )
        if story.id in matched_story_ids:
            existing_story_score += int(story.scoring.story_match_bonus or 0)

        new_stage_score = sum(
            int(stage.score_delta or 0)
            for stage in story.stages
            if stage.id in newly_hit_stage_ids
        )

        max_story_score = int(story.scoring.max_story_score or 0) if story.scoring.max_story_score is not None else None
        if max_story_score is not None:
            remaining = max(0, max_story_score - existing_story_score)
            applied_stage_score = min(max(0, new_stage_score), remaining)
        else:
            applied_stage_score = max(0, new_stage_score)
        total_story_score += applied_stage_score
        existing_story_score += applied_stage_score

        if story_fully_matched and story.id not in matched_story_ids:
            story_bonus = max(0, int(story.scoring.story_match_bonus or 0))
            if max_story_score is not None:
                story_bonus = min(story_bonus, max(0, max_story_score - existing_story_score))
            if story_bonus > 0:
                total_story_score += story_bonus

            matched_story_ids.append(story.id)
            matched_story_names.append(story.name)
            story_confidence = _story_confidence(story, story_hits)
            reason_line = _story_reasoning_line(story, story_hits, entity_value=entity_value)
            if reason_line and reason_line not in story_reasoning:
                story_reasoning.append(reason_line)
            new_story_matches.append(
                {
                    "story_id": story.id,
                    "story_name": story.name,
                    "confidence": story_confidence,
                    "reason": reason_line,
                }
            )

    overall_confidence = None
    if matched_story_ids:
        confidence_by_story: list[int] = []
        stories_by_id = {story.id: story for story in enabled_stories}
        for story_id in matched_story_ids:
            story = stories_by_id.get(story_id)
            if not story:
                continue
            story_hits = merged_stage_hits.get(story_id) or {}
            confidence_by_story.append(_story_confidence(story, story_hits))
        if confidence_by_story:
            overall_confidence = max(confidence_by_story)

    context_patch: dict[str, Any] = {}
    if merged_stage_hits != existing_stage_hits:
        context_patch["story_stage_hits"] = merged_stage_hits
    if matched_story_ids != _norm_str_list(ctx.get("matched_story_ids"), max_items=64):
        context_patch["matched_story_ids"] = matched_story_ids
    if matched_story_names != _norm_str_list(ctx.get("matched_story_names"), max_items=64):
        context_patch["matched_story_names"] = matched_story_names
    if story_reasoning != _norm_str_list(ctx.get("story_reasoning"), max_items=64):
        context_patch["story_reasoning"] = story_reasoning
    if overall_confidence is not None and overall_confidence != _to_int(ctx.get("story_confidence"), 0):
        context_patch["story_confidence"] = overall_confidence

    detail_patch: dict[str, Any] = {}
    if total_story_score > 0:
        detail_patch["story_score_delta"] = int(total_story_score)
    if new_stage_matches:
        detail_patch["story_stage_matches"] = new_stage_matches
    if new_story_matches:
        detail_patch["story_matches"] = new_story_matches

    return AttackStoryEvaluation(
        score_delta=int(total_story_score),
        matched_story_ids=list(matched_story_ids),
        matched_story_names=list(matched_story_names),
        story_stage_hits=merged_stage_hits,
        story_confidence=overall_confidence,
        story_reasoning=list(story_reasoning),
        context_patch=context_patch,
        detail_patch=detail_patch,
    )
