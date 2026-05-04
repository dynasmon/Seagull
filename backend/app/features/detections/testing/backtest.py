from __future__ import annotations

from collections import Counter, defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.features.detections.rules.loader import load_rules
from app.features.detections.testing.fixtures import netevent_row_to_document, normalize_event_document
from app.features.detections.testing.yaml_tests import (
    build_rule_execution_spec,
    evaluate_group_window,
    event_matches_rule,
    summarize_hit_entities,
)
from app.features.events.worker_runtime import NetEventModel


DEFAULT_SAMPLE_LIMIT = 5


def _rule_index(*, rules_dir: str | Path | None = None) -> dict[str, dict[str, Any]]:
    rules = load_rules(
        include_disabled=True,
        with_source=True,
        rules_dir=rules_dir,
        apply_env_filters=False,
        include_non_runtime=True,
    )
    return {str(rule.get("id") or "").strip(): rule for rule in rules if str(rule.get("id") or "").strip()}


def _load_rule(rule_id: str, *, rules_dir: str | Path | None = None) -> dict[str, Any]:
    rule = _rule_index(rules_dir=rules_dir).get(str(rule_id or "").strip())
    if rule is None:
        raise ValueError(f"Unknown rule id: {rule_id}")
    return rule


def _sample_event(event: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": event.get("id"),
        "timestamp": event.get("timestamp"),
        "agent_id": event.get("agent_id"),
        "event_type": event.get("event_type"),
        "src_ip": event.get("src_ip"),
        "src_port": event.get("src_port"),
        "dst_ip": event.get("dst_ip"),
        "dst_port": event.get("dst_port"),
        "proto": event.get("proto"),
        "bytes": event.get("bytes"),
        "app_proto": event.get("app_proto"),
        "http_host": event.get("http_host"),
        "tls_sni": event.get("tls_sni"),
        "ssh_action": event.get("ssh_action"),
        "ssh_username": event.get("ssh_username"),
        "proc_name": event.get("proc_name"),
        "heuristic_name": event.get("heuristic_name"),
        "extra": event.get("extra") if isinstance(event.get("extra"), dict) else {},
    }


def backtest_detection_rule(
    rule: Mapping[str, Any],
    events: list[Mapping[str, Any]],
    *,
    dry_run: bool = True,
    sample_limit: int = DEFAULT_SAMPLE_LIMIT,
) -> dict[str, Any]:
    spec = build_rule_execution_spec(rule)
    if not spec.group_fields:
        return {
            "dry_run": dry_run,
            "match_count": 0,
            "matched_entities": [],
            "severity_distribution": {},
            "sample_evidence": [],
        }

    ordered_events = sorted(
        [netevent_row_to_document(event) if isinstance(event, NetEventModel) else normalize_event_document(event) for event in events],
        key=lambda item: (item.get("timestamp"), item.get("id") or 0),
    )

    windows: dict[tuple[Any, ...], deque[dict[str, Any]]] = defaultdict(deque)
    last_emitted_at: dict[tuple[Any, ...], datetime] = {}
    hits: list[dict[str, Any]] = []

    for event in ordered_events:
        if not event_matches_rule(spec, event):
            continue

        group_key = tuple(event.get(field_name) for field_name in spec.group_fields)
        active_rows = windows[group_key]
        active_rows.append(event)

        cutoff = event["timestamp"] - spec.window
        while active_rows and active_rows[0]["timestamp"] < cutoff:
            active_rows.popleft()

        window_rows = list(active_rows)
        result = evaluate_group_window(spec, window_rows)
        if result is None:
            continue

        last_at = last_emitted_at.get(group_key)
        if last_at is not None and spec.cooldown.total_seconds() > 0 and (event["timestamp"] - last_at) < spec.cooldown:
            continue

        last_emitted_at[group_key] = event["timestamp"]
        hit = {
            "matched_at": event["timestamp"],
            "severity": spec.severity,
            "group_key": dict(zip(spec.group_fields, group_key)),
            "sample_events": [_sample_event(sample) for sample in window_rows[-max(1, sample_limit) :]],
        }
        hit.update(result)
        hits.append(hit)

    severity_distribution = dict(Counter(str(hit.get("severity") or "low").strip().lower() for hit in hits))
    return {
        "dry_run": dry_run,
        "match_count": len(hits),
        "matched_entities": summarize_hit_entities(hits),
        "severity_distribution": severity_distribution,
        "sample_evidence": hits[:max(1, sample_limit)],
    }


def run_detection_backtest(
    db: Session,
    *,
    rule_id: str,
    started_at: datetime,
    ended_at: datetime,
    limit: int,
    dry_run: bool = True,
    sample_limit: int = DEFAULT_SAMPLE_LIMIT,
    rules_dir: str | Path | None = None,
) -> dict[str, Any]:
    if started_at >= ended_at:
        raise ValueError("started_at must be before ended_at")

    rule = _load_rule(rule_id, rules_dir=rules_dir)
    stmt = (
        select(NetEventModel)
        .where(NetEventModel.timestamp >= started_at, NetEventModel.timestamp < ended_at)
        .order_by(NetEventModel.timestamp.desc(), NetEventModel.id.desc())
        .limit(int(limit) + 1)
    )
    rows = list(db.execute(stmt).scalars().all())
    truncated = len(rows) > int(limit)
    if truncated:
        rows = rows[: int(limit)]
    rows.sort(key=lambda row: (row.timestamp, row.id or 0))

    result = backtest_detection_rule(
        rule,
        [netevent_row_to_document(row) for row in rows],
        dry_run=dry_run,
        sample_limit=sample_limit,
    )
    result.update(
        {
            "rule_id": str(rule.get("id") or "").strip(),
            "source_file": str(rule.get("source_file") or "").strip() or None,
            "started_at": started_at,
            "ended_at": ended_at,
            "scanned_events": len(rows),
            "event_limit": int(limit),
            "truncated": truncated,
        }
    )
    return result


__all__ = [
    "DEFAULT_SAMPLE_LIMIT",
    "backtest_detection_rule",
    "run_detection_backtest",
]
