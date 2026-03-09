from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.alert_rule_overrides import AlertRuleOverrideModel
from app.models.alert_rule_suppressions import AlertRuleSuppressionModel
from app.models.alert_rule_tuning import AlertRuleTuningModel
from app.workers.rules_loader import load_rules


def deep_merge(base: Dict[str, Any], patch: Dict[str, Any]) -> Dict[str, Any]:
    """Deep-merge dictionaries.

    - dict values are merged recursively
    - other values overwrite
    - lists overwrite (no concat) to avoid ambiguous merges
    """
    if not isinstance(base, dict):
        return patch
    out: Dict[str, Any] = dict(base)
    for k, v in (patch or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def override_to_dict(row: AlertRuleOverrideModel) -> Dict[str, Any]:
    return {
        "enabled": row.enabled,
        "severity": row.severity,
        "window": row.window,
        "cooldown": row.cooldown,
        "min_events": row.min_events,
        "condition": row.condition or {},
        "schedule": row.schedule or {},
        "patch": row.patch or {},
    }


def fetch_overrides(db: Session) -> Dict[str, AlertRuleOverrideModel]:
    rows = db.execute(select(AlertRuleOverrideModel)).scalars().all()
    return {r.rule_id: r for r in rows if r.rule_id}


def fetch_tuning(db: Session) -> Dict[str, AlertRuleTuningModel]:
    rows = db.execute(select(AlertRuleTuningModel)).scalars().all()
    return {r.rule_id: r for r in rows if r.rule_id}


def fetch_suppressions(db: Session) -> Dict[str, List[AlertRuleSuppressionModel]]:
    rows = db.execute(select(AlertRuleSuppressionModel)).scalars().all()
    out: Dict[str, List[AlertRuleSuppressionModel]] = {}
    for r in rows:
        rid = str(r.rule_id or "").strip()
        if not rid:
            continue
        out.setdefault(rid, []).append(r)
    return out


def apply_override(base_rule: Dict[str, Any], row: Optional[AlertRuleOverrideModel]) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    """Returns (effective_rule, override_payload)."""
    base = dict(base_rule or {})
    if not row:
        return base, None

    eff = dict(base)

    if row.enabled is not None:
        eff["enabled"] = bool(row.enabled)
    if row.severity:
        eff["severity"] = row.severity
    if row.window:
        eff["window"] = row.window
    if row.cooldown:
        eff["cooldown"] = row.cooldown
    if row.min_events is not None:
        eff["min_events"] = int(row.min_events)

    if isinstance(row.condition, dict) and row.condition:
        eff["condition"] = deep_merge(eff.get("condition") or {}, row.condition)

    if isinstance(row.schedule, dict) and row.schedule:
        eff["schedule"] = deep_merge(eff.get("schedule") or {}, row.schedule)

    if isinstance(row.patch, dict) and row.patch:
        eff = deep_merge(eff, row.patch)

    return eff, override_to_dict(row)


def apply_tuning_and_suppressions(
    rule: Dict[str, Any],
    *,
    tuning_row: Optional[AlertRuleTuningModel],
    suppression_rows: Optional[List[AlertRuleSuppressionModel]],
) -> Dict[str, Any]:
    out = dict(rule or {})

    if tuning_row is not None:
        t = tuning_row.tuning if isinstance(tuning_row.tuning, dict) else {}
        out["tuning"] = t

    if suppression_rows:
        sups: list[Dict[str, Any]] = []
        for s in suppression_rows:
            if not bool(getattr(s, "enabled", True)):
                continue
            sups.append(
                {
                    "id": int(s.id),
                    "reason": s.reason,
                    "when": s.when if isinstance(s.when, dict) else {},
                    "until": s.until.isoformat() if getattr(s, "until", None) is not None else None,
                }
            )
        out["suppressions"] = sups

    return out


def load_baseline_rules(include_disabled: bool = True) -> List[Dict[str, Any]]:
    # We keep baseline rules as-is (including enabled=false) so the portal can configure them.
    return load_rules(include_disabled=include_disabled, with_source=True)


def normalize_rule_list(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for r in rules or []:
        if not isinstance(r, dict):
            continue
        rid = r.get("id")
        if not rid:
            continue
        out.append(r)
    return out
