from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.features.agents.models import AgentModel

from .conditions import _parse_window, _selector_matches


def _resolve_tuning_eval(
    rule: Dict[str, Any],
    *,
    ctx: Dict[str, Any],
    base_min_events: int,
    base_condition: Dict[str, Any],
    base_cooldown_seconds: int,
    base_severity: str,
) -> Dict[str, Any]:
    out = {
        "min_events": int(base_min_events),
        "condition": dict(base_condition or {}),
        "cooldown_seconds": int(max(0, base_cooldown_seconds)),
        "severity": str(base_severity or "low"),
        "applied_scopes": [],
    }
    tuning = rule.get("tuning") if isinstance(rule.get("tuning"), dict) else {}
    scopes = tuning.get("threshold_scopes") or tuning.get("scopes") or []
    if not isinstance(scopes, list) or not scopes:
        return out

    for i, scope in enumerate(scopes):
        if not isinstance(scope, dict):
            continue
        if scope.get("enabled") is False:
            continue
        when = scope.get("when") if isinstance(scope.get("when"), dict) else {}
        if when and not _selector_matches(when, ctx):
            continue
        if when == {}:
            continue

        name = str(scope.get("name") or f"scope_{i+1}").strip()
        out["applied_scopes"].append(name)

        if scope.get("min_events") is not None:
            try:
                out["min_events"] = max(0, int(scope.get("min_events")))
            except Exception:
                pass

        if isinstance(scope.get("condition"), dict):
            cond = scope.get("condition") or {}
            out["condition"] = dict(cond)
        elif scope.get("condition_value") is not None:
            try:
                v = int(scope.get("condition_value"))
                cur = dict(out.get("condition") or {})
                cur["value"] = v
                if not cur.get("operator"):
                    cur["operator"] = ">="
                out["condition"] = cur
            except Exception:
                pass

        cooldown_raw = scope.get("cooldown")
        if cooldown_raw is not None and str(cooldown_raw).strip():
            try:
                out["cooldown_seconds"] = max(0, int(_parse_window(str(cooldown_raw))))
            except Exception:
                pass

        sev_raw = str(scope.get("severity") or "").strip().lower()
        if sev_raw in {"low", "medium", "high", "critical"}:
            out["severity"] = sev_raw

    return out


def _load_agent_context(db: Session) -> Dict[str, Dict[str, Any]]:
    rows = db.execute(select(AgentModel.agent_id, AgentModel.agent_metadata, AgentModel.tags)).all()
    out: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        aid = str(row.agent_id or "").strip()
        if not aid:
            continue
        meta = row.agent_metadata if isinstance(row.agent_metadata, dict) else {}
        row_tags = row.tags if isinstance(row.tags, list) else []
        meta_tags = meta.get("tags") if isinstance(meta.get("tags"), list) else []
        tags: list[str] = []
        for item in [*row_tags, *meta_tags]:
            v = str(item or "").strip().lower()
            if v and v not in tags:
                tags.append(v)

        hostname = (
            str(meta.get("hostname") or meta.get("host") or meta.get("node_name") or "").strip().lower()
        )
        host_role = (
            str(meta.get("host_role") or meta.get("role") or meta.get("agent_role") or "").strip().lower()
        )
        agent_env = (
            str(meta.get("environment") or meta.get("env") or meta.get("deployment_env") or settings.SEAGULL_ENV or "")
            .strip()
            .lower()
        )
        out[aid] = {
            "agent_hostname": hostname,
            "agent_host_role": host_role,
            "agent_environment": agent_env,
            "agent_tags": tags,
        }
    return out


def _build_rule_context(
    *,
    group_key: Dict[str, Any],
    match: Dict[str, Any],
    rule_id: str,
    severity: str,
    src_ip: Optional[str],
    dst_ip: Optional[str],
    dst_port: Optional[int],
    agent_ctx_map: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    out = dict(group_key or {})
    out.update(
        {
            "rule_id": rule_id,
            "severity": severity,
            "agent_id": (group_key or {}).get("agent_id") or (match or {}).get("agent_id"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "proto": (group_key or {}).get("proto") or (match or {}).get("proto"),
            "event_type": (group_key or {}).get("event_type") or (match or {}).get("event_type"),
            "path_category": (group_key or {}).get("fim_category") or (match or {}).get("extra_path_category"),
            "username": (match or {}).get("extra_username"),
            "target_user": (match or {}).get("extra_target_user"),
            "proc_name": (group_key or {}).get("proc_name") or (match or {}).get("extra_exe_name"),
            "proc_parent_name": (group_key or {}).get("proc_parent_name") or (match or {}).get("extra_parent_exe_name"),
        }
    )

    aid = str(out.get("agent_id") or "").strip()
    if aid and aid in agent_ctx_map:
        meta = agent_ctx_map.get(aid) or {}
        out["agent_hostname"] = meta.get("agent_hostname")
        out["hostname"] = meta.get("agent_hostname")
        out["agent_host_role"] = meta.get("agent_host_role")
        out["host_role"] = meta.get("agent_host_role")
        out["agent_environment"] = meta.get("agent_environment")
        out["environment"] = meta.get("agent_environment")
        out["agent_tags"] = meta.get("agent_tags") or []
    else:
        out["environment"] = str(settings.SEAGULL_ENV or "").strip().lower()

    return out


def _is_tuning_allowlisted(rule: Dict[str, Any], ctx: Dict[str, Any]) -> tuple[bool, Optional[str]]:
    tuning = rule.get("tuning") if isinstance(rule.get("tuning"), dict) else {}
    allowlist = tuning.get("allowlist") if isinstance(tuning, dict) else None
    if isinstance(allowlist, dict) and allowlist and _selector_matches(allowlist, ctx):
        return True, "tuning.allowlist"

    scoped = tuning.get("allowlist_scopes")
    if isinstance(scoped, list):
        for i, item in enumerate(scoped):
            if not isinstance(item, dict):
                continue
            if item.get("enabled") is False:
                continue
            when = item.get("when") if isinstance(item.get("when"), dict) else {}
            if not when or not _selector_matches(when, ctx):
                continue
            reason = str(item.get("reason") or item.get("name") or f"tuning.allowlist_scopes[{i}]").strip()
            return True, reason or "tuning.allowlist_scope"

    return False, None
