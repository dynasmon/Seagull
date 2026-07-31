from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import HTTPException, status

from app.core.observability import incr_counter

SENSOR = "sensor"
MANAGED = "managed"
VALID_PROFILES = (SENSOR, MANAGED)
DEFAULT_PROFILE = MANAGED

_RANK = {SENSOR: 0, MANAGED: 1}


def normalize(value: Optional[str]) -> str:
    raw = str(value or "").strip().lower()
    return raw if raw in VALID_PROFILES else ""


def of(metadata: Optional[Dict[str, Any]]) -> str:
    if not isinstance(metadata, dict):
        return DEFAULT_PROFILE
    return normalize(metadata.get("profile")) or DEFAULT_PROFILE


def of_agent(agent_row) -> str:
    return of(getattr(agent_row, "agent_metadata", None))


def allows_response_actions(profile: Optional[str]) -> bool:
    return (normalize(profile) or DEFAULT_PROFILE) != SENSOR


def resolve_reported(current: Optional[str], reported: Optional[str]) -> str:
    effective = normalize(current) or DEFAULT_PROFILE
    declared = normalize(reported)
    if not declared:
        return effective
    if _RANK[declared] < _RANK[effective]:
        return declared
    return effective


def require_response_capable(agent_row, *, agent_id: str) -> None:
    profile = of_agent(agent_row)
    if allows_response_actions(profile):
        return
    incr_counter("response_action_profile_denied_total", profile=profile)
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail=f"Agent '{agent_id}' runs the {profile} profile and cannot execute response actions",
    )


def response_action_support(agent_row, *, action_type: str) -> tuple[bool, str]:
    profile = of_agent(agent_row)
    if not allows_response_actions(profile):
        return False, "sensor_profile"
    metrics = getattr(agent_row, "metrics", None)
    capabilities = metrics.get("capabilities") if isinstance(metrics, dict) else None
    if not isinstance(capabilities, dict):
        return False, "capabilities_not_reported"
    action_types = capabilities.get("response_action_types")
    if not isinstance(action_types, list):
        return False, "capabilities_not_reported"
    supported = {
        str(value or "").strip().lower()
        for value in action_types
        if isinstance(value, str) and str(value or "").strip()
    }
    normalized_action = str(action_type or "").strip().lower()
    if normalized_action not in supported:
        return False, "unsupported_action"
    if normalized_action == "run_shell_command" and capabilities.get("shell_exec") is not True:
        return False, "local_policy_denied"
    return True, ""


def require_response_action_capable(agent_row, *, agent_id: str, action_type: str) -> None:
    supported, reason = response_action_support(agent_row, action_type=action_type)
    if supported:
        return
    profile = of_agent(agent_row)
    incr_counter("response_action_capability_denied_total", profile=profile, reason=reason)
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={
            "error": "agent_capability_unavailable",
            "agent_id": agent_id,
            "action_type": action_type,
            "profile": profile,
            "reason": reason,
        },
    )
