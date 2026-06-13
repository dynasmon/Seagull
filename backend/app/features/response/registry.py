from __future__ import annotations

import ipaddress
import posixpath
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from fastapi import HTTPException

_ALLOWED_SIGNALS = {
    "SIGTERM",
    "SIGKILL",
    "SIGINT",
    "SIGHUP",
    "SIGQUIT",
    "SIGSTOP",
    "SIGCONT",
    "SIGUSR1",
    "SIGUSR2",
}

_QUARANTINE_FORBIDDEN_PREFIXES = ("/proc", "/sys", "/dev", "/run", "/etc")


def _as_dict(v: Any, field: str) -> Dict[str, Any]:
    if v is None:
        return {}
    if not isinstance(v, dict):
        raise HTTPException(status_code=422, detail=f"{field} must be an object")
    return dict(v)


def _as_bool(v: Any, field: str) -> bool:
    if isinstance(v, bool):
        return v
    raise HTTPException(status_code=422, detail=f"{field} must be a boolean")


def _as_int(v: Any, field: str, *, min_value: int, max_value: int) -> int:
    if isinstance(v, bool):
        raise HTTPException(status_code=422, detail=f"{field} must be an integer")
    try:
        n = int(v)
    except Exception:
        raise HTTPException(status_code=422, detail=f"{field} must be an integer") from None
    if n < min_value or n > max_value:
        raise HTTPException(status_code=422, detail=f"{field} must be between {min_value} and {max_value}")
    return n


def _as_str(v: Any, field: str, *, max_length: int) -> str:
    if not isinstance(v, str):
        raise HTTPException(status_code=422, detail=f"{field} must be a string")
    s = v.strip()
    if len(s) > max_length:
        raise HTTPException(status_code=422, detail=f"{field} must be at most {max_length} characters")
    return s


def _validate_collect_triage_bundle_payload(raw_payload: Dict[str, Any]) -> Dict[str, Any]:
    payload = _as_dict(raw_payload, "payload")
    allowed_root = {"collectors", "limits", "redaction"}
    unknown = sorted([k for k in payload.keys() if k not in allowed_root])
    if unknown:
        raise HTTPException(status_code=422, detail=f"payload has unsupported keys: {', '.join(unknown)}")

    out: Dict[str, Any] = {}

    collectors_in = _as_dict(payload.get("collectors"), "payload.collectors")
    collectors_allowed = {
        "runtime",
        "host",
        "processes",
        "network",
        "auth_log",
        "recent_events",
        "effective_config",
    }
    collectors_unknown = sorted([k for k in collectors_in.keys() if k not in collectors_allowed])
    if collectors_unknown:
        raise HTTPException(
            status_code=422,
            detail=f"payload.collectors has unsupported keys: {', '.join(collectors_unknown)}",
        )
    out["collectors"] = {
        "runtime": _as_bool(collectors_in.get("runtime", True), "payload.collectors.runtime"),
        "host": _as_bool(collectors_in.get("host", True), "payload.collectors.host"),
        "processes": _as_bool(collectors_in.get("processes", True), "payload.collectors.processes"),
        "network": _as_bool(collectors_in.get("network", True), "payload.collectors.network"),
        "auth_log": _as_bool(collectors_in.get("auth_log", True), "payload.collectors.auth_log"),
        "recent_events": _as_bool(collectors_in.get("recent_events", True), "payload.collectors.recent_events"),
        "effective_config": _as_bool(
            collectors_in.get("effective_config", True),
            "payload.collectors.effective_config",
        ),
    }

    limits_in = _as_dict(payload.get("limits"), "payload.limits")
    out["limits"] = {
        "max_auth_log_lines": _as_int(
            limits_in.get("max_auth_log_lines", 500),
            "payload.limits.max_auth_log_lines",
            min_value=10,
            max_value=5000,
        ),
        "max_processes": _as_int(
            limits_in.get("max_processes", 200),
            "payload.limits.max_processes",
            min_value=10,
            max_value=2000,
        ),
        "max_connections": _as_int(
            limits_in.get("max_connections", 200),
            "payload.limits.max_connections",
            min_value=10,
            max_value=2000,
        ),
        "max_event_count": _as_int(
            limits_in.get("max_event_count", 300),
            "payload.limits.max_event_count",
            min_value=10,
            max_value=5000,
        ),
    }

    redaction_in = _as_dict(payload.get("redaction"), "payload.redaction")
    out["redaction"] = {
        "mask_secrets": _as_bool(redaction_in.get("mask_secrets", True), "payload.redaction.mask_secrets"),
    }
    return out


def _validate_refresh_runtime_config_payload(raw_payload: Dict[str, Any]) -> Dict[str, Any]:
    payload = _as_dict(raw_payload, "payload")
    if payload:
        unknown = ", ".join(sorted(payload.keys()))
        raise HTTPException(
            status_code=422,
            detail=f"payload has unsupported keys for refresh_runtime_config: {unknown}",
        )
    return {}


def _validate_trigger_inventory_snapshot_payload(raw_payload: Dict[str, Any]) -> Dict[str, Any]:
    payload = _as_dict(raw_payload, "payload")
    allowed_root = {"limits"}
    unknown = sorted([k for k in payload.keys() if k not in allowed_root])
    if unknown:
        raise HTTPException(
            status_code=422,
            detail=f"payload has unsupported keys: {', '.join(unknown)}",
        )
    limits_in = _as_dict(payload.get("limits"), "payload.limits")
    limits_unknown = sorted([k for k in limits_in.keys() if k not in {"max_processes", "max_connections"}])
    if limits_unknown:
        raise HTTPException(
            status_code=422,
            detail=f"payload.limits has unsupported keys: {', '.join(limits_unknown)}",
        )
    return {
        "limits": {
            "max_processes": _as_int(
                limits_in.get("max_processes", 200),
                "payload.limits.max_processes",
                min_value=10,
                max_value=2000,
            ),
            "max_connections": _as_int(
                limits_in.get("max_connections", 200),
                "payload.limits.max_connections",
                min_value=10,
                max_value=2000,
            ),
        }
    }


def _validate_trigger_topology_discovery_payload(raw_payload: Dict[str, Any]) -> Dict[str, Any]:
    payload = _as_dict(raw_payload, "payload")
    allowed_root = {"reason"}
    unknown = sorted([k for k in payload.keys() if k not in allowed_root])
    if unknown:
        raise HTTPException(
            status_code=422,
            detail=f"payload has unsupported keys: {', '.join(unknown)}",
        )
    reason = str(payload.get("reason") or "").strip()
    if len(reason) > 160:
        raise HTTPException(status_code=422, detail="payload.reason must be at most 160 characters")
    return {"reason": reason} if reason else {}


def _validate_kill_process_payload(raw_payload: Dict[str, Any]) -> Dict[str, Any]:
    payload = _as_dict(raw_payload, "payload")
    allowed_root = {"target", "signal", "dry_run"}
    unknown = sorted([k for k in payload.keys() if k not in allowed_root])
    if unknown:
        raise HTTPException(status_code=422, detail=f"payload has unsupported keys: {', '.join(unknown)}")

    target_in = _as_dict(payload.get("target"), "payload.target")
    target_unknown = sorted([k for k in target_in.keys() if k not in {"pid", "name"}])
    if target_unknown:
        raise HTTPException(status_code=422, detail=f"payload.target has unsupported keys: {', '.join(target_unknown)}")

    has_pid = target_in.get("pid") is not None
    has_name = isinstance(target_in.get("name"), str) and target_in.get("name").strip() != ""
    if has_pid == has_name:
        raise HTTPException(status_code=422, detail="payload.target requires exactly one of pid or name")

    target_out: Dict[str, Any] = {}
    if has_pid:
        target_out["pid"] = _as_int(target_in.get("pid"), "payload.target.pid", min_value=2, max_value=2147483647)
    else:
        target_out["name"] = _as_str(target_in.get("name"), "payload.target.name", max_length=128)

    signal = str(payload.get("signal") or "SIGTERM").strip().upper()
    if not signal.startswith("SIG"):
        signal = "SIG" + signal
    if signal not in _ALLOWED_SIGNALS:
        raise HTTPException(status_code=422, detail="payload.signal is not supported")

    return {
        "target": target_out,
        "signal": signal,
        "dry_run": _as_bool(payload.get("dry_run", False), "payload.dry_run"),
    }


def _validate_firewall_payload(raw_payload: Dict[str, Any]) -> Dict[str, Any]:
    payload = _as_dict(raw_payload, "payload")
    allowed_root = {"ip", "port", "protocol", "comment", "dry_run"}
    unknown = sorted([k for k in payload.keys() if k not in allowed_root])
    if unknown:
        raise HTTPException(status_code=422, detail=f"payload has unsupported keys: {', '.join(unknown)}")

    ip = _as_str(payload.get("ip"), "payload.ip", max_length=64) if payload.get("ip") is not None else ""
    if not ip:
        raise HTTPException(status_code=422, detail="payload.ip is required")
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=422, detail="payload.ip is not a valid IP address") from None

    out: Dict[str, Any] = {"ip": ip}
    if payload.get("protocol") is not None:
        protocol = _as_str(payload.get("protocol"), "payload.protocol", max_length=8).lower()
        if protocol and protocol not in {"tcp", "udp"}:
            raise HTTPException(status_code=422, detail="payload.protocol must be tcp or udp")
        if protocol:
            out["protocol"] = protocol
    if payload.get("port") is not None:
        out["port"] = _as_int(payload.get("port"), "payload.port", min_value=1, max_value=65535)
        out.setdefault("protocol", "tcp")
    if payload.get("comment") is not None:
        out["comment"] = _as_str(payload.get("comment"), "payload.comment", max_length=128)
    out["dry_run"] = _as_bool(payload.get("dry_run", False), "payload.dry_run")
    return out


def _validate_quarantine_file_payload(raw_payload: Dict[str, Any]) -> Dict[str, Any]:
    payload = _as_dict(raw_payload, "payload")
    allowed_root = {"path", "quarantine_dir", "compute_hash", "dry_run"}
    unknown = sorted([k for k in payload.keys() if k not in allowed_root])
    if unknown:
        raise HTTPException(status_code=422, detail=f"payload has unsupported keys: {', '.join(unknown)}")

    path = _as_str(payload.get("path"), "payload.path", max_length=4096) if payload.get("path") is not None else ""
    if not path:
        raise HTTPException(status_code=422, detail="payload.path is required")
    if not path.startswith("/"):
        raise HTTPException(status_code=422, detail="payload.path must be absolute")
    norm = posixpath.normpath(path)
    for prefix in _QUARANTINE_FORBIDDEN_PREFIXES:
        if norm == prefix or norm.startswith(prefix + "/"):
            raise HTTPException(status_code=422, detail=f"payload.path is in a protected location: {prefix}")

    out: Dict[str, Any] = {"path": path}
    if payload.get("quarantine_dir") is not None:
        qd = _as_str(payload.get("quarantine_dir"), "payload.quarantine_dir", max_length=4096)
        if qd:
            if not qd.startswith("/"):
                raise HTTPException(status_code=422, detail="payload.quarantine_dir must be absolute")
            out["quarantine_dir"] = qd
    out["compute_hash"] = _as_bool(payload.get("compute_hash", True), "payload.compute_hash")
    out["dry_run"] = _as_bool(payload.get("dry_run", False), "payload.dry_run")
    return out


def _validate_run_shell_command_payload(raw_payload: Dict[str, Any]) -> Dict[str, Any]:
    payload = _as_dict(raw_payload, "payload")
    allowed_root = {"command", "timeout_seconds", "working_dir"}
    unknown = sorted([k for k in payload.keys() if k not in allowed_root])
    if unknown:
        raise HTTPException(status_code=422, detail=f"payload has unsupported keys: {', '.join(unknown)}")

    command = _as_str(payload.get("command"), "payload.command", max_length=4096) if payload.get("command") is not None else ""
    if not command:
        raise HTTPException(status_code=422, detail="payload.command is required")

    out: Dict[str, Any] = {"command": command}
    if payload.get("timeout_seconds") is not None:
        out["timeout_seconds"] = _as_int(
            payload.get("timeout_seconds"),
            "payload.timeout_seconds",
            min_value=1,
            max_value=300,
        )
    if payload.get("working_dir") is not None:
        working_dir = _as_str(payload.get("working_dir"), "payload.working_dir", max_length=4096)
        if working_dir:
            if not working_dir.startswith("/"):
                raise HTTPException(status_code=422, detail="payload.working_dir must be absolute")
            out["working_dir"] = working_dir
    return out


@dataclass(frozen=True)
class ActionDefinition:
    key: str
    label: str
    category: str
    risk_level: str
    reversible: bool
    requires_confirmation: bool
    estimated_duration_seconds: int
    undo_action: Optional[str]
    description: str
    validate_payload: Callable[[Dict[str, Any]], Dict[str, Any]]


ACTION_REGISTRY: Dict[str, ActionDefinition] = {
    "collect_triage_bundle": ActionDefinition(
        key="collect_triage_bundle",
        label="Collect Triage Bundle",
        category="forensics",
        risk_level="low",
        reversible=True,
        requires_confirmation=False,
        estimated_duration_seconds=30,
        undo_action=None,
        description="Collect host and runtime triage data from the selected agent.",
        validate_payload=_validate_collect_triage_bundle_payload,
    ),
    "trigger_inventory_snapshot": ActionDefinition(
        key="trigger_inventory_snapshot",
        label="Trigger Inventory Snapshot",
        category="forensics",
        risk_level="low",
        reversible=True,
        requires_confirmation=False,
        estimated_duration_seconds=15,
        undo_action=None,
        description="Capture a focused host and runtime inventory snapshot from the agent.",
        validate_payload=_validate_trigger_inventory_snapshot_payload,
    ),
    "refresh_runtime_config": ActionDefinition(
        key="refresh_runtime_config",
        label="Refresh Runtime Config",
        category="diagnostics",
        risk_level="low",
        reversible=True,
        requires_confirmation=False,
        estimated_duration_seconds=10,
        undo_action=None,
        description="Pull and apply the latest runtime configuration immediately.",
        validate_payload=_validate_refresh_runtime_config_payload,
    ),
    "trigger_topology_discovery": ActionDefinition(
        key="trigger_topology_discovery",
        label="Trigger Topology Discovery",
        category="diagnostics",
        risk_level="low",
        reversible=True,
        requires_confirmation=False,
        estimated_duration_seconds=60,
        undo_action=None,
        description="Run an on-demand network topology discovery sweep.",
        validate_payload=_validate_trigger_topology_discovery_payload,
    ),
    "kill_process": ActionDefinition(
        key="kill_process",
        label="Kill Process",
        category="containment",
        risk_level="high",
        reversible=False,
        requires_confirmation=True,
        estimated_duration_seconds=5,
        undo_action=None,
        description="Send a termination signal to one or more processes by PID or name.",
        validate_payload=_validate_kill_process_payload,
    ),
    "block_outbound_ip": ActionDefinition(
        key="block_outbound_ip",
        label="Block Outbound IP",
        category="containment",
        risk_level="medium",
        reversible=True,
        requires_confirmation=True,
        estimated_duration_seconds=5,
        undo_action="unblock_outbound_ip",
        description="Drop outbound traffic to a specific IP via the host firewall.",
        validate_payload=_validate_firewall_payload,
    ),
    "unblock_outbound_ip": ActionDefinition(
        key="unblock_outbound_ip",
        label="Unblock Outbound IP",
        category="containment",
        risk_level="low",
        reversible=True,
        requires_confirmation=False,
        estimated_duration_seconds=5,
        undo_action=None,
        description="Remove a previously added outbound block rule from the host firewall.",
        validate_payload=_validate_firewall_payload,
    ),
    "quarantine_file": ActionDefinition(
        key="quarantine_file",
        label="Quarantine File",
        category="containment",
        risk_level="high",
        reversible=True,
        requires_confirmation=True,
        estimated_duration_seconds=10,
        undo_action=None,
        description="Move a file to the agent quarantine directory with 000 permissions.",
        validate_payload=_validate_quarantine_file_payload,
    ),
    "run_shell_command": ActionDefinition(
        key="run_shell_command",
        label="Run Shell Command",
        category="containment",
        risk_level="critical",
        reversible=False,
        requires_confirmation=True,
        estimated_duration_seconds=30,
        undo_action=None,
        description="Execute a shell command on the agent host. Gated by agent config and an optional command allowlist.",
        validate_payload=_validate_run_shell_command_payload,
    ),
}


def get_definition(action_type: str) -> Optional[ActionDefinition]:
    return ACTION_REGISTRY.get(action_type)


def action_catalog() -> List[Dict[str, Any]]:
    return [
        {
            "key": d.key,
            "label": d.label,
            "category": d.category,
            "risk_level": d.risk_level,
            "reversible": d.reversible,
            "requires_confirmation": d.requires_confirmation,
            "estimated_duration_seconds": d.estimated_duration_seconds,
            "undo_action": d.undo_action,
            "description": d.description,
        }
        for d in ACTION_REGISTRY.values()
    ]
