from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping


_FIXED_VERSION_RE = re.compile(r">=\s*([^\s,;]+)")
_LOC_VERSION_RE = re.compile(r"@([^@\s]+)$")
_SENSITIVE_SCAN_SCOPE_KEYS = {"request_token", "trigger_token", "scan_now_token", "host_root"}
_SENSITIVE_SCAN_CONFIG_KEYS = {"request_token", "trigger_token", "scan_now_token", "scan_now_at", "osv_url", "host_root"}


def _value(row: Any, key: str, default: Any = None) -> Any:
    if isinstance(row, Mapping):
        return row.get(key, default)
    return getattr(row, key, default)


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return list(value)
    if isinstance(value, tuple):
        return list(value)
    return []


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _lower(value: Any) -> str:
    return str(value or "").strip().lower()


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        out = float(value)
    except Exception:
        return default
    if out != out:
        return default
    return out


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = _lower(value)
    return text in {"1", "true", "t", "yes", "y", "on"}


def _dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        if raw.endswith("Z"):
            raw = f"{raw[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(raw)
        except Exception:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    return None


def _iso(value: Any) -> str | None:
    parsed = _dt(value)
    return parsed.isoformat() if parsed is not None else None


def _dedupe_texts(values: list[Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = _text(value)
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(text)
    return out


def _dedupe_ints(values: list[Any]) -> list[int]:
    out: list[int] = []
    seen: set[int] = set()
    for value in values:
        try:
            num = int(value)
        except Exception:
            continue
        if num in seen:
            continue
        seen.add(num)
        out.append(num)
    return out


def _sanitize_mapping(value: Any, *, blocked_keys: set[str]) -> dict[str, Any]:
    raw = _as_dict(value)
    if not raw:
        return {}
    out: dict[str, Any] = {}
    for key, item in raw.items():
        normalized_key = _lower(key)
        if normalized_key in blocked_keys:
            continue
        key_text = _text(key)
        if not key_text:
            continue
        out[key_text] = item
    return out


def serialize_scan(row: Any) -> dict[str, Any]:
    queued_at = _dt(_value(row, "queued_at"))
    started_at = _dt(_value(row, "started_at"))
    finished_at = _dt(_value(row, "finished_at"))
    created_at = _dt(_value(row, "created_at"))
    updated_at = _dt(_value(row, "updated_at"))
    last_progress_at = _dt(_value(row, "last_progress_at")) or finished_at or started_at or queued_at or updated_at or created_at
    queued_at = queued_at or started_at or last_progress_at or updated_at or created_at

    duration_ms: int | None = None
    if started_at is not None and last_progress_at is not None:
        end_at = finished_at or last_progress_at
        duration_ms = max(0, int((end_at - started_at).total_seconds() * 1000))

    created_at = created_at or updated_at or queued_at or last_progress_at
    updated_at = updated_at or created_at or last_progress_at or queued_at

    phase_timestamps: dict[str, str] = {}
    for key, value in _as_dict(_value(row, "phase_timestamps", {})).items():
        phase_name = _text(key)
        phase_at = _iso(value)
        if not phase_name or not phase_at:
            continue
        phase_timestamps[phase_name.lower()] = phase_at

    lifecycle_state = _text(_value(row, "lifecycle_state")) or _text(_value(row, "status")) or "queued"
    return {
        "id": _to_int(_value(row, "id")),
        "scan_uuid": _text(_value(row, "scan_uuid")) or "",
        "reporter_agent_id": _text(_value(row, "reporter_agent_id")),
        "target": _text(_value(row, "target")),
        "tool": _text(_value(row, "tool")) or "unknown",
        "tool_version": _text(_value(row, "tool_version")),
        "status": lifecycle_state,
        "lifecycle_state": lifecycle_state,
        "current_phase": _text(_value(row, "current_phase")) or lifecycle_state,
        "queued_at": _iso(queued_at),
        "acknowledged_at": _iso(_value(row, "acknowledged_at")),
        "started_at": _iso(started_at),
        "finished_at": _iso(finished_at),
        "last_progress_at": _iso(last_progress_at),
        "duration_ms": duration_ms,
        "trigger_source": _text(_value(row, "trigger_source")) or "scheduled",
        "error_summary": _text(_value(row, "error_summary")),
        "scope": _sanitize_mapping(_value(row, "scope", {}), blocked_keys=_SENSITIVE_SCAN_SCOPE_KEYS),
        "config": _sanitize_mapping(_value(row, "config", {}), blocked_keys=_SENSITIVE_SCAN_CONFIG_KEYS),
        "stats": _as_dict(_value(row, "stats", {})),
        "phase_timestamps": phase_timestamps,
        "created_at": _iso(created_at),
        "updated_at": _iso(updated_at),
    }


def _severity_points(rank: int) -> float:
    if rank >= 4:
        return 34.0
    if rank == 3:
        return 26.0
    if rank == 2:
        return 16.0
    if rank == 1:
        return 8.0
    return 0.0


def _confidence_points(confidence: int) -> tuple[float, str | None]:
    if confidence >= 90:
        return 14.0, "high confidence"
    if confidence >= 75:
        return 10.0, "strong confidence"
    if confidence >= 60:
        return 6.0, "moderate confidence"
    return 2.0 if confidence > 0 else 0.0, None


def _remediation_from_version(name: str | None, fixed_version: str | None, installed_version: str | None) -> str | None:
    if not fixed_version:
        return None
    if name and installed_version:
        return f"Upgrade {name} from {installed_version} to {fixed_version} or later."
    if name:
        return f"Upgrade {name} to {fixed_version} or later."
    return f"Upgrade to {fixed_version} or later."


def derive_component(row: Any) -> dict[str, Any]:
    asset = _as_dict(_value(row, "asset", {}))
    evidence = _as_dict(_value(row, "evidence", {}))
    asset_package = _as_dict(asset.get("package"))
    asset_component = _as_dict(asset.get("component"))
    evidence_package = _as_dict(evidence.get("package"))
    evidence_dependency = _as_dict(evidence.get("dependency"))
    osv = _as_dict(evidence.get("osv"))

    name = (
        _text(asset_package.get("name"))
        or _text(asset_component.get("name"))
        or _text(evidence_package.get("name"))
        or _text(evidence_dependency.get("name"))
    )
    installed_version = (
        _text(asset_package.get("version"))
        or _text(asset_component.get("version"))
        or _text(evidence_package.get("version"))
        or _text(evidence_dependency.get("version"))
    )
    location = _text(_value(row, "location"))
    if installed_version is None and location:
        loc_match = _LOC_VERSION_RE.search(location)
        if loc_match:
            installed_version = _text(loc_match.group(1))

    fixed_version = _text(osv.get("fixed"))
    remediation = _text(_value(row, "remediation"))
    if fixed_version is None and remediation:
        rem_match = _FIXED_VERSION_RE.search(remediation)
        if rem_match:
            fixed_version = _text(rem_match.group(1))

    kind = "component" if asset_component else "package"
    if not asset_component and evidence_dependency:
        kind = "component"

    return {
        "kind": kind,
        "name": name,
        "installed_version": installed_version,
        "fixed_version": fixed_version,
        "ecosystem": _text(asset_package.get("ecosystem"))
        or _text(asset_component.get("ecosystem"))
        or _text(evidence_dependency.get("ecosystem")),
        "manager": _text(asset_package.get("manager")) or _text(evidence_dependency.get("manager")),
        "purl": _text(asset_component.get("purl")) or _text(evidence_dependency.get("purl")),
    }


def derive_exposure(row: Any) -> dict[str, Any]:
    asset = _as_dict(_value(row, "asset", {}))
    evidence = _as_dict(_value(row, "evidence", {}))
    asset_exposure = _as_dict(asset.get("exposure"))
    evidence_exposure = _as_dict(evidence.get("exposure"))
    analysis = _as_dict(evidence.get("analysis"))

    service_hints = _dedupe_texts(
        _as_list(asset_exposure.get("service_hints")) + _as_list(evidence_exposure.get("service_hints"))
    )
    exposed_ports = _dedupe_ints(
        _as_list(asset_exposure.get("exposed_ports"))
        + _as_list(analysis.get("exposed_ports"))
        + _as_list(evidence_exposure.get("exposed_ports"))
    )

    observed = _to_bool(asset_exposure.get("has_exposed_ports")) or len(exposed_ports) > 0
    package_relevant = _to_bool(analysis.get("package_network_facing"))
    network_attack_vector = _to_bool(analysis.get("network_attack_vector")) or "/AV:N" in str(_value(row, "cvss") or "").upper()
    surface_score = max(
        _to_int(analysis.get("exposure_score")),
        _to_int(asset_exposure.get("surface_score")),
        _to_int(evidence_exposure.get("surface_score")),
    )
    inferred = (not observed) and (package_relevant or network_attack_vector or surface_score >= 50)
    source = "observed" if observed else "inferred" if inferred else "none"

    return {
        "source": source,
        "observed": observed,
        "inferred": inferred,
        "externally_exposed": observed,
        "package_relevant": package_relevant,
        "surface_score": surface_score,
        "service_hints": service_hints,
        "exposed_ports": exposed_ports,
    }


def derive_asset_display(row: Any) -> str:
    asset_agent_id = _text(_value(row, "asset_agent_id"))
    if asset_agent_id:
        return f"agent:{asset_agent_id}"
    target = _text(_value(row, "target"))
    if target:
        return target
    asset = _as_dict(_value(row, "asset", {}))
    for key in ("hostname", "fqdn", "ip", "ip_address", "url"):
        value = _text(asset.get(key))
        if value:
            return value
    return _text(_value(row, "asset_key")) or "-"


def derive_asset_context(row: Any) -> list[str]:
    asset = _as_dict(_value(row, "asset", {}))
    component = derive_component(row)
    display = derive_asset_display(row)
    context: list[str] = []

    target = _text(_value(row, "target"))
    asset_key = _text(_value(row, "asset_key"))
    reporter = _text(_value(row, "reporter_agent_id"))
    if target and target != display:
        context.append(target)
    if asset_key and asset_key != display:
        context.append(asset_key)
    if reporter:
        context.append(f"reported by {reporter}")
    if component.get("manager"):
        context.append(f"manager {component['manager']}")
    if component.get("ecosystem"):
        context.append(f"ecosystem {component['ecosystem']}")
    for key in ("os_name", "platform", "hostname", "arch"):
        value = _text(asset.get(key))
        if value and value not in display and value not in context:
            context.append(value)
    return context[:6]


def derive_remediation_guidance(row: Any, component: dict[str, Any] | None = None) -> str | None:
    remediation = _text(_value(row, "remediation"))
    if remediation:
        return remediation
    component = component or derive_component(row)
    return _remediation_from_version(
        component.get("name"),
        component.get("fixed_version"),
        component.get("installed_version"),
    )


def derive_priority(row: Any) -> dict[str, Any]:
    component = derive_component(row)
    exposure = derive_exposure(row)
    remediation_guidance = derive_remediation_guidance(row, component)
    now = datetime.now(timezone.utc)
    last_seen = _dt(_value(row, "last_seen_at"))
    confidence = _to_int(_value(row, "confidence"))
    severity_rank = _to_int(_value(row, "severity_rank"))
    cvss_score = _to_float(_value(row, "cvss_score"))
    occurrences = max(1, _to_int(_value(row, "occurrences"), 1))
    observation_state = _lower(_value(row, "observation_state"))
    operator_disposition = _lower(_value(row, "operator_disposition"))

    score = _severity_points(severity_rank)
    factors: list[str] = []

    severity = _lower(_value(row, "severity"))
    if severity and severity != "unknown":
        factors.append(f"{severity} severity")

    conf_points, conf_label = _confidence_points(confidence)
    score += conf_points
    if conf_label:
        factors.append(conf_label)

    if cvss_score >= 9.0:
        score += 10.0
        factors.append("CVSS 9+")
    elif cvss_score >= 7.0:
        score += 7.0
        factors.append("CVSS 7+")

    if _text(_value(row, "cve")):
        score += 4.0
        factors.append("known CVE")

    if exposure["externally_exposed"]:
        score += 14.0
        factors.append("externally exposed asset")
    elif exposure["source"] == "inferred":
        score += 8.0
        factors.append("network exposure inferred")

    if exposure["package_relevant"]:
        score += 6.0
        factors.append("component matches exposed service")

    if exposure["surface_score"] >= 60:
        score += 6.0
        factors.append("high exposure surface")
    elif exposure["surface_score"] >= 30:
        score += 3.0

    if remediation_guidance:
        score += 6.0
        factors.append("fix available")

    if occurrences >= 5:
        score += 8.0
        factors.append("repeatedly observed")
    elif occurrences >= 2:
        score += 4.0
        factors.append("seen multiple times")

    if last_seen is not None:
        age = now - last_seen
        if age <= timedelta(days=1):
            score += 8.0
            factors.append("seen in last 24h")
        elif age <= timedelta(days=7):
            score += 4.0
            factors.append("recently observed")

    if _text(_value(row, "asset_agent_id")):
        score += 2.0
        factors.append("managed asset")

    if observation_state == "awaiting_verification":
        score -= 10.0
        factors.append("pending verification")
    elif observation_state == "resolved":
        score -= 25.0
        factors.append("no longer observed")

    if operator_disposition == "accepted_risk":
        score -= 8.0
        factors.append("risk accepted")
    elif operator_disposition == "suppressed":
        score -= 14.0
        factors.append("suppressed")

    if score < 0:
        score = 0.0
    if score > 100:
        score = 100.0

    deduped = _dedupe_texts(factors)
    return {
        "score": round(score, 1),
        "factors": deduped,
    }


def derive_risk_summary(row: Any, component: dict[str, Any] | None = None, exposure: dict[str, Any] | None = None) -> str | None:
    component = component or derive_component(row)
    exposure = exposure or derive_exposure(row)
    severity = _lower(_value(row, "severity"))
    severity_label = severity if severity and severity != "unknown" else None
    cvss_score = _to_float(_value(row, "cvss_score"))
    occurrences = max(1, _to_int(_value(row, "occurrences"), 1))

    fragments: list[str] = []
    name = _text(component.get("name"))
    installed_version = _text(component.get("installed_version"))
    fixed_version = _text(component.get("fixed_version"))

    if name and installed_version:
        fragments.append(f"{name} {installed_version} is affected")
    elif name:
        fragments.append(f"{name} is affected")
    elif _text(_value(row, "title")):
        fragments.append(_text(_value(row, "title")) or "")

    if severity_label and cvss_score >= 7.0:
        fragments.append(f"{severity_label} severity with CVSS {cvss_score:.1f}")
    elif severity_label:
        fragments.append(f"{severity_label} severity")

    if exposure["externally_exposed"]:
        fragments.append("the asset shows externally reachable services")
    elif exposure["source"] == "inferred":
        fragments.append("network exposure is inferred from scanner context")

    if occurrences >= 2:
        fragments.append(f"it has been observed {occurrences} times")

    if fixed_version:
        fragments.append(f"a fix is available in {fixed_version}")

    out = ". ".join(fragment.strip() for fragment in fragments if fragment.strip())
    return f"{out}." if out else None


def serialize_finding(row: Any) -> dict[str, Any]:
    component = derive_component(row)
    exposure = derive_exposure(row)
    priority = derive_priority(row)
    remediation_guidance = derive_remediation_guidance(row, component)

    return {
        "id": _to_int(_value(row, "id")),
        "scan_id": _value(row, "scan_id"),
        "asset_key": _text(_value(row, "asset_key")) or "",
        "asset_agent_id": _text(_value(row, "asset_agent_id")),
        "reporter_agent_id": _text(_value(row, "reporter_agent_id")),
        "target": _text(_value(row, "target")),
        "asset": _as_dict(_value(row, "asset", {})),
        "source": _text(_value(row, "source")) or "unknown",
        "external_id": _text(_value(row, "external_id")),
        "fingerprint": _text(_value(row, "fingerprint")) or "",
        "severity": _text(_value(row, "severity")) or "unknown",
        "severity_rank": _to_int(_value(row, "severity_rank")),
        "confidence": _to_int(_value(row, "confidence")),
        "title": _text(_value(row, "title")) or "vulnerability detected",
        "description": _text(_value(row, "description")),
        "remediation": _text(_value(row, "remediation")),
        "cve": _text(_value(row, "cve")),
        "cwe": _text(_value(row, "cwe")),
        "cvss": _text(_value(row, "cvss")),
        "location": _text(_value(row, "location")),
        "tags": _dedupe_texts(_as_list(_value(row, "tags", []))),
        "evidence": _as_dict(_value(row, "evidence", {})),
        "status": _text(_value(row, "status")) or "open",
        "is_suppressed": _to_bool(_value(row, "is_suppressed")),
        "observation_state": _text(_value(row, "observation_state")) or "observed",
        "operator_disposition": _text(_value(row, "operator_disposition")) or "open",
        "first_seen_at": _iso(_value(row, "first_seen_at")),
        "last_seen_at": _iso(_value(row, "last_seen_at")),
        "occurrences": max(1, _to_int(_value(row, "occurrences"), 1)),
        "updated_at": _iso(_value(row, "updated_at")),
        "component": component,
        "exposure": exposure,
        "asset_display": derive_asset_display(row),
        "asset_context": derive_asset_context(row),
        "risk_summary": derive_risk_summary(row, component, exposure),
        "remediation_guidance": remediation_guidance,
        "repeated_observation": max(1, _to_int(_value(row, "occurrences"), 1)) > 1,
        "priority": priority,
    }


def serialize_risk_item(row: Any) -> dict[str, Any]:
    component = derive_component(row)
    exposure = derive_exposure(row)
    priority = derive_priority(row)
    risk_score = _to_float(_value(row, "risk_score"), priority["score"])
    if risk_score <= 0:
        risk_score = priority["score"]

    cvss_score = _to_float(_value(row, "cvss_score"))
    has_fix = _to_bool(_value(row, "has_fix")) or bool(component.get("fixed_version")) or bool(
        derive_remediation_guidance(row, component)
    )

    return {
        "id": _to_int(_value(row, "id")),
        "asset_key": _text(_value(row, "asset_key")) or "",
        "asset_agent_id": _text(_value(row, "asset_agent_id")),
        "target": _text(_value(row, "target")),
        "title": _text(_value(row, "title")) or "vulnerability detected",
        "cve": _text(_value(row, "cve")),
        "severity": _text(_value(row, "severity")) or "unknown",
        "confidence": _to_int(_value(row, "confidence")),
        "occurrences": max(1, _to_int(_value(row, "occurrences"), 1)),
        "last_seen_at": _iso(_value(row, "last_seen_at")),
        "remediation": _text(_value(row, "remediation")),
        "cvss": _text(_value(row, "cvss")),
        "cvss_score": cvss_score,
        "has_fix": has_fix,
        "internet_exposed": exposure["externally_exposed"] or exposure["source"] == "inferred",
        "exploit_likely": _to_bool(_value(row, "exploit_likely")) or cvss_score >= 7.0,
        "risk_score": round(risk_score, 1),
        "component_name": component.get("name"),
        "installed_version": component.get("installed_version"),
        "fixed_version": component.get("fixed_version"),
        "asset_display": derive_asset_display(row),
        "risk_summary": derive_risk_summary(row, component, exposure),
        "priority_factors": priority["factors"],
        "exposure_source": exposure["source"],
        "service_hints": exposure["service_hints"],
    }
