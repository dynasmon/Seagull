from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Sequence, Tuple

from app.features.attack_chain.domain.types import stage_rank, StepCandidate


EVIDENCE_CLASSES = ("observed", "strongly_supported", "inferred", "weakly_inferred")

_INFERRED_EVENT_TYPES = {"beacon_suspect", "c2_suspect", "exfil_suspect", "egress_anomaly"}

_SOURCE_BY_EVENT = {
    "proc_exec": "process_telemetry",
    "ebpf_exec": "process_telemetry",
    "fim_change": "file_integrity",
    "persistence_systemd": "persistence_telemetry",
    "persistence_cron": "persistence_telemetry",
    "ssh_key_change": "persistence_telemetry",
    "ssh_auth": "auth_telemetry",
    "sudo_cmd": "privileged_command",
    "beacon_suspect": "network_heuristic",
    "c2_suspect": "network_heuristic",
    "exfil_suspect": "network_heuristic",
    "egress_anomaly": "network_heuristic",
}

_RELIABILITY_BY_SOURCE = {
    "process_telemetry": 92,
    "file_integrity": 90,
    "persistence_telemetry": 88,
    "privileged_command": 78,
    "auth_telemetry": 74,
    "network_heuristic": 58,
    "correlated_context": 45,
    "generic_signal": 60,
}

_FAMILIES_BY_KIND = {
    "ssh_fail": ["auth"],
    "ssh_accept": ["auth"],
    "ssh_bruteforce": ["auth"],
    "ssh_bruteforce_success": ["auth"],
    "ssh_new_source": ["auth"],
    "sudo_allowlisted": ["privilege"],
    "sudo_defense_evasion": ["tamper", "privilege"],
    "sudo_priv_escalation": ["privilege", "process"],
    "sudo_remote_exec": ["process", "network"],
    "sudo_lolbin": ["process", "privilege"],
    "sudo_routine": ["privilege"],
    "sudo_exec": ["privilege", "process"],
    "exec_remote_fetch": ["process", "network"],
    "exec_reverse_shell": ["process", "network"],
    "exec_service_shell": ["process"],
    "exec_priv_escalation": ["process", "privilege"],
    "exec_lolbin": ["process"],
    "persistence": ["persistence", "file"],
    "tamper": ["tamper", "file"],
    "c2": ["network"],
    "exfil": ["network", "exfil"],
    "context": ["context"],
}

_DEFAULT_FAMILY_BY_STAGE = {
    "initial_access": ["auth"],
    "execution": ["process"],
    "persistence": ["persistence"],
    "privilege_escalation": ["privilege"],
    "defense_evasion": ["tamper"],
    "command_and_control": ["network"],
    "exfiltration": ["network", "exfil"],
}

_STAGE_SUPPORT_THRESHOLD = {
    "initial_access": 4.0,
    "execution": 6.0,
    "persistence": 6.8,
    "privilege_escalation": 6.5,
    "defense_evasion": 6.0,
    "command_and_control": 7.2,
    "exfiltration": 8.0,
}

_STAGE_PREREQ = {
    "execution": "initial_access",
    "persistence": "execution",
    "privilege_escalation": "execution",
    "defense_evasion": "execution",
    "command_and_control": "execution",
    "exfiltration": "command_and_control",
}

_PREREQ_MIN_SUPPORT = {
    "initial_access": 3.0,
    "execution": 4.5,
    "command_and_control": 5.0,
}


@dataclass(frozen=True)
class ScoredEvidence:
    score_delta: int
    confidence: int
    evidence_class: str
    evidence_nature: str
    evidence_source: str
    evidence_families: list[str]
    confidence_factors: list[str]
    missing_evidence: list[str]
    promote_stage: bool
    transition_allowed: bool
    transition_reason: str
    support_gain: float
    stage_support_snapshot: Dict[str, Any]
    context_patch: Dict[str, Any]


def _safe_dict(v: Any) -> Dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _to_float(v: Any, default: float = 0.0) -> float:
    try:
        if v is None or v == "":
            return float(default)
        return float(v)
    except Exception:
        return float(default)


def _to_int(v: Any, default: int = 0) -> int:
    try:
        if v is None or v == "":
            return int(default)
        return int(float(v))
    except Exception:
        return int(default)


def _clamp(v: float, low: float, high: float) -> float:
    return max(low, min(high, v))


def _parse_dt(v: Any) -> datetime | None:
    if isinstance(v, datetime):
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return None
        try:
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            parsed = datetime.fromisoformat(s)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except Exception:
            return None
    return None


def _stage_label(stage: str) -> str:
    return str(stage or "").replace("_", " ")


def _normalize_families(values: Sequence[str] | None) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for v in values or []:
        s = str(v or "").strip().lower()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def _families_for(candidate: StepCandidate, *, stage: str, event_type: str, kind: str) -> list[str]:
    explicit = _normalize_families(list(candidate.evidence_families or []))
    if explicit:
        return explicit
    by_kind = _normalize_families(_FAMILIES_BY_KIND.get(kind) or [])
    if by_kind:
        return by_kind
    by_event = {
        "proc_exec": ["process"],
        "ebpf_exec": ["process"],
        "sudo_cmd": ["privilege", "process"],
        "fim_change": ["file"],
        "persistence_systemd": ["persistence", "file"],
        "persistence_cron": ["persistence", "file"],
        "ssh_key_change": ["persistence", "auth"],
        "ssh_auth": ["auth"],
        "beacon_suspect": ["network"],
        "c2_suspect": ["network"],
        "exfil_suspect": ["network", "exfil"],
        "egress_anomaly": ["network"],
    }.get(event_type)
    if by_event:
        return _normalize_families(by_event)
    return _normalize_families(_DEFAULT_FAMILY_BY_STAGE.get(stage) or ["signal"])


def _nature_for(candidate: StepCandidate, *, event_type: str, source: str, kind: str) -> str:
    explicit = str(candidate.evidence_nature or "").strip().lower()
    if explicit in {"direct", "inferred"}:
        return explicit
    if source == "network_heuristic" or event_type in _INFERRED_EVENT_TYPES:
        return "inferred"
    if kind in {"ssh_new_source", "context"}:
        return "inferred"
    return "direct"


def _source_for(candidate: StepCandidate, *, event_type: str, kind: str) -> str:
    explicit = str(candidate.evidence_source or "").strip().lower()
    if explicit:
        return explicit
    if kind == "context":
        return "correlated_context"
    return _SOURCE_BY_EVENT.get(event_type, "generic_signal")


def _reliability_for(candidate: StepCandidate, *, source: str) -> int:
    explicit = _to_int(candidate.evidence_reliability, 0)
    if explicit > 0:
        return int(_clamp(explicit, 1, 99))
    return int(_RELIABILITY_BY_SOURCE.get(source, 60))


def _repeat_multiplier(repeats: int, evidence_class: str) -> float:
    if repeats <= 0:
        return 1.0
    if evidence_class == "weakly_inferred":
        if repeats == 1:
            return 0.45
        if repeats == 2:
            return 0.24
        return 0.12
    if evidence_class == "inferred":
        if repeats == 1:
            return 0.62
        if repeats == 2:
            return 0.38
        return 0.24
    if repeats == 1:
        return 0.72
    if repeats == 2:
        return 0.55
    return 0.36


def _normalize_stage_support(raw: Any) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    if not isinstance(raw, dict):
        return out
    for stage, state in raw.items():
        sk = str(stage or "").strip()
        if not sk:
            continue
        st = _safe_dict(state)
        out[sk] = {
            "support": float(_to_float(st.get("support"), 0.0)),
            "direct_support": float(_to_float(st.get("direct_support"), 0.0)),
            "inferred_support": float(_to_float(st.get("inferred_support"), 0.0)),
            "event_count": int(_to_int(st.get("event_count"), 0)),
            "observed_count": int(_to_int(st.get("observed_count"), 0)),
            "strong_count": int(_to_int(st.get("strong_count"), 0)),
            "inferred_count": int(_to_int(st.get("inferred_count"), 0)),
            "weak_count": int(_to_int(st.get("weak_count"), 0)),
            "max_confidence": int(_to_int(st.get("max_confidence"), 0)),
            "families": _normalize_families(st.get("families") if isinstance(st.get("families"), list) else []),
            "last_seen_at": str(st.get("last_seen_at") or "") if st.get("last_seen_at") else None,
            "last_missing_evidence": [
                str(x).strip() for x in (st.get("last_missing_evidence") if isinstance(st.get("last_missing_evidence"), list) else []) if str(x).strip()
            ][:5],
            "last_class": str(st.get("last_class") or "").strip() or None,
        }
    return out


def _normalize_nested_counts(raw: Any) -> Dict[str, Dict[str, int]]:
    out: Dict[str, Dict[str, int]] = {}
    if not isinstance(raw, dict):
        return out
    for stage, row in raw.items():
        sk = str(stage or "").strip()
        if not sk or not isinstance(row, dict):
            continue
        bucket: Dict[str, int] = {}
        for k, v in row.items():
            kk = str(k or "").strip().lower()
            if not kk:
                continue
            bucket[kk] = int(max(0, _to_int(v, 0)))
        out[sk] = bucket
    return out


def _normalize_root_counts(raw: Any) -> Dict[str, int]:
    out: Dict[str, int] = {}
    if not isinstance(raw, dict):
        return out
    for k, v in raw.items():
        kk = str(k or "").strip()
        if not kk:
            continue
        out[kk[:160]] = int(max(0, _to_int(v, 0)))
    return out


def _missing_hint_for_stage(stage: str) -> str:
    hints = {
        "initial_access": "Add explicit authentication abuse evidence",
        "execution": "Add direct process execution evidence",
        "persistence": "Add direct persistence artifact changes",
        "privilege_escalation": "Add stronger privilege escalation telemetry",
        "defense_evasion": "Add direct tamper or control-disable evidence",
        "command_and_control": "Add protocol-aware outbound command channel evidence",
        "exfiltration": "Add direct sustained outbound data transfer evidence",
    }
    return hints.get(stage, "Add stronger direct evidence")


def _quality_counter(ctx: Dict[str, Any]) -> Dict[str, int]:
    raw = _safe_dict(ctx.get("evidence_quality_counts_v2"))
    out: Dict[str, int] = {k: int(max(0, _to_int(raw.get(k), 0))) for k in EVIDENCE_CLASSES}
    return out


def _collect_related_families(stage: str, stage_support: Dict[str, Dict[str, Any]]) -> set[str]:
    related: set[str] = set()
    cur = stage_support.get(stage) or {}
    for fam in _normalize_families(cur.get("families") if isinstance(cur.get("families"), list) else []):
        related.add(fam)

    prereq = _STAGE_PREREQ.get(stage)
    if prereq:
        prev = stage_support.get(prereq) or {}
        for fam in _normalize_families(prev.get("families") if isinstance(prev.get("families"), list) else []):
            related.add(fam)
    return related


def _transition_decision(
    *,
    stage: str,
    predicted_stage_state: Dict[str, Any],
    stage_support: Dict[str, Dict[str, Any]],
    max_stage: str,
    now: datetime,
    evidence_class: str,
    evidence_nature: str,
    evidence_families: Iterable[str],
    transition_window_seconds: int,
) -> Tuple[bool, str, list[str]]:
    target_rank = stage_rank(stage)
    current_rank = stage_rank(max_stage)
    if target_rank <= current_rank:
        return False, "", []

    missing: list[str] = []
    support = _to_float(predicted_stage_state.get("support"), 0.0)
    min_support = _STAGE_SUPPORT_THRESHOLD.get(stage, 5.0)
    strong_direct_host_stage = (
        evidence_nature == "direct"
        and evidence_class in {"observed", "strongly_supported"}
        and stage in {"execution", "persistence", "privilege_escalation", "defense_evasion"}
    )
    if support < min_support and not strong_direct_host_stage:
        missing.append(f"Need stronger { _stage_label(stage) } evidence")

    prereq = _STAGE_PREREQ.get(stage)
    prereq_state = stage_support.get(prereq or "") if prereq else None

    bypass = False
    if stage == "execution" and evidence_nature == "direct" and evidence_class in {"observed", "strongly_supported"}:
        bypass = True
    if stage in {"persistence", "privilege_escalation", "defense_evasion"}:
        if evidence_nature == "direct" and evidence_class == "observed":
            bypass = True

    if prereq and not bypass:
        ps = _to_float((prereq_state or {}).get("support"), 0.0)
        if ps < _PREREQ_MIN_SUPPORT.get(prereq, 3.5):
            missing.append(f"Insufficient { _stage_label(prereq) } support")
        p_last = _parse_dt((prereq_state or {}).get("last_seen_at"))
        if p_last and transition_window_seconds > 0 and p_last < (now - timedelta(seconds=int(transition_window_seconds))):
            missing.append(f"{ _stage_label(prereq).capitalize() } evidence is too old")

    fams = {str(x).strip().lower() for x in evidence_families if str(x).strip()}
    if stage in {"command_and_control", "exfiltration"} and "network" not in fams:
        missing.append("Network evidence quality is insufficient")

    if stage == "command_and_control":
        exec_support = _to_float((stage_support.get("execution") or {}).get("support"), 0.0)
        if evidence_nature == "inferred" and exec_support < 5.0:
            missing.append("Execution evidence is required before C2 inference")

    if stage == "exfiltration":
        c2_support = _to_float((stage_support.get("command_and_control") or {}).get("support"), 0.0)
        if c2_support < 5.0:
            missing.append("Command and control evidence is required before exfiltration")
        if evidence_class == "weakly_inferred":
            missing.append("Exfiltration is weakly inferred and needs direct transfer evidence")

    if missing:
        return False, missing[0], missing
    return True, "stage transition supported by evidence", []


def evaluate_candidate(
    *,
    case_max_stage: str,
    case_context: Dict[str, Any],
    candidate: StepCandidate,
    event: Dict[str, Any],
    now: datetime,
    transition_window_seconds: int,
) -> ScoredEvidence:
    stage = candidate.stage.value
    kind = str(candidate.kind or "signal").strip().lower() or "signal"
    event_type = str(event.get("event_type") or "").strip().lower()

    source = _source_for(candidate, event_type=event_type, kind=kind)
    nature = _nature_for(candidate, event_type=event_type, source=source, kind=kind)
    reliability = _reliability_for(candidate, source=source)
    families = _families_for(candidate, stage=stage, event_type=event_type, kind=kind)

    ctx = _safe_dict(case_context)
    stage_support = _normalize_stage_support(ctx.get("stage_support_v2"))
    kind_counts = _normalize_nested_counts(ctx.get("evidence_kind_counts_v2"))
    root_counts = _normalize_root_counts(ctx.get("evidence_root_counts_v2"))

    stage_state = stage_support.setdefault(
        stage,
        {
            "support": 0.0,
            "direct_support": 0.0,
            "inferred_support": 0.0,
            "event_count": 0,
            "observed_count": 0,
            "strong_count": 0,
            "inferred_count": 0,
            "weak_count": 0,
            "max_confidence": 0,
            "families": [],
            "last_seen_at": None,
            "last_missing_evidence": [],
            "last_class": None,
        },
    )

    stage_kind_counts = kind_counts.setdefault(stage, {})
    kind_repeat = int(stage_kind_counts.get(kind, 0))

    extra = _safe_dict(event.get("extra"))
    root_key = str(extra.get("fingerprint") or candidate.fingerprint or "").strip()[:160]
    root_repeat = int(root_counts.get(root_key, 0)) if root_key else 0

    base_conf = int(_clamp(_to_int(candidate.confidence, 50), 1, 99))
    if nature == "inferred":
        base_conf = min(base_conf, 86)

    conf = (base_conf * 0.58) + (float(reliability) * 0.26) + (10.0 if nature == "direct" else -8.0)

    last_stage_ts = _parse_dt(stage_state.get("last_seen_at"))
    if last_stage_ts:
        if last_stage_ts >= (now - timedelta(minutes=20)):
            conf += 4.0
        elif last_stage_ts < (now - timedelta(hours=3)):
            conf -= 5.0

    related_families = _collect_related_families(stage, stage_support)
    fam_set = set(families)
    has_existing_related = bool(related_families)
    brings_new_family = bool(fam_set - related_families)
    meaningful_convergence = has_existing_related and brings_new_family and len(related_families | fam_set) >= 2
    if meaningful_convergence:
        conf += 6.0

    repeat_penalty = min(18.0, (kind_repeat * 4.0) + (root_repeat * 2.5))
    conf -= repeat_penalty

    confidence = int(round(_clamp(conf, 5.0, 99.0)))

    if nature == "direct" and confidence >= 84:
        evidence_class = "observed"
    elif confidence >= 70:
        evidence_class = "strongly_supported"
    elif confidence >= 45:
        evidence_class = "inferred"
    else:
        evidence_class = "weakly_inferred"

    if nature != "direct" and evidence_class == "observed":
        evidence_class = "strongly_supported"
    if kind == "context":
        confidence = min(confidence, 30)
        evidence_class = "weakly_inferred"

    class_factor = {
        "observed": 1.00,
        "strongly_supported": 0.76,
        "inferred": 0.45,
        "weakly_inferred": 0.20,
    }.get(evidence_class, 0.45)
    nature_factor = 1.0 if nature == "direct" else 0.7
    repeat_mult = _repeat_multiplier(kind_repeat + root_repeat, evidence_class)

    raw_delta = float(max(0, _to_int(candidate.score_delta, 0))) * class_factor * nature_factor * repeat_mult
    if meaningful_convergence and raw_delta > 0.0 and evidence_class in {"observed", "strongly_supported"}:
        raw_delta += min(6.0, 2.0 + float(len(fam_set)))

    if kind == "context":
        raw_delta = 0.0
    if evidence_class == "weakly_inferred":
        raw_delta = min(raw_delta, 3.0)
    elif evidence_class == "inferred" and nature == "inferred":
        raw_delta = min(raw_delta, max(6.0, float(max(0, _to_int(candidate.score_delta, 0)) * 0.55)))

    score_delta = int(max(0, round(raw_delta)))

    support_gain = (float(confidence) / 18.0) * (1.0 if nature == "direct" else 0.7)
    if evidence_class == "weakly_inferred":
        support_gain *= 0.45
    support_gain *= repeat_mult
    if meaningful_convergence:
        support_gain += 0.8
    if kind == "context":
        support_gain = 0.0
    support_gain = float(_clamp(support_gain, 0.0, 10.0))

    next_stage_state = dict(stage_state)
    next_stage_state["support"] = float(_to_float(stage_state.get("support"), 0.0)) + support_gain
    if nature == "direct":
        next_stage_state["direct_support"] = float(_to_float(stage_state.get("direct_support"), 0.0)) + support_gain
    else:
        next_stage_state["inferred_support"] = float(_to_float(stage_state.get("inferred_support"), 0.0)) + support_gain
    next_stage_state["event_count"] = int(_to_int(stage_state.get("event_count"), 0)) + 1
    next_stage_state["max_confidence"] = max(int(_to_int(stage_state.get("max_confidence"), 0)), confidence)

    next_stage_families = set(_normalize_families(stage_state.get("families") if isinstance(stage_state.get("families"), list) else []))
    next_stage_families.update(fam_set)
    next_stage_state["families"] = sorted(next_stage_families)
    next_stage_state["last_seen_at"] = now.isoformat()
    next_stage_state["last_class"] = evidence_class

    class_counter_key = {
        "observed": "observed_count",
        "strongly_supported": "strong_count",
        "inferred": "inferred_count",
        "weakly_inferred": "weak_count",
    }.get(evidence_class, "inferred_count")
    next_stage_state[class_counter_key] = int(_to_int(stage_state.get(class_counter_key), 0)) + 1

    stage_support[stage] = next_stage_state

    transition_allowed, transition_reason, missing = _transition_decision(
        stage=stage,
        predicted_stage_state=next_stage_state,
        stage_support=stage_support,
        max_stage=case_max_stage,
        now=now,
        evidence_class=evidence_class,
        evidence_nature=nature,
        evidence_families=families,
        transition_window_seconds=max(0, int(transition_window_seconds)),
    )
    promote_stage = transition_allowed and stage_rank(stage) > stage_rank(case_max_stage)

    if evidence_class in {"inferred", "weakly_inferred"} and not missing:
        missing = [_missing_hint_for_stage(stage)]

    next_stage_state["last_missing_evidence"] = missing[:5]
    stage_support[stage] = next_stage_state

    stage_kind_counts[kind] = int(stage_kind_counts.get(kind, 0)) + 1
    kind_counts[stage] = stage_kind_counts

    if root_key:
        root_counts[root_key] = int(root_counts.get(root_key, 0)) + 1
    if len(root_counts) > 64:
        keep = sorted(root_counts.items(), key=lambda kv: (-int(kv[1]), kv[0]))[:64]
        root_counts = {k: int(v) for k, v in keep}

    quality_counts = _quality_counter(ctx)
    quality_counts[evidence_class] = int(quality_counts.get(evidence_class, 0)) + 1

    factors: list[str] = [
        f"{nature} evidence from {source.replace('_', ' ')}",
    ]
    if meaningful_convergence:
        factors.append("multi-signal convergence across related evidence families")
    if repeat_penalty > 0:
        factors.append("repeated similar evidence was down-weighted")
    if transition_allowed and stage_rank(stage) > stage_rank(case_max_stage):
        factors.append("stage transition requirements were satisfied")
    elif stage_rank(stage) > stage_rank(case_max_stage):
        factors.append("stage transition held back due to missing support")

    context_patch = {
        "stage_support_v2": stage_support,
        "evidence_kind_counts_v2": kind_counts,
        "evidence_root_counts_v2": root_counts,
        "evidence_quality_counts_v2": quality_counts,
        "last_evidence_at": now.isoformat(),
    }

    snapshot = {
        "support": round(float(next_stage_state.get("support") or 0.0), 3),
        "direct_support": round(float(next_stage_state.get("direct_support") or 0.0), 3),
        "inferred_support": round(float(next_stage_state.get("inferred_support") or 0.0), 3),
        "event_count": int(next_stage_state.get("event_count") or 0),
        "families": list(next_stage_state.get("families") or []),
        "max_confidence": int(next_stage_state.get("max_confidence") or 0),
        "threshold": float(_STAGE_SUPPORT_THRESHOLD.get(stage, 0.0)),
    }

    return ScoredEvidence(
        score_delta=score_delta,
        confidence=int(confidence),
        evidence_class=evidence_class,
        evidence_nature=nature,
        evidence_source=source,
        evidence_families=families,
        confidence_factors=factors[:4],
        missing_evidence=missing[:5],
        promote_stage=bool(promote_stage),
        transition_allowed=bool(transition_allowed),
        transition_reason=transition_reason,
        support_gain=round(float(support_gain), 3),
        stage_support_snapshot=snapshot,
        context_patch=context_patch,
    )
