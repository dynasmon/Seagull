from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List

from app.features.attack_chain.domain.types import STAGE_ORDER, stage_rank


def _safe_dict(v: Any) -> Dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _to_int(v: Any, default: int = 0) -> int:
    try:
        if v is None or v == "":
            return int(default)
        return int(float(v))
    except Exception:
        return int(default)


def _to_float(v: Any, default: float = 0.0) -> float:
    try:
        if v is None or v == "":
            return float(default)
        return float(v)
    except Exception:
        return float(default)


def _stage_label(stage: str) -> str:
    return str(stage or "").replace("_", " ").title()


def _norm_list(v: Any, *, max_items: int = 8) -> list[str]:
    if not isinstance(v, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for x in v:
        s = str(x or "").strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
        if len(out) >= max_items:
            break
    return out


def _support_level(*, observed: int, strong: int, inferred: int, weak: int) -> str:
    if observed > 0:
        return "observed"
    if strong > 0:
        return "strongly_supported"
    if inferred > 0:
        return "inferred"
    if weak > 0:
        return "weakly_inferred"
    return "weakly_inferred"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_case_reasoning(*, case: Any, steps: Iterable[Any]) -> Dict[str, Any]:
    context = _safe_dict(getattr(case, "context", None))
    stage_support = _safe_dict(context.get("stage_support_v2"))
    quality_counts = _safe_dict(context.get("evidence_quality_counts_v2"))
    story_stage_hits = _safe_dict(context.get("story_stage_hits"))
    matched_story_ids = _norm_list(context.get("matched_story_ids"), max_items=16)
    matched_story_names = _norm_list(context.get("matched_story_names"), max_items=16)
    story_reasoning = _norm_list(context.get("story_reasoning"), max_items=12)

    aggregated: Dict[str, Dict[str, Any]] = {}
    for raw in steps:
        stage = str(getattr(raw, "stage", "") or "").strip()
        if not stage:
            continue
        details = _safe_dict(getattr(raw, "details", None))
        bucket = aggregated.setdefault(
            stage,
            {
                "event_count": 0,
                "max_confidence": 0,
                "observed_count": 0,
                "strong_count": 0,
                "inferred_count": 0,
                "weak_count": 0,
                "direct_count": 0,
                "inferred_nature_count": 0,
                "families": set(),
                "factors": [],
                "missing": [],
                "latest_transition": {},
            },
        )

        bucket["event_count"] += 1
        conf = _to_int(details.get("confidence"), 0)
        bucket["max_confidence"] = max(int(bucket["max_confidence"]), conf)

        eclass = str(details.get("evidence_class") or "").strip().lower()
        if eclass == "observed":
            bucket["observed_count"] += 1
        elif eclass == "strongly_supported":
            bucket["strong_count"] += 1
        elif eclass == "inferred":
            bucket["inferred_count"] += 1
        elif eclass == "weakly_inferred":
            bucket["weak_count"] += 1

        nature = str(details.get("evidence_nature") or "").strip().lower()
        if nature == "direct":
            bucket["direct_count"] += 1
        elif nature == "inferred":
            bucket["inferred_nature_count"] += 1

        for fam in _norm_list(details.get("evidence_families"), max_items=8):
            bucket["families"].add(fam)

        for fac in _norm_list(details.get("confidence_factors"), max_items=4):
            if fac not in bucket["factors"]:
                bucket["factors"].append(fac)

        for miss in _norm_list(details.get("missing_evidence"), max_items=4):
            if miss not in bucket["missing"]:
                bucket["missing"].append(miss)

        tr = _safe_dict(details.get("transition"))
        if tr:
            bucket["latest_transition"] = {
                "allowed": bool(tr.get("allowed")),
                "promoted": bool(tr.get("promoted")),
                "reason": str(tr.get("reason") or "").strip(),
            }

    stage_items: list[Dict[str, Any]] = []
    max_stage = str(getattr(case, "max_stage", "") or "initial_access")
    for st in STAGE_ORDER:
        stage = st.value
        from_steps = aggregated.get(stage) or {}
        from_ctx = _safe_dict(stage_support.get(stage))
        event_count = max(_to_int(from_steps.get("event_count"), 0), _to_int(from_ctx.get("event_count"), 0))
        if event_count <= 0:
            continue

        observed = max(_to_int(from_steps.get("observed_count"), 0), _to_int(from_ctx.get("observed_count"), 0))
        strong = max(_to_int(from_steps.get("strong_count"), 0), _to_int(from_ctx.get("strong_count"), 0))
        inferred = max(_to_int(from_steps.get("inferred_count"), 0), _to_int(from_ctx.get("inferred_count"), 0))
        weak = max(_to_int(from_steps.get("weak_count"), 0), _to_int(from_ctx.get("weak_count"), 0))

        support_level = _support_level(observed=observed, strong=strong, inferred=inferred, weak=weak)
        confidence = max(_to_int(from_steps.get("max_confidence"), 0), _to_int(from_ctx.get("max_confidence"), 0))

        families_from_steps = set(from_steps.get("families") or set())
        families_from_ctx = set(_norm_list(from_ctx.get("families"), max_items=8))
        families = sorted({str(x) for x in (families_from_steps | families_from_ctx) if str(x).strip()})

        transition = _safe_dict(from_steps.get("latest_transition"))
        promoted = bool(stage_rank(stage) <= stage_rank(max_stage))
        if transition and transition.get("promoted") is True:
            promoted = True

        stage_items.append(
            {
                "stage": stage,
                "label": _stage_label(stage),
                "support_level": support_level,
                "confidence": confidence,
                "support_score": round(_to_float(from_ctx.get("support"), 0.0), 3),
                "direct_support": round(_to_float(from_ctx.get("direct_support"), 0.0), 3),
                "inferred_support": round(_to_float(from_ctx.get("inferred_support"), 0.0), 3),
                "evidence_count": event_count,
                "observed_count": observed,
                "strong_count": strong,
                "inferred_count": inferred,
                "weak_count": weak,
                "direct_count": _to_int(from_steps.get("direct_count"), 0),
                "inferred_nature_count": _to_int(from_steps.get("inferred_nature_count"), 0),
                "families": families,
                "top_factors": (from_steps.get("factors") or [])[:4],
                "missing_evidence": (
                    _norm_list(from_ctx.get("last_missing_evidence"), max_items=4)
                    or (from_steps.get("missing") or [])[:4]
                ),
                "promoted": promoted,
                "transition": transition,
            }
        )

    stage_items.sort(key=lambda x: stage_rank(str(x.get("stage") or "")))

    observed_total = _to_int(quality_counts.get("observed"), 0)
    strong_total = _to_int(quality_counts.get("strongly_supported"), 0)
    inferred_total = _to_int(quality_counts.get("inferred"), 0)
    weak_total = _to_int(quality_counts.get("weakly_inferred"), 0)

    if observed_total > 0:
        verdict = "Observed-led chain"
        analyst_hint = "Core stages are backed by direct telemetry and can be actioned confidently."
    elif strong_total > 0:
        verdict = "Strongly supported chain"
        analyst_hint = "The chain is supported by multiple signals with good reliability."
    elif inferred_total > 0:
        verdict = "Inferred chain"
        analyst_hint = "Treat this as suspicious but collect direct host/network artifacts before escalation."
    else:
        verdict = "Weakly inferred chain"
        analyst_hint = "Evidence is sparse or weak; avoid strong conclusions without additional telemetry."

    out = {
        "generated_at": _now_iso(),
        "overall": {
            "verdict": verdict,
            "analyst_hint": analyst_hint,
            "quality_counts": {
                "observed": observed_total,
                "strongly_supported": strong_total,
                "inferred": inferred_total,
                "weakly_inferred": weak_total,
            },
            "stage_count": len(stage_items),
        },
        "stages": stage_items,
    }

    if matched_story_ids or matched_story_names or story_stage_hits:
        out["stories"] = {
            "matched_story_ids": matched_story_ids,
            "matched_story_names": matched_story_names,
            "confidence": _to_int(context.get("story_confidence"), 0),
            "reasoning": story_reasoning,
            "stage_hits": story_stage_hits,
        }

    return out
