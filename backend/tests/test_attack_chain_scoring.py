from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from app.features.attack_chain.domain.reasoning import build_case_reasoning
from app.features.attack_chain.domain.scoring import evaluate_candidate
from app.features.attack_chain.domain.types import AttackStage, StepCandidate


def _now() -> datetime:
    return datetime(2026, 4, 4, 12, 0, 0, tzinfo=timezone.utc)


def _event(event_type: str, *, extra: dict | None = None) -> dict:
    return {
        "id": 100,
        "event_type": event_type,
        "timestamp": _now(),
        "src_ip": "10.0.0.10",
        "dst_ip": "198.51.100.20",
        "dst_port": 443,
        "proto": "tcp",
        "extra": extra or {},
    }


def _cand(
    *,
    stage: AttackStage,
    kind: str,
    score_delta: int,
    confidence: int,
    evidence_nature: str = "",
    fingerprint: str = "fp",
) -> StepCandidate:
    return StepCandidate(
        stage=stage,
        title="Signal",
        description="Signal description",
        score_delta=score_delta,
        fingerprint=fingerprint,
        kind=kind,
        confidence=confidence,
        emit=True,
        evidence_nature=evidence_nature,
    )


def test_direct_telemetry_scores_higher_than_inferred_signal() -> None:
    direct = evaluate_candidate(
        case_max_stage="initial_access",
        case_context={},
        candidate=_cand(
            stage=AttackStage.execution,
            kind="exec_remote_fetch",
            score_delta=28,
            confidence=86,
            evidence_nature="direct",
            fingerprint="exec:rfetch",
        ),
        event=_event("proc_exec"),
        now=_now(),
        transition_window_seconds=5400,
    )

    inferred = evaluate_candidate(
        case_max_stage="initial_access",
        case_context={},
        candidate=_cand(
            stage=AttackStage.command_and_control,
            kind="c2",
            score_delta=28,
            confidence=86,
            evidence_nature="inferred",
            fingerprint="net:beacon",
        ),
        event=_event("beacon_suspect"),
        now=_now(),
        transition_window_seconds=5400,
    )

    assert direct.score_delta > inferred.score_delta
    assert direct.evidence_nature == "direct"
    assert direct.evidence_class in {"observed", "strongly_supported"}
    assert inferred.evidence_nature == "inferred"
    assert inferred.evidence_class in {"inferred", "weakly_inferred", "strongly_supported"}


def test_weak_inferred_exfil_does_not_auto_promote_stage() -> None:
    weak_exfil = evaluate_candidate(
        case_max_stage="execution",
        case_context={},
        candidate=_cand(
            stage=AttackStage.exfiltration,
            kind="exfil",
            score_delta=34,
            confidence=58,
            evidence_nature="inferred",
            fingerprint="exfil:rare",
        ),
        event=_event("egress_anomaly"),
        now=_now(),
        transition_window_seconds=5400,
    )

    assert weak_exfil.promote_stage is False
    assert weak_exfil.transition_allowed is False
    assert weak_exfil.score_delta <= 6
    assert any("command and control" in x.lower() for x in weak_exfil.missing_evidence)


def test_multi_signal_convergence_increases_confidence_only_with_related_context() -> None:
    base_persistence = _cand(
        stage=AttackStage.persistence,
        kind="persistence",
        score_delta=26,
        confidence=74,
        evidence_nature="direct",
        fingerprint="persist:systemd",
    )

    isolated = evaluate_candidate(
        case_max_stage="execution",
        case_context={},
        candidate=base_persistence,
        event=_event("persistence_systemd"),
        now=_now(),
        transition_window_seconds=5400,
    )

    exec_seed = evaluate_candidate(
        case_max_stage="initial_access",
        case_context={},
        candidate=_cand(
            stage=AttackStage.execution,
            kind="exec_remote_fetch",
            score_delta=28,
            confidence=86,
            evidence_nature="direct",
            fingerprint="exec:seed",
        ),
        event=_event("proc_exec"),
        now=_now(),
        transition_window_seconds=5400,
    )

    converged = evaluate_candidate(
        case_max_stage="execution",
        case_context=exec_seed.context_patch,
        candidate=base_persistence,
        event=_event("persistence_systemd"),
        now=_now(),
        transition_window_seconds=5400,
    )

    assert converged.score_delta > isolated.score_delta
    assert converged.confidence >= isolated.confidence
    assert any("multi-signal convergence" in x.lower() for x in converged.confidence_factors)


def test_stage_transition_requires_progressive_support() -> None:
    execution_seed = evaluate_candidate(
        case_max_stage="initial_access",
        case_context={},
        candidate=_cand(
            stage=AttackStage.execution,
            kind="exec_remote_fetch",
            score_delta=28,
            confidence=88,
            evidence_nature="direct",
            fingerprint="exec:for_c2",
        ),
        event=_event("proc_exec"),
        now=_now(),
        transition_window_seconds=5400,
    )

    c2_candidate = _cand(
        stage=AttackStage.command_and_control,
        kind="c2",
        score_delta=30,
        confidence=90,
        evidence_nature="direct",
        fingerprint="c2:step",
    )

    c2_first = evaluate_candidate(
        case_max_stage="execution",
        case_context=execution_seed.context_patch,
        candidate=c2_candidate,
        event=_event("c2_suspect"),
        now=_now(),
        transition_window_seconds=5400,
    )

    c2_second = evaluate_candidate(
        case_max_stage="execution",
        case_context=c2_first.context_patch,
        candidate=c2_candidate,
        event=_event("c2_suspect"),
        now=_now(),
        transition_window_seconds=5400,
    )

    c2_third = evaluate_candidate(
        case_max_stage="execution",
        case_context=c2_second.context_patch,
        candidate=c2_candidate,
        event=_event("c2_suspect"),
        now=_now(),
        transition_window_seconds=5400,
    )

    assert c2_first.promote_stage is False
    assert c2_second.promote_stage is False
    assert c2_third.promote_stage is True


def test_repeated_duplicate_weak_signals_are_diminishing() -> None:
    weak = _cand(
        stage=AttackStage.command_and_control,
        kind="c2",
        score_delta=28,
        confidence=54,
        evidence_nature="inferred",
        fingerprint="dup:weak_c2",
    )

    s1 = evaluate_candidate(
        case_max_stage="execution",
        case_context={},
        candidate=weak,
        event=_event("beacon_suspect", extra={"fingerprint": "dup:weak_c2"}),
        now=_now(),
        transition_window_seconds=5400,
    )
    s2 = evaluate_candidate(
        case_max_stage="execution",
        case_context=s1.context_patch,
        candidate=weak,
        event=_event("beacon_suspect", extra={"fingerprint": "dup:weak_c2"}),
        now=_now(),
        transition_window_seconds=5400,
    )
    s3 = evaluate_candidate(
        case_max_stage="execution",
        case_context=s2.context_patch,
        candidate=weak,
        event=_event("beacon_suspect", extra={"fingerprint": "dup:weak_c2"}),
        now=_now(),
        transition_window_seconds=5400,
    )

    assert s2.score_delta <= s1.score_delta
    assert s3.score_delta <= s2.score_delta
    assert (s1.score_delta + s2.score_delta + s3.score_delta) < (s1.score_delta * 2)


def test_sparse_signal_stays_cautious_and_inferred() -> None:
    sparse = evaluate_candidate(
        case_max_stage="initial_access",
        case_context={},
        candidate=_cand(
            stage=AttackStage.initial_access,
            kind="ssh_new_source",
            score_delta=14,
            confidence=60,
            evidence_nature="inferred",
            fingerprint="ssh:new_source",
        ),
        event=_event("ssh_auth"),
        now=_now(),
        transition_window_seconds=5400,
    )

    assert sparse.evidence_class in {"inferred", "weakly_inferred"}
    assert sparse.score_delta <= 6


def test_reasoning_payload_includes_stage_quality_and_missing_evidence() -> None:
    case = SimpleNamespace(
        id=10,
        max_stage="command_and_control",
        context={
            "stage_support_v2": {
                "execution": {
                    "support": 6.1,
                    "direct_support": 5.9,
                    "inferred_support": 0.2,
                    "event_count": 2,
                    "observed_count": 1,
                    "strong_count": 1,
                    "inferred_count": 0,
                    "weak_count": 0,
                    "max_confidence": 91,
                    "families": ["process"],
                    "last_seen_at": _now().isoformat(),
                    "last_missing_evidence": [],
                },
                "command_and_control": {
                    "support": 5.0,
                    "direct_support": 0.0,
                    "inferred_support": 5.0,
                    "event_count": 2,
                    "observed_count": 0,
                    "strong_count": 0,
                    "inferred_count": 2,
                    "weak_count": 0,
                    "max_confidence": 63,
                    "families": ["network"],
                    "last_seen_at": _now().isoformat(),
                    "last_missing_evidence": ["Need stronger command and control evidence"],
                },
            },
            "evidence_quality_counts_v2": {
                "observed": 1,
                "strongly_supported": 1,
                "inferred": 2,
                "weakly_inferred": 0,
            },
        },
    )

    steps = [
        SimpleNamespace(
            stage="execution",
            details={
                "confidence": 91,
                "evidence_class": "observed",
                "evidence_nature": "direct",
                "evidence_families": ["process"],
                "confidence_factors": ["direct evidence from process telemetry"],
                "missing_evidence": [],
                "transition": {"allowed": True, "promoted": True, "reason": "stage transition supported by evidence"},
            },
        ),
        SimpleNamespace(
            stage="command_and_control",
            details={
                "confidence": 63,
                "evidence_class": "inferred",
                "evidence_nature": "inferred",
                "evidence_families": ["network"],
                "confidence_factors": ["inferred evidence from network heuristic"],
                "missing_evidence": ["Need stronger command and control evidence"],
                "transition": {"allowed": False, "promoted": False, "reason": "Need stronger command and control evidence"},
            },
        ),
    ]

    reasoning = build_case_reasoning(case=case, steps=steps)

    assert isinstance(reasoning.get("overall"), dict)
    assert isinstance(reasoning.get("stages"), list)
    assert reasoning["overall"]["quality_counts"]["observed"] == 1

    c2 = next((x for x in reasoning["stages"] if x.get("stage") == "command_and_control"), None)
    assert c2 is not None
    assert c2["support_level"] in {"inferred", "weakly_inferred"}
    assert isinstance(c2.get("missing_evidence"), list)
    assert "Need stronger command and control evidence" in c2["missing_evidence"]
