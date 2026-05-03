from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.features.attack_chain.domain.story_engine import evaluate_attack_stories
from app.features.attack_chain.domain.story_schemas import AttackStoryTemplate
from app.features.attack_chain.domain.types import AttackStage, StepCandidate


def _now() -> datetime:
    return datetime(2026, 4, 4, 12, 0, 0, tzinfo=timezone.utc)


def test_story_engine_matches_attack_steps_without_duplicate_score_inflation() -> None:
    story = AttackStoryTemplate.model_validate(
        {
            "schema_version": 1,
            "id": "ssh_compromise_story",
            "name": "SSH Compromise After Brute Force",
            "description": "A successful SSH session follows brute-force activity.",
            "enabled": True,
            "maturity": "stable",
            "entity": {"type": "suspect_ip", "field": "suspect_ip"},
            "maxspan_seconds": 1800,
            "stages": [
                {
                    "id": "brute_force",
                    "name": "SSH Brute Force",
                    "tactic": "credential_access",
                    "technique_id": "T1110.001",
                    "required": True,
                    "min_signals": 1,
                    "after": None,
                    "within_seconds": None,
                    "match": {
                        "rule_ids": [],
                        "correlation_rule_ids": [],
                        "attack_step_kinds": ["ssh_bruteforce"],
                        "event_types": [],
                    },
                    "score_delta": 4,
                    "confidence_weight": 1.0,
                },
                {
                    "id": "accepted_ssh",
                    "name": "Accepted SSH",
                    "tactic": "initial_access",
                    "technique_id": "T1078",
                    "required": True,
                    "min_signals": 1,
                    "after": "brute_force",
                    "within_seconds": 1800,
                    "match": {
                        "rule_ids": [],
                        "correlation_rule_ids": [],
                        "attack_step_kinds": ["ssh_bruteforce_success"],
                        "event_types": ["ssh_auth"],
                    },
                    "score_delta": 6,
                    "confidence_weight": 1.2,
                },
            ],
            "scoring": {"story_match_bonus": 8, "max_story_score": 18},
            "attack": {"summary": "SSH compromise", "techniques": ["T1110.001", "T1078"], "tags": ["ssh"]},
            "response": {"summary": "Review host", "recommendations": ["Review adjacent activity"]},
        }
    )

    suspect_ip = "203.0.113.10"
    brute_force_step = SimpleNamespace(
        id=1,
        stage="initial_access",
        label="SSH brute-force activity",
        event_type="ssh_auth",
        timestamp=_now(),
        src_ip=suspect_ip,
        dst_ip="198.51.100.10",
        details={
            "kind": "ssh_bruteforce",
            "confidence": 85,
            "src_ip": suspect_ip,
        },
    )

    accepted_candidate = StepCandidate(
        stage=AttackStage.initial_access,
        title="SSH login accepted after failures",
        description="Successful SSH authentication after repeated failures.",
        score_delta=34,
        fingerprint="ssh_success_after_fail:203.0.113.10:root",
        suspect_ip=suspect_ip,
        details={"src_ip": suspect_ip, "username": "root"},
        kind="ssh_bruteforce_success",
        technique_id="T1078",
        confidence=90,
        emit=True,
    )
    accepted_event = {
        "id": 200,
        "agent_id": "agent-1",
        "event_type": "ssh_auth",
        "timestamp": _now() + timedelta(minutes=5),
        "src_ip": suspect_ip,
        "dst_ip": "198.51.100.10",
        "dst_port": 22,
        "proto": "tcp",
        "extra": {"action": "accepted", "username": "root"},
    }

    first_eval = evaluate_attack_stories(
        stories=[story],
        case_context={},
        existing_steps=[brute_force_step],
        alerts=[],
        correlation_incidents=[],
        candidate=accepted_candidate,
        event=accepted_event,
        now=accepted_event["timestamp"],
        entity_values={"agent_id": "agent-1", "suspect_ip": suspect_ip},
        candidate_confidence=92,
    )

    assert first_eval.score_delta == 18
    assert first_eval.matched_story_ids == ["ssh_compromise_story"]
    assert first_eval.matched_story_names == ["SSH Compromise After Brute Force"]
    assert first_eval.story_confidence is not None and first_eval.story_confidence > 0
    assert "story_stage_hits" in first_eval.context_patch
    assert len(first_eval.detail_patch.get("story_stage_matches") or []) == 2
    assert len(first_eval.detail_patch.get("story_matches") or []) == 1

    accepted_step = SimpleNamespace(
        id=2,
        stage="initial_access",
        label="SSH login accepted after failures",
        event_type="ssh_auth",
        timestamp=accepted_event["timestamp"],
        src_ip=suspect_ip,
        dst_ip="198.51.100.10",
        details={
            "kind": "ssh_bruteforce_success",
            "confidence": 92,
            "src_ip": suspect_ip,
        },
    )

    second_eval = evaluate_attack_stories(
        stories=[story],
        case_context=first_eval.context_patch,
        existing_steps=[brute_force_step, accepted_step],
        alerts=[],
        correlation_incidents=[],
        candidate=accepted_candidate,
        event=accepted_event,
        now=accepted_event["timestamp"],
        entity_values={"agent_id": "agent-1", "suspect_ip": suspect_ip},
        candidate_confidence=92,
    )

    assert second_eval.score_delta == 0
    assert not second_eval.detail_patch
    assert second_eval.matched_story_ids == ["ssh_compromise_story"]
