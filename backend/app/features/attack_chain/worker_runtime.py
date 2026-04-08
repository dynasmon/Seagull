"""Worker-facing entrypoint for the attack_chain feature.

This module provides a stable import surface for long-running worker processes,
so worker code does not need to depend on deep internal package paths.
"""

from __future__ import annotations

from app.features.attack_chain.domain.config import load_config
from app.features.attack_chain.domain.detectors import detect_steps
from app.features.attack_chain.domain.scoring import evaluate_candidate
from app.features.attack_chain.domain.store import (
    CaseRow,
    case_recent_step_exists,
    close_stale_cases,
    find_attachable_case_id,
    get_or_create_open_case_ex,
    insert_step_and_update_case,
)
from app.features.attack_chain.domain.types import AttackStage, StepCandidate
from app.features.attack_chain.models import (
    AttackChainAllowlistModel,
    AttackChainCaseModel,
    AttackChainLastAccessModel,
    AttackChainLoginBaselineModel,
    AttackChainSshFailureModel,
    AttackChainStepModel,
)

__all__ = [
    "AttackChainAllowlistModel",
    "AttackChainCaseModel",
    "AttackChainLastAccessModel",
    "AttackChainLoginBaselineModel",
    "AttackChainSshFailureModel",
    "AttackChainStepModel",
    "AttackStage",
    "CaseRow",
    "StepCandidate",
    "case_recent_step_exists",
    "close_stale_cases",
    "detect_steps",
    "evaluate_candidate",
    "find_attachable_case_id",
    "get_or_create_open_case_ex",
    "insert_step_and_update_case",
    "load_config",
]
