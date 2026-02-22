from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional


class AttackStage(str, Enum):
    initial_access = "initial_access"
    execution = "execution"
    persistence = "persistence"
    privilege_escalation = "privilege_escalation"
    defense_evasion = "defense_evasion"
    command_and_control = "command_and_control"
    exfiltration = "exfiltration"


STAGE_ORDER = [
    AttackStage.initial_access,
    AttackStage.execution,
    AttackStage.persistence,
    AttackStage.privilege_escalation,
    AttackStage.defense_evasion,
    AttackStage.command_and_control,
    AttackStage.exfiltration,
]


def stage_rank(stage: str) -> int:
    s = (stage or "").strip()
    for i, st in enumerate(STAGE_ORDER):
        if st.value == s:
            return i
    return 0


@dataclass(frozen=True)
class StepCandidate:
    stage: AttackStage
    # Short, human-readable title (used by UI)
    title: str
    # Optional longer description (used by UI)
    description: str = ""
    score_delta: int
    # If set, used to avoid producing noisy duplicates.
    fingerprint: str
    # If set, the case should be keyed by this suspect ip.
    suspect_ip: Optional[str] = None
    details: Dict[str, Any] | None = None

    # Metadata for downstream scoring / UI.
    kind: str = "signal"  # e.g. ssh_fail, ssh_accept, sudo, c2
    technique_id: Optional[str] = None  # MITRE ATT&CK technique (optional)
    confidence: int = 50  # 0..100

    # If False, the worker may still use the candidate to update baselines,
    # but it should not be written as a visible step.
    emit: bool = True
