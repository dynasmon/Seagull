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
    label: str
    score_delta: int
    # If set, used to avoid producing noisy duplicates.
    fingerprint: str
    # If set, the case should be keyed by this suspect ip.
    suspect_ip: Optional[str] = None
    details: Dict[str, Any] | None = None
