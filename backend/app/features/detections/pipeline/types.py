from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any


@dataclass(frozen=True)
class AlertCandidate:
    rule_id: str
    rule: dict[str, Any]
    group_key: dict[str, Any]
    match_hints: dict[str, Any]
    count_value: int
    min_events_check: int
    since: datetime
    until: datetime
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class AlertContext:
    candidate: AlertCandidate
    eff_min_events: int = 0
    eff_condition: dict[str, Any] = field(default_factory=dict)
    eff_cooldown: timedelta = field(default_factory=lambda: timedelta(0))
    eff_severity: str = "low"
    applied_scopes: list[str] = field(default_factory=list)
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    enrichment: dict[str, Any] = field(default_factory=dict)
    risk_score: int = 0
    confidence: int = 50
    score_breakdown: list[dict] = field(default_factory=list)
    rule_context: dict[str, Any] = field(default_factory=dict)
    rejected: bool = False
    rejection_reason: str | None = None

    def reject(self, reason: str) -> None:
        self.rejected = True
        self.rejection_reason = reason
