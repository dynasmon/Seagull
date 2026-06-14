from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol

from sqlalchemy.orm import Session

from app.features.detections.pipeline.types import AlertCandidate


class RuleExecutor(Protocol):
    def can_execute(self, rule: dict[str, Any]) -> bool: ...

    def execute(
        self, rule: dict[str, Any], *, db: Session, since: datetime, until: datetime
    ) -> list[AlertCandidate]: ...
