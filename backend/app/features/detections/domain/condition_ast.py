from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class FieldPredicate:
    field: str
    operator: str = "eq"
    value: Any = None
    source_key: str | None = None
    runtime_field: str | None = None


@dataclass(frozen=True)
class MatchCondition:
    predicates: tuple[FieldPredicate, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ThresholdCondition:
    operator: str = ">="
    value: int = 0
