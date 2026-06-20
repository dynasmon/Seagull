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
class DetectionSelection:
    name: str
    predicates: tuple[FieldPredicate, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class SelectionReference:
    name: str


@dataclass(frozen=True)
class PatternReference:
    pattern: str
    quantifier: str | int
    matches: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class UnaryExpression:
    operator: str
    operand: Any


@dataclass(frozen=True)
class BinaryExpression:
    operator: str
    left: Any
    right: Any


@dataclass(frozen=True)
class DetectionCondition:
    raw: str
    expression: Any


@dataclass(frozen=True)
class DetectionBlock:
    selections: tuple[DetectionSelection, ...]
    condition: DetectionCondition


@dataclass(frozen=True)
class ThresholdCondition:
    operator: str = ">="
    value: int = 0
