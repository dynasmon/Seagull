from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
import re
from typing import Any

from app.features.detections.domain.validation import (
    DetectionRuleValidationError,
    ensure_boolean,
    ensure_field_operator,
    ensure_mapping,
    ensure_non_empty_string,
    ensure_number,
    ensure_sequence,
    normalize_string_list,
)
from app.features.detections.rules.registry import resolve_runtime_field


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


_SELECTION_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_CONDITION_TOKEN_RE = re.compile(r"\s*(\(|\)|\d+|[A-Za-z_][A-Za-z0-9_*]*)")
_RESERVED_SELECTION_NAMES = {"and", "or", "not", "all", "of", "condition"}


def parse_selection_name(name: str) -> str:
    text = ensure_non_empty_string(name, field_name="selection name")
    lowered = text.lower()
    if lowered in _RESERVED_SELECTION_NAMES or not _SELECTION_NAME_RE.match(text):
        raise DetectionRuleValidationError(f"Invalid selection name: {text}")
    return text


def parse_predicate_key(raw_key: str) -> tuple[str, str]:
    key = ensure_non_empty_string(raw_key, field_name="predicate key")
    if "|" in key:
        field_name, operator = key.rsplit("|", 1)
        field_name = ensure_non_empty_string(field_name, field_name="predicate field")
        return field_name, ensure_field_operator(operator)
    return key, "eq"


def _normalize_exists_value(operator: str, value: Any, *, field_name: str) -> tuple[str, bool]:
    exists = ensure_boolean(value, field_name=field_name)
    if operator == "exists":
        return ("exists", True) if exists else ("not_exists", True)
    return ("not_exists", True) if exists else ("exists", True)


def normalize_predicate_value(operator: str, value: Any, *, field_name: str) -> tuple[str, Any]:
    if operator in {"exists", "not_exists"}:
        return _normalize_exists_value(operator, value, field_name=field_name)
    if operator in {"gt", "gte", "lt", "lte"}:
        return operator, ensure_number(value, field_name=field_name)
    if operator in {"in", "not_in"}:
        items = ensure_sequence(value, field_name=field_name, allow_scalar=True)
        if not items:
            raise DetectionRuleValidationError(f"{field_name} must not be empty")
        return operator, items
    if operator == "contains_all":
        items = normalize_string_list(ensure_sequence(value, field_name=field_name, allow_scalar=True))
        if not items:
            raise DetectionRuleValidationError(f"{field_name} must not be empty")
        return operator, items
    if operator in {"contains", "not_contains", "startswith", "endswith"}:
        if isinstance(value, (list, tuple, set)):
            items = normalize_string_list(value)
            if not items:
                raise DetectionRuleValidationError(f"{field_name} must not be empty")
            return operator, items if len(items) > 1 else items[0]
        return operator, ensure_non_empty_string(value, field_name=field_name)
    if isinstance(value, dict):
        raise DetectionRuleValidationError(f"{field_name} must not be a mapping")
    return operator, value


def parse_selection_mapping(selection_name: str, selection: Any) -> DetectionSelection:
    selection_name = parse_selection_name(selection_name)
    selection_map = ensure_mapping(selection, field_name=f"detection.{selection_name}")
    predicates: list[FieldPredicate] = []

    for raw_key, raw_value in selection_map.items():
        source_key = ensure_non_empty_string(raw_key, field_name=f"detection.{selection_name} predicate")
        field_name, operator = parse_predicate_key(source_key)
        runtime_field = resolve_runtime_field(field_name)
        normalized_operator, normalized_value = normalize_predicate_value(
            operator,
            raw_value,
            field_name=f"detection.{selection_name}.{source_key}",
        )
        predicates.append(
            FieldPredicate(
                field=field_name,
                operator=normalized_operator,
                value=normalized_value,
                source_key=source_key,
                runtime_field=runtime_field,
            )
        )

    if not predicates:
        raise DetectionRuleValidationError(f"detection.{selection_name} must define at least one predicate")
    return DetectionSelection(name=selection_name, predicates=tuple(predicates))


class _ConditionParser:
    def __init__(self, tokens: list[str]) -> None:
        self._tokens = tokens
        self._index = 0

    def parse(self) -> Any:
        expression = self._parse_or()
        if self._peek() is not None:
            raise DetectionRuleValidationError(f"Unexpected token in condition: {self._peek()}")
        return expression

    def _parse_or(self) -> Any:
        left = self._parse_and()
        while self._peek_lower() == "or":
            self._consume()
            right = self._parse_and()
            left = BinaryExpression(operator="or", left=left, right=right)
        return left

    def _parse_and(self) -> Any:
        left = self._parse_unary()
        while self._peek_lower() == "and":
            self._consume()
            right = self._parse_unary()
            left = BinaryExpression(operator="and", left=left, right=right)
        return left

    def _parse_unary(self) -> Any:
        if self._peek_lower() == "not":
            self._consume()
            return UnaryExpression(operator="not", operand=self._parse_unary())
        return self._parse_primary()

    def _parse_primary(self) -> Any:
        token = self._peek()
        if token is None:
            raise DetectionRuleValidationError("Condition expression ended unexpectedly")
        if token == "(":
            self._consume()
            expression = self._parse_or()
            if self._consume() != ")":
                raise DetectionRuleValidationError("Condition expression is missing a closing parenthesis")
            return expression
        if token.isdigit() or token.lower() == "all":
            return self._parse_pattern_reference()
        if token.lower() in {"and", "or", "not", "of"}:
            raise DetectionRuleValidationError(f"Unexpected token in condition: {token}")
        self._consume()
        return SelectionReference(name=token)

    def _parse_pattern_reference(self) -> PatternReference:
        token = self._consume()
        quantifier: str | int
        if token.lower() == "all":
            quantifier = "all"
        else:
            quantifier = int(token)
        if self._peek_lower() != "of":
            raise DetectionRuleValidationError("Expected 'of' in condition expression")
        self._consume()
        pattern = self._consume()
        if pattern in {"(", ")"}:
            raise DetectionRuleValidationError("Expected a selection pattern after 'of'")
        return PatternReference(pattern=pattern, quantifier=quantifier)

    def _peek(self) -> str | None:
        if self._index >= len(self._tokens):
            return None
        return self._tokens[self._index]

    def _peek_lower(self) -> str | None:
        token = self._peek()
        return token.lower() if token is not None else None

    def _consume(self) -> str:
        token = self._peek()
        if token is None:
            raise DetectionRuleValidationError("Condition expression ended unexpectedly")
        self._index += 1
        return token


def _tokenize_condition(raw_expression: str) -> list[str]:
    expression = ensure_non_empty_string(raw_expression, field_name="detection.condition").strip()
    tokens: list[str] = []
    index = 0
    while index < len(expression):
        match = _CONDITION_TOKEN_RE.match(expression, index)
        if match is None:
            raise DetectionRuleValidationError(f"Invalid condition syntax near: {expression[index:].strip() or expression[index:]}")
        token = match.group(1)
        tokens.append(token)
        index = match.end()
    return tokens


def _bind_condition_references(node: Any, selection_names: tuple[str, ...]) -> Any:
    if isinstance(node, SelectionReference):
        if node.name not in selection_names:
            raise DetectionRuleValidationError(f"Unknown selection in condition: {node.name}")
        return node
    if isinstance(node, PatternReference):
        matches = tuple(sorted(name for name in selection_names if fnmatchcase(name, node.pattern)))
        if not matches:
            raise DetectionRuleValidationError(f"Condition pattern matches no selections: {node.pattern}")
        if isinstance(node.quantifier, int):
            if node.quantifier <= 0:
                raise DetectionRuleValidationError("Condition count must be greater than zero")
            if node.quantifier > len(matches):
                raise DetectionRuleValidationError(
                    f"Condition requires {node.quantifier} selections but pattern {node.pattern} matched {len(matches)}"
                )
        return PatternReference(pattern=node.pattern, quantifier=node.quantifier, matches=matches)
    if isinstance(node, UnaryExpression):
        return UnaryExpression(operator=node.operator, operand=_bind_condition_references(node.operand, selection_names))
    if isinstance(node, BinaryExpression):
        return BinaryExpression(
            operator=node.operator,
            left=_bind_condition_references(node.left, selection_names),
            right=_bind_condition_references(node.right, selection_names),
        )
    raise DetectionRuleValidationError("Unsupported condition expression node")


def parse_condition_expression(raw_expression: str, *, selection_names: tuple[str, ...]) -> DetectionCondition:
    if not selection_names:
        raise DetectionRuleValidationError("Detection condition requires at least one selection")
    tokens = _tokenize_condition(raw_expression)
    parsed = _ConditionParser(tokens).parse()
    bound = _bind_condition_references(parsed, selection_names)
    return DetectionCondition(raw=raw_expression, expression=bound)


def parse_detection_block(detection: Any) -> DetectionBlock:
    detection_map = ensure_mapping(detection, field_name="detection")
    selections: list[DetectionSelection] = []
    for key, value in detection_map.items():
        if str(key) == "condition":
            continue
        selections.append(parse_selection_mapping(str(key), value))

    if not selections:
        raise DetectionRuleValidationError("detection must define at least one selection")

    selection_names = tuple(selection.name for selection in selections)
    raw_condition = detection_map.get("condition")
    if raw_condition is None:
        if len(selection_names) == 1:
            raw_condition = selection_names[0]
        else:
            raise DetectionRuleValidationError("detection.condition is required when multiple selections are defined")

    condition = parse_condition_expression(str(raw_condition), selection_names=selection_names)
    return DetectionBlock(selections=tuple(selections), condition=condition)
