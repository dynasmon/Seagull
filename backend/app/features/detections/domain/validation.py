from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from app.features.detections.domain.operators import (
    DEFAULT_FIELD_OPERATOR,
    SUPPORTED_FIELD_OPERATORS,
    SUPPORTED_THRESHOLD_OPERATORS,
)


class DetectionRuleValidationError(ValueError):
    pass


def ensure_mapping(value: object, *, field_name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise DetectionRuleValidationError(f"{field_name} must be a mapping")
    return value


def ensure_non_empty_string(value: object, *, field_name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise DetectionRuleValidationError(f"{field_name} must be a non-empty string")
    return text


def normalize_string_list(value: object) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, Iterable) or isinstance(value, (bytes, bytearray, dict)):
        return []
    out: list[str] = []
    for item in value:
        text = str(item or "").strip()
        if text:
            out.append(text)
    return out


def ensure_field_operator(operator: str) -> str:
    op = str(operator or DEFAULT_FIELD_OPERATOR).strip() or DEFAULT_FIELD_OPERATOR
    if op not in SUPPORTED_FIELD_OPERATORS:
        raise DetectionRuleValidationError(f"Unsupported field operator: {op}")
    return op


def ensure_threshold_operator(operator: str) -> str:
    op = str(operator or ">=").strip() or ">="
    if op not in SUPPORTED_THRESHOLD_OPERATORS:
        raise DetectionRuleValidationError(f"Unsupported threshold operator: {op}")
    return op


def ensure_value_in_set(value: object, *, field_name: str, supported: set[str] | frozenset[str]) -> str:
    normalized = str(value or "").strip().lower()
    if normalized and normalized not in supported:
        raise DetectionRuleValidationError(f"Unsupported {field_name}: {value}")
    return normalized


def ensure_boolean(value: object, *, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    raise DetectionRuleValidationError(f"{field_name} must be a boolean")


def ensure_number(
    value: object,
    *,
    field_name: str,
    minimum: float | None = None,
    maximum: float | None = None,
) -> int | float:
    if isinstance(value, bool) or value is None:
        raise DetectionRuleValidationError(f"{field_name} must be numeric")
    try:
        number = float(value)
    except Exception as exc:
        raise DetectionRuleValidationError(f"{field_name} must be numeric") from exc
    if minimum is not None and number < minimum:
        raise DetectionRuleValidationError(f"{field_name} must be >= {minimum}")
    if maximum is not None and number > maximum:
        raise DetectionRuleValidationError(f"{field_name} must be <= {maximum}")
    if number.is_integer():
        return int(number)
    return number


def ensure_sequence(value: object, *, field_name: str, allow_scalar: bool = False) -> list[Any]:
    if allow_scalar and not isinstance(value, (list, tuple, set)):
        return [value]
    if not isinstance(value, (list, tuple, set)):
        raise DetectionRuleValidationError(f"{field_name} must be a list")
    return list(value)
