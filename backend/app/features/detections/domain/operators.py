from __future__ import annotations

DEFAULT_FIELD_OPERATOR = "eq"

OPERATOR_SUFFIXES: tuple[tuple[str, str], ...] = (
    ("_not_exists", "not_exists"),
    ("_exists", "exists"),
    ("_not_contains", "not_contains"),
    ("_contains_all", "contains_all"),
    ("_contains", "contains"),
    ("_startswith", "startswith"),
    ("_endswith", "endswith"),
    ("_not_in", "not_in"),
    ("_in", "in"),
    ("_gte", "gte"),
    ("_gt", "gt"),
    ("_lte", "lte"),
    ("_lt", "lt"),
    ("_neq", "neq"),
)

SUPPORTED_FIELD_OPERATORS = frozenset(
    {
        DEFAULT_FIELD_OPERATOR,
        "neq",
        "gt",
        "gte",
        "lt",
        "lte",
        "in",
        "not_in",
        "contains",
        "contains_all",
        "not_contains",
        "startswith",
        "endswith",
        "exists",
        "not_exists",
    }
)

SUPPORTED_THRESHOLD_OPERATORS = frozenset({">=", ">", "<=", "<", "==", "!="})

_OPERATOR_TO_SUFFIX = {op: suffix for suffix, op in OPERATOR_SUFFIXES}


def split_operator_suffix(raw_key: str) -> tuple[str, str]:
    key = str(raw_key or "").strip()
    for suffix, operator in OPERATOR_SUFFIXES:
        if key.endswith(suffix):
            return key[: -len(suffix)], operator
    return key, DEFAULT_FIELD_OPERATOR


def join_operator_suffix(field_name: str, operator: str) -> str:
    op = str(operator or DEFAULT_FIELD_OPERATOR).strip() or DEFAULT_FIELD_OPERATOR
    if op == DEFAULT_FIELD_OPERATOR:
        return field_name
    suffix = _OPERATOR_TO_SUFFIX.get(op)
    if suffix is None:
        raise ValueError(f"Unsupported field operator: {op}")
    return f"{field_name}{suffix}"
