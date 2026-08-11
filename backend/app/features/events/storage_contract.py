from __future__ import annotations

import ipaddress
import json
from typing import Any, Dict, Final, Mapping, Optional, Sequence

AGENT_ID_MAX_CHARS: Final[int] = 64
AGENT_ID_PATTERN: Final[str] = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"

EVENT_TYPE_MAX_CHARS: Final[int] = 32
EVENT_TYPE_PATTERN: Final[str] = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,31}$"

EVENT_ID_CHARS: Final[int] = 36
EVENT_ID_PATTERN: Final[str] = r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"

IP_MAX_CHARS: Final[int] = 45
PROTO_MAX_CHARS: Final[int] = 16

PORT_MIN: Final[int] = 0
PORT_MAX: Final[int] = 65535

BYTE_COUNT_MIN: Final[int] = 0
BYTE_COUNT_MAX: Final[int] = 2**63 - 1

SCHEMA_VERSION_MIN: Final[int] = 1
SCHEMA_VERSION_MAX: Final[int] = 16

INT32_MIN: Final[int] = -(2**31)
INT32_MAX: Final[int] = 2**31 - 1
SMALLINT_MIN: Final[int] = -(2**15)
SMALLINT_MAX: Final[int] = 2**15 - 1

HOT_TEXT_COLUMN_MAX_CHARS: Final[Mapping[str, int]] = {
    "app_proto": 32,
    "app_proto_reason": 64,
    "app_proto_conf_band": 16,
    "dns_qname": 512,
    "http_host": 512,
    "http_method": 16,
    "tls_sni": 512,
    "tls_alpn_first": 64,
    "ja3": 128,
    "ja4": 128,
    "ja4_ptype": 8,
    "ssh_action": 64,
    "ssh_username": 128,
    "proc_name": 128,
    "proc_exe": 512,
    "proc_parent_name": 128,
    "fim_path": 1024,
    "fim_category": 64,
    "heuristic_name": 64,
}

EXTRA_MAX_DEPTH: Final[int] = 8
EXTRA_MAX_NODES: Final[int] = 512
EXTRA_MAX_KEY_CHARS: Final[int] = 128
EXTRA_MAX_TEXT_CHARS: Final[int] = 4096
EXTRA_MAX_SERIALIZED_BYTES: Final[int] = 32 * 1024

VIOLATION_EXTRA_NOT_AN_OBJECT: Final[str] = "extra_must_be_an_object"
VIOLATION_EXTRA_DEPTH: Final[str] = f"extra_nests_deeper_than_{EXTRA_MAX_DEPTH}_levels"
VIOLATION_EXTRA_NODES: Final[str] = f"extra_holds_more_than_{EXTRA_MAX_NODES}_values"
VIOLATION_EXTRA_KEY_CHARS: Final[str] = f"extra_key_is_longer_than_{EXTRA_MAX_KEY_CHARS}_characters"
VIOLATION_EXTRA_TEXT_CHARS: Final[str] = f"extra_value_is_longer_than_{EXTRA_MAX_TEXT_CHARS}_characters"
VIOLATION_EXTRA_BYTES: Final[str] = f"extra_serializes_to_more_than_{EXTRA_MAX_SERIALIZED_BYTES}_bytes"
VIOLATION_NOT_AN_IP: Final[str] = "value_is_not_an_ip_address"


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def clean_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = value.strip() if isinstance(value, str) else str(value).strip()
    return text or None


def fit_text(value: Any, max_chars: int) -> Optional[str]:
    text = clean_text(value)
    if text is None:
        return None
    return text[:max_chars]


def fit_agent_id(value: Any) -> str:
    return fit_text(value, AGENT_ID_MAX_CHARS) or ""


def fit_event_type(value: Any) -> str:
    return fit_text(value, EVENT_TYPE_MAX_CHARS) or ""


def fit_ip(value: Any) -> Optional[str]:
    text = fit_text(value, IP_MAX_CHARS)
    if text is None or not is_ip_address(text):
        return None
    return text


def fit_proto(value: Any) -> Optional[str]:
    return fit_text(value, PROTO_MAX_CHARS)


def fit_hot_text(column: str, value: Any) -> Optional[str]:
    return fit_text(value, HOT_TEXT_COLUMN_MAX_CHARS[column])


def fit_port(value: Any) -> Optional[int]:
    number = _as_int(value)
    if number is None or number < PORT_MIN or number > PORT_MAX:
        return None
    return number


def fit_byte_count(value: Any) -> int:
    number = _as_int(value)
    if number is None or number < BYTE_COUNT_MIN:
        return BYTE_COUNT_MIN
    return min(number, BYTE_COUNT_MAX)


def fit_schema_version(value: Any) -> int:
    number = _as_int(value)
    if number is None:
        return SCHEMA_VERSION_MIN
    return max(SCHEMA_VERSION_MIN, min(number, SCHEMA_VERSION_MAX))


def fit_int32(value: Any) -> Optional[int]:
    return _fit_bounded_int(value, INT32_MIN, INT32_MAX)


def fit_smallint(value: Any) -> Optional[int]:
    return _fit_bounded_int(value, SMALLINT_MIN, SMALLINT_MAX)


def fit_extra(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    if extra_structure_violation(value) is None:
        return value
    return _fit_mapping(value, depth=1, budget=_NodeBudget(EXTRA_MAX_NODES))


def extra_violation(value: Any) -> Optional[str]:
    reason = extra_structure_violation(value)
    if reason is not None:
        return reason
    if _serialized_bytes(value) > EXTRA_MAX_SERIALIZED_BYTES:
        return VIOLATION_EXTRA_BYTES
    return None


def extra_structure_violation(value: Any) -> Optional[str]:
    if not isinstance(value, dict):
        return VIOLATION_EXTRA_NOT_AN_OBJECT

    nodes = 0
    pending: list[tuple[Any, int]] = [(value, 1)]
    while pending:
        current, depth = pending.pop()
        if depth > EXTRA_MAX_DEPTH:
            return VIOLATION_EXTRA_DEPTH
        is_mapping = isinstance(current, Mapping)
        items = current.items() if is_mapping else enumerate(current)
        for key, item in items:
            nodes += 1
            if nodes > EXTRA_MAX_NODES:
                return VIOLATION_EXTRA_NODES
            if is_mapping and len(str(key)) > EXTRA_MAX_KEY_CHARS:
                return VIOLATION_EXTRA_KEY_CHARS
            if isinstance(item, str) and len(item) > EXTRA_MAX_TEXT_CHARS:
                return VIOLATION_EXTRA_TEXT_CHARS
            if _is_container(item):
                pending.append((item, depth + 1))
    return None


class _NodeBudget:
    __slots__ = ("remaining",)

    def __init__(self, total: int) -> None:
        self.remaining = int(total)

    def take(self) -> bool:
        if self.remaining <= 0:
            return False
        self.remaining -= 1
        return True


def _fit_mapping(value: Mapping[Any, Any], *, depth: int, budget: _NodeBudget) -> Dict[str, Any]:
    fitted: Dict[str, Any] = {}
    for key, item in value.items():
        if not budget.take():
            break
        fitted[str(key)[:EXTRA_MAX_KEY_CHARS]] = _fit_value(item, depth=depth + 1, budget=budget)
    return fitted


def _fit_sequence(value: Sequence[Any], *, depth: int, budget: _NodeBudget) -> list[Any]:
    fitted: list[Any] = []
    for item in value:
        if not budget.take():
            break
        fitted.append(_fit_value(item, depth=depth + 1, budget=budget))
    return fitted


def _fit_value(value: Any, *, depth: int, budget: _NodeBudget) -> Any:
    if isinstance(value, str):
        return value[:EXTRA_MAX_TEXT_CHARS]
    if isinstance(value, Mapping):
        if depth > EXTRA_MAX_DEPTH:
            return {}
        return _fit_mapping(value, depth=depth, budget=budget)
    if isinstance(value, (list, tuple)):
        if depth > EXTRA_MAX_DEPTH:
            return []
        return _fit_sequence(value, depth=depth, budget=budget)
    return value


def _is_container(value: Any) -> bool:
    return isinstance(value, (Mapping, list, tuple))


def _serialized_bytes(value: Any) -> int:
    try:
        payload = json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        return EXTRA_MAX_SERIALIZED_BYTES + 1
    return len(payload.encode("utf-8"))


def _as_int(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _fit_bounded_int(value: Any, minimum: int, maximum: int) -> Optional[int]:
    number = _as_int(value)
    if number is None:
        return None
    return max(minimum, min(number, maximum))
