from __future__ import annotations

from app.features.detections.domain.canonical_fields import (
    CANONICAL_FIELD_MAP,
    CanonicalFieldSpec,
    UnsupportedCanonicalFieldError,
    canonical_field_names,
    resolve_canonical_field,
)
from app.features.detections.domain.validation import DetectionRuleValidationError
from app.features.detections.rules.loader import load_and_validate_rules, load_rules
from app.features.detections.rules.registry import (
    SUPPORTED_RUNTIME_EVENT_FIELDS,
    normalize_group_by_fields,
    normalize_match_fields,
    resolve_runtime_field,
)

__all__ = [
    "CANONICAL_FIELD_MAP",
    "CanonicalFieldSpec",
    "DetectionRuleValidationError",
    "SUPPORTED_RUNTIME_EVENT_FIELDS",
    "UnsupportedCanonicalFieldError",
    "canonical_field_names",
    "load_and_validate_rules",
    "load_rules",
    "normalize_group_by_fields",
    "normalize_match_fields",
    "resolve_canonical_field",
    "resolve_runtime_field",
]
