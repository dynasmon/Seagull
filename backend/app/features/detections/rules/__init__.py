from __future__ import annotations

from app.features.detections.rules.loader import load_and_validate_rules, load_rules
from app.features.detections.rules.registry import (
    SUPPORTED_RUNTIME_EVENT_FIELDS,
    normalize_group_by_fields,
    normalize_match_fields,
    resolve_runtime_field,
)


def import_sigma_rule_document(*args, **kwargs):
    from app.features.detections.rules.sigma_import import import_sigma_rule_document as _import_sigma_rule_document

    return _import_sigma_rule_document(*args, **kwargs)


def import_sigma_yaml(*args, **kwargs):
    from app.features.detections.rules.sigma_import import import_sigma_yaml as _import_sigma_yaml

    return _import_sigma_yaml(*args, **kwargs)


def build_sigma_import_pack_document(*args, **kwargs):
    from app.features.detections.rules.sigma_import import (
        build_sigma_import_pack_document as _build_sigma_import_pack_document,
    )

    return _build_sigma_import_pack_document(*args, **kwargs)


def convert_sigma_file(*args, **kwargs):
    from app.features.detections.rules.sigma_import import convert_sigma_file as _convert_sigma_file

    return _convert_sigma_file(*args, **kwargs)


def convert_sigma_path(*args, **kwargs):
    from app.features.detections.rules.sigma_import import convert_sigma_path as _convert_sigma_path

    return _convert_sigma_path(*args, **kwargs)

__all__ = [
    "SUPPORTED_RUNTIME_EVENT_FIELDS",
    "build_sigma_import_pack_document",
    "convert_sigma_file",
    "convert_sigma_path",
    "import_sigma_rule_document",
    "import_sigma_yaml",
    "load_and_validate_rules",
    "load_rules",
    "normalize_group_by_fields",
    "normalize_match_fields",
    "resolve_runtime_field",
]
