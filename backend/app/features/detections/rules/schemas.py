from __future__ import annotations

from typing import Any, TypedDict


class RuleConditionDocument(TypedDict, total=False):
    operator: str
    value: int
    min_events: int


class DetectionRuleDocument(TypedDict, total=False):
    id: str
    name: str
    description: str
    enabled: bool
    type: str
    severity: str
    window: str
    cooldown: str
    match: dict[str, Any]
    group_by: str | list[str]
    condition: RuleConditionDocument
    schedule: dict[str, Any]
    tuning: dict[str, Any]
    suppressions: list[dict[str, Any]]
    mitre: dict[str, Any]
    environments: list[str]
    env_overrides: dict[str, Any]
    category: str
    pack: str
    maturity: str
    version: int
    rule_version: int
    schema_version: int
    pack_version: int
    source_file: str


class RulePackDocument(TypedDict, total=False):
    pack: str
    category: str
    maturity: str
    environments: list[str]
    pack_version: int
    schema_version: int
    rules: list[DetectionRuleDocument]
