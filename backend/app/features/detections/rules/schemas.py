from __future__ import annotations

from typing import Any, TypedDict


class RuleConditionDocument(TypedDict, total=False):
    operator: str
    value: int
    min_events: int


class V1DetectionRuleDocument(TypedDict, total=False):
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


class V2LogsourceDocument(TypedDict, total=False):
    product: str
    service: str
    category: str
    source: str
    event_type: str


class V2AttackDocument(TypedDict, total=False):
    tactic: str
    technique_id: str
    technique: str
    confidence: int


class V2DetectionSelectionDocument(TypedDict, total=False):
    pass


class V2DetectionDocument(TypedDict, total=False):
    condition: str


class V2AggregationDistinctConditionDocument(TypedDict, total=False):
    field: str
    operator: str
    value: int


class V2AggregationDocument(TypedDict, total=False):
    type: str
    window: str
    group_by: str | list[str]
    field: str
    distinct_conditions: list[V2AggregationDistinctConditionDocument]
    condition: RuleConditionDocument
    min_events: int


class V2SuppressionDocument(TypedDict, total=False):
    cooldown: str
    rules: list[dict[str, Any]]


class V2ResponseDocument(TypedDict, total=False):
    playbook: str
    false_positives: str | list[str]


class V2DetectionRuleDocument(TypedDict, total=False):
    schema_version: int
    id: str
    name: str
    description: str
    enabled: bool
    status: str
    maturity: str
    severity: str
    risk_score: int
    confidence: int
    logsource: V2LogsourceDocument
    attack: V2AttackDocument | dict[str, Any]
    detection: V2DetectionDocument | dict[str, Any]
    aggregation: V2AggregationDocument | dict[str, Any]
    suppression: V2SuppressionDocument | dict[str, Any]
    tuning: dict[str, Any]
    response: V2ResponseDocument | dict[str, Any]
    tests: list[dict[str, Any]]
    pack: str
    category: str
    pack_version: int
    environments: list[str]
    source_file: str


DetectionRuleDocument = V1DetectionRuleDocument | V2DetectionRuleDocument


class RulePackDocument(TypedDict, total=False):
    pack: str
    category: str
    maturity: str
    environments: list[str]
    pack_version: int
    schema_version: int
    rules: list[DetectionRuleDocument]
