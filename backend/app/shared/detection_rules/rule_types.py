from __future__ import annotations

V1_RULE_SCHEMA_VERSION = 1
V2_RULE_SCHEMA_VERSION = 2
DEFAULT_RULE_SCHEMA_VERSION = V1_RULE_SCHEMA_VERSION
SUPPORTED_RULE_SCHEMA_VERSIONS = frozenset({V1_RULE_SCHEMA_VERSION, V2_RULE_SCHEMA_VERSION})
SUPPORTED_RUNTIME_RULE_SCHEMA_VERSIONS = frozenset({V1_RULE_SCHEMA_VERSION, V2_RULE_SCHEMA_VERSION})
SUPPORTED_RULE_TYPES = frozenset({"aggregate_count", "distinct_count", "multi_distinct"})
SUPPORTED_RULE_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
SUPPORTED_RULE_MATURITIES = frozenset({"stable", "experimental"})
SUPPORTED_RULE_STATUSES = frozenset({"draft", "active", "disabled", "deprecated"})
SUPPORTED_V2_AGGREGATION_TYPES = frozenset({"threshold", "cardinality", "multi_cardinality"})
