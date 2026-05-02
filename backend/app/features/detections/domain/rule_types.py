from __future__ import annotations


DEFAULT_RULE_SCHEMA_VERSION = 1
SUPPORTED_RULE_SCHEMA_VERSIONS = frozenset({DEFAULT_RULE_SCHEMA_VERSION})
SUPPORTED_RULE_TYPES = frozenset({"aggregate_count", "distinct_count", "multi_distinct"})
SUPPORTED_RULE_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
SUPPORTED_RULE_MATURITIES = frozenset({"stable", "experimental"})
