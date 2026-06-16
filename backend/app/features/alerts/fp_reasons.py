from __future__ import annotations

from enum import StrEnum


class FalsePositiveReason(StrEnum):
    ALLOWLISTED_HOST = "allowlisted_host"
    SCANNING_TOOL = "scanning_tool"
    DEV_ENVIRONMENT = "dev_environment"
    EXPECTED_BEHAVIOR = "expected_behavior"
    KNOWN_VULN_SCANNER = "known_vuln_scanner"
    MONITORING_AGENT = "monitoring_agent"
    OTHER = "other"
