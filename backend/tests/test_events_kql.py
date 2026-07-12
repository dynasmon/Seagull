from __future__ import annotations

import os

import pytest

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "sqlite:///./test.db")

from app.features.events.domain.field_catalog import HUNT_FREE_TEXT_FIELDS, hunt_field_types
from app.features.events.domain.hunt_dialects import HuntQueryError
from app.features.events.domain.kql import CompiledKql, compile_kql

FIELDS = hunt_field_types()


def _compile(text: str, max_clauses: int = 32) -> CompiledKql:
    return compile_kql(
        text,
        field_types=FIELDS,
        free_text_fields=HUNT_FREE_TEXT_FIELDS,
        max_clauses=max_clauses,
    )


def _error(text: str, max_clauses: int = 32) -> HuntQueryError:
    with pytest.raises(HuntQueryError) as exc:
        _compile(text, max_clauses=max_clauses)
    return exc.value


def test_terms_ranges_and_negation_compile_to_filter_context() -> None:
    compiled = _compile("ssh_action:accepted and dst_port >= 30000 and not proto:udp")

    clauses = compiled.query["bool"]["filter"]
    assert {"term": {"ssh_action": "accepted"}} in clauses
    assert {"range": {"dst_port": {"gte": 30000}}} in clauses
    assert {"bool": {"must_not": [{"term": {"proto": "udp"}}]}} in clauses
    assert compiled.clause_count == 3
    assert compiled.has_wildcard is False
    assert compiled.has_timestamp_range is False


def test_or_and_grouping_with_parentheses() -> None:
    compiled = _compile("(event_type:ssh_auth or event_type:sudo) and agent_id:edge-1")

    outer = compiled.query["bool"]["filter"]
    assert {"term": {"agent_id": "edge-1"}} in outer
    grouped = outer[0]["bool"]
    assert grouped["minimum_should_match"] == 1
    assert {"term": {"event_type": "ssh_auth"}} in grouped["should"]
    assert {"term": {"event_type": "sudo"}} in grouped["should"]


def test_value_group_expands_to_should_terms() -> None:
    compiled = _compile("event_type:(ssh_auth or sudo)")

    grouped = compiled.query["bool"]
    assert grouped["minimum_should_match"] == 1
    assert {"term": {"event_type": "ssh_auth"}} in grouped["should"]
    assert compiled.clause_count == 2


def test_value_group_rejects_mixed_connectors() -> None:
    error = _error("event_type:(ssh_auth or sudo and flow)")
    assert error.reason == "syntax"
    assert "mix" in str(error)


def test_keywords_are_case_insensitive() -> None:
    compiled = _compile("ssh_action:accepted AND NOT proto:udp OR proto:tcp")
    assert compiled.clause_count == 3


def test_quoted_phrase_on_keyword_is_exact_term() -> None:
    compiled = _compile('sudo_command:"apt install nginx"')
    assert compiled.query == {"term": {"sudo_command": "apt install nginx"}}


def test_text_field_uses_match_and_match_phrase() -> None:
    match = _compile("extra_search:curl")
    assert match.query == {"match": {"extra_search": {"query": "curl", "operator": "and"}}}

    phrase = _compile('extra_search:"curl bash"')
    assert phrase.query == {"match_phrase": {"extra_search": "curl bash"}}


def test_bare_term_searches_free_text_fields() -> None:
    compiled = _compile("bruteforce")

    sqs = compiled.query["simple_query_string"]
    assert sqs["query"] == "bruteforce"
    assert sqs["fields"] == list(HUNT_FREE_TEXT_FIELDS)
    assert sqs["lenient"] is True
    assert sqs["default_operator"] == "and"


def test_star_value_compiles_to_exists() -> None:
    compiled = _compile("tls_sni:*")
    assert compiled.query == {"exists": {"field": "tls_sni"}}
    assert compiled.has_wildcard is False


def test_trailing_wildcard_is_allowed_and_flagged() -> None:
    compiled = _compile("dns_qname:evil.*")
    assert compiled.query == {"wildcard": {"dns_qname": {"value": "evil.*", "case_insensitive": True}}}
    assert compiled.has_wildcard is True


def test_leading_wildcard_is_rejected() -> None:
    assert _error("dns_qname:*evil*").reason == "leading_wildcard"
    assert _error("dns_qname:?evil").reason == "leading_wildcard"
    assert _error("*evil").reason == "leading_wildcard"


def test_wildcard_on_numeric_field_is_rejected() -> None:
    error = _error("dst_port:2*")
    assert error.reason == "invalid_value"


def test_ip_field_accepts_cidr_values() -> None:
    compiled = _compile("src_ip:203.0.113.0/24")
    assert compiled.query == {"term": {"src_ip": "203.0.113.0/24"}}


def test_extra_subfields_resolve_as_flattened() -> None:
    compiled = _compile("extra.container_id:web-1")
    assert compiled.query == {"term": {"extra.container_id": "web-1"}}


def test_unknown_field_lists_valid_fields() -> None:
    error = _error("sshaction:x")
    assert error.reason == "unknown_field"
    assert "agent_id" in str(error)
    assert "extra.*" in str(error)


def test_numeric_field_coerces_and_validates_values() -> None:
    compiled = _compile("dst_port:22")
    assert compiled.query == {"term": {"dst_port": 22}}

    error = _error("dst_port:ssh")
    assert error.reason == "invalid_value"


def test_date_field_requires_range_operators() -> None:
    error = _error("timestamp:2026-07-01")
    assert error.reason == "invalid_value"

    compiled = _compile('timestamp >= "2026-07-01T00:00:00Z"')
    assert compiled.query == {"range": {"timestamp": {"gte": "2026-07-01T00:00:00Z"}}}
    assert compiled.has_timestamp_range is True


def test_range_on_keyword_field_is_rejected() -> None:
    error = _error("agent_id > 5")
    assert error.reason == "invalid_value"


def test_clause_limit_is_enforced() -> None:
    error = _error("ssh_action:a and proto:b and agent_id:c", max_clauses=2)
    assert error.reason == "too_many_clauses"


def test_group_depth_limit_is_enforced() -> None:
    error = _error("(" * 17 + "proto:tcp" + ")" * 17)
    assert error.reason == "syntax"
    assert "deeper" in str(error)


def test_adjacent_clauses_without_operator_are_rejected() -> None:
    error = _error("ssh_action:accepted dst_port:22")
    assert error.reason == "syntax"
    assert "position" in str(error)


def test_missing_value_reports_position() -> None:
    error = _error("ssh_action:")
    assert error.reason == "syntax"
    assert "position 12" in str(error)


def test_unterminated_phrase_is_rejected() -> None:
    error = _error('sudo_command:"rm -rf')
    assert error.reason == "syntax"
    assert "unterminated" in str(error)


def test_unbalanced_parenthesis_is_rejected() -> None:
    error = _error("(proto:tcp")
    assert error.reason == "syntax"
    assert "')'" in str(error)


def test_blank_query_is_rejected() -> None:
    error = _error("   ")
    assert error.reason == "syntax"
