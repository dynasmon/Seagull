from __future__ import annotations

import os
from datetime import datetime, timezone

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

import pytest
from pydantic import ValidationError

from app.features.events import storage_contract as contract
from app.features.events.models import NetEventModel
from app.features.events.rollup_keys import ROLLUP_NO_IP, ROLLUP_NO_PORT, rollup_dst_ip, rollup_dst_port
from app.features.events.schemas import NetEvent, NetEventDB


def _column_length(name: str) -> int:
    return int(NetEventModel.__table__.columns[name].type.length)


def _event(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "agent_id": "agent-a",
        "event_type": "ssh_auth",
        "schema_version": 1,
        "timestamp": "2026-08-11T12:00:00+00:00",
    }
    payload.update(overrides)
    return payload


def test_identity_limits_match_the_hot_store_columns() -> None:
    assert contract.AGENT_ID_MAX_CHARS == _column_length("agent_id")
    assert contract.EVENT_TYPE_MAX_CHARS == _column_length("event_type")
    assert contract.PROTO_MAX_CHARS == _column_length("proto")
    assert contract.IP_MAX_CHARS == _column_length("src_ip") == _column_length("dst_ip")


def test_hot_text_limits_cover_every_text_column_exactly() -> None:
    identity_columns = {"agent_id", "event_type", "proto", "src_ip", "dst_ip"}
    text_columns = {
        name
        for name, column in NetEventModel.__table__.columns.items()
        if getattr(column.type, "length", None) is not None
    }
    assert set(contract.HOT_TEXT_COLUMN_MAX_CHARS) == text_columns - identity_columns
    for name, max_chars in contract.HOT_TEXT_COLUMN_MAX_CHARS.items():
        assert max_chars == _column_length(name)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("agent_id", "a" * (contract.AGENT_ID_MAX_CHARS + 1)),
        ("agent_id", "../escape"),
        ("agent_id", ""),
        ("event_type", "e" * (contract.EVENT_TYPE_MAX_CHARS + 1)),
        ("event_type", "ssh auth"),
        ("proto", "p" * (contract.PROTO_MAX_CHARS + 1)),
        ("src_ip", "not-an-ip"),
        ("dst_ip", "999.1.1.1"),
        ("src_port", -1),
        ("dst_port", contract.PORT_MAX + 1),
        ("bytes", -1),
        ("schema_version", 0),
    ],
)
def test_ingest_contract_rejects_values_the_hot_store_cannot_hold(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        NetEvent.model_validate(_event(**{field: value}))


def test_ingest_contract_accepts_the_widest_valid_event() -> None:
    event = NetEvent.model_validate(
        _event(
            agent_id="a" * contract.AGENT_ID_MAX_CHARS,
            event_type="e" * contract.EVENT_TYPE_MAX_CHARS,
            src_ip="2001:db8::1",
            dst_ip="198.51.100.7",
            src_port=contract.PORT_MAX,
            dst_port=contract.PORT_MIN,
            proto="p" * contract.PROTO_MAX_CHARS,
            bytes=contract.BYTE_COUNT_MAX,
            extra={"note": "n" * contract.EXTRA_MAX_TEXT_CHARS},
        )
    )
    assert event.src_ip == "2001:db8::1"
    assert event.bytes == contract.BYTE_COUNT_MAX


def test_blank_optional_text_is_read_as_absent() -> None:
    event = NetEvent.model_validate(_event(src_ip="  ", proto=""))
    assert event.src_ip is None
    assert event.proto is None


@pytest.mark.parametrize(
    ("extra", "reason"),
    [
        ({"k" * (contract.EXTRA_MAX_KEY_CHARS + 1): "v"}, contract.VIOLATION_EXTRA_KEY_CHARS),
        ({"note": "n" * (contract.EXTRA_MAX_TEXT_CHARS + 1)}, contract.VIOLATION_EXTRA_TEXT_CHARS),
        ({str(index): index for index in range(contract.EXTRA_MAX_NODES + 1)}, contract.VIOLATION_EXTRA_NODES),
    ],
)
def test_extra_violations_are_named(extra: dict, reason: str) -> None:
    assert contract.extra_violation(extra) == reason
    with pytest.raises(ValidationError, match=reason):
        NetEvent.model_validate(_event(extra=extra))


def test_extra_nesting_beyond_the_contract_is_rejected() -> None:
    nested: dict = {"leaf": 1}
    for _ in range(contract.EXTRA_MAX_DEPTH):
        nested = {"child": nested}
    assert contract.extra_violation(nested) == contract.VIOLATION_EXTRA_DEPTH


def test_extra_within_the_contract_is_returned_untouched() -> None:
    extra = {"action": "failed_password", "peers": [{"ip": "203.0.113.5"}]}
    assert contract.extra_violation(extra) is None
    assert contract.fit_extra(extra) is extra


def test_oversized_extra_is_trimmed_to_the_contract() -> None:
    extra = {
        "note": "n" * (contract.EXTRA_MAX_TEXT_CHARS * 2),
        "k" * (contract.EXTRA_MAX_KEY_CHARS * 2): "v",
    }
    fitted = contract.fit_extra(extra)

    assert contract.extra_structure_violation(fitted) is None
    assert len(fitted["note"]) == contract.EXTRA_MAX_TEXT_CHARS
    assert all(len(key) <= contract.EXTRA_MAX_KEY_CHARS for key in fitted)


def test_serialized_extra_budget_is_enforced_only_at_the_edge() -> None:
    extra = {str(index): "v" * 1024 for index in range(64)}

    assert contract.extra_violation(extra) == contract.VIOLATION_EXTRA_BYTES
    assert contract.extra_structure_violation(extra) is None
    assert contract.fit_extra(extra) is extra


def test_rollup_keys_drop_values_that_are_not_addresses_or_ports() -> None:
    assert rollup_dst_ip("203.0.113.9") == "203.0.113.9"
    assert rollup_dst_ip("not-an-ip") == ROLLUP_NO_IP
    assert rollup_dst_port("443") == 443
    assert rollup_dst_port(70000) == ROLLUP_NO_PORT


def test_read_model_still_renders_rows_written_before_the_contract() -> None:
    legacy = NetEventDB(
        id=7,
        agent_id="legacy agent",
        event_type="legacy event type that is far longer than the column",
        schema_version=99,
        timestamp=datetime.now(timezone.utc),
        src_ip="hostname.invalid",
        dst_port=99999,
        proto="a very long protocol name",
        extra={"deep": {"deep": {"deep": {"deep": {"deep": {"deep": {"deep": {"deep": {"deep": 1}}}}}}}}},
    )
    assert legacy.id == 7
    assert legacy.src_ip == "hostname.invalid"
