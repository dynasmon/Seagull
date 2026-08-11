from __future__ import annotations

import os

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

from typing import Any, Dict, List

from app.features.events import storage_contract as contract
from app.features.events.models import NetEventModel
from app.workers.ingest.parser import event_from_wire, event_hot_columns, hot_event_from_wire


def _poison_wire_event() -> List[Any]:
    return [
        "a" * 200,
        "e" * 200,
        "99",
        "2026-08-11T12:00:00+00:00",
        "not-an-ip",
        "203.0.113.9",
        "-1",
        "70000",
        "p" * 200,
        "not-a-number",
        {
            "app_proto": "x" * 200,
            "dns_qname": "D" * 900,
            "http_method": "get",
            "ja4_ptype": "u" * 40,
            "note": "n" * (contract.EXTRA_MAX_TEXT_CHARS * 2),
        },
    ]


def _text_columns_of(row: Dict[str, Any]) -> Dict[str, str]:
    return {
        name: value
        for name, value in row.items()
        if isinstance(value, str) and getattr(NetEventModel.__table__.columns[name].type, "length", None)
    }


def test_every_column_bound_field_is_repaired_before_it_reaches_the_hot_store() -> None:
    row = hot_event_from_wire(_poison_wire_event())

    assert row is not None
    for name, value in _text_columns_of(row).items():
        assert len(value) <= int(NetEventModel.__table__.columns[name].type.length)

    assert row["src_ip"] is None
    assert row["dst_ip"] == "203.0.113.9"
    assert row["src_port"] is None
    assert row["dst_port"] is None
    assert row["bytes"] == 0
    assert row["schema_version"] == contract.SCHEMA_VERSION_MAX
    assert row["http_method"] == "GET"


def test_oversized_extra_is_trimmed_without_losing_the_event() -> None:
    row = event_from_wire(_poison_wire_event())

    assert row is not None
    assert contract.extra_structure_violation(row["extra"]) is None
    assert len(row["extra"]["note"]) == contract.EXTRA_MAX_TEXT_CHARS


def test_events_without_an_identity_are_dropped_instead_of_stored() -> None:
    assert event_from_wire([]) is None
    assert event_from_wire(["   ", "flow"]) is None
    assert event_from_wire(["agent-a", ""]) is None
    assert event_from_wire("not-a-row") is None


def test_out_of_range_process_and_confidence_values_are_bounded() -> None:
    columns = event_hot_columns(
        event_type="proc_exec",
        extra={"pid": 2**40, "ppid": "-" + "9" * 20, "exe_name": "b" * 400},
    )
    assert columns["proc_pid"] == contract.INT32_MAX
    assert columns["proc_ppid"] == contract.INT32_MIN
    assert len(columns["proc_name"]) == contract.HOT_TEXT_COLUMN_MAX_CHARS["proc_name"]

    heuristic = event_hot_columns(event_type="beacon_suspect", extra={"confidence": 10**9})
    assert heuristic["heuristic_confidence"] == contract.SMALLINT_MAX


def test_a_malformed_extra_never_becomes_a_null_jsonb_column() -> None:
    row = event_from_wire(["agent-a", "flow", 1, "2026-08-11T12:00:00+00:00", None, None, None, None, None, None, "x"])

    assert row is not None
    assert row["extra"] == {}
