
import os

os.environ.setdefault("SEAGULL_DB_PASSWORD", "test")
os.environ.setdefault("SEAGULL_SECRET_KEY", "test")
os.environ.setdefault("SEAGULL_JWT_SECRET", "test")

from datetime import datetime
from types import SimpleNamespace

import pytest

from app.features.alerts.lifecycle import (
    VALID_DISPOSITIONS,
    VALID_STATUSES,
    InvalidTransitionError,
    MissingDispositionError,
    apply_triage,
    check_transition,
)


def _alert(**kwargs):
    defaults = dict(
        status="open",
        disposition=None,
        priority=None,
        assigned_to=None,
        investigation_id=None,
        acknowledged_at=None,
        acknowledged_by=None,
        closed_at=None,
        closed_by=None,
        triage_notes=None,
        risk_score=None,
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


NOW = datetime(2026, 5, 6, 12, 0, 0)


# --- check_transition ---

def test_open_to_acknowledged():
    check_transition("open", "acknowledged")


def test_open_to_investigating():
    check_transition("open", "investigating")


def test_open_to_closed():
    check_transition("open", "closed")


def test_acknowledged_to_investigating():
    check_transition("acknowledged", "investigating")


def test_closed_to_open():
    check_transition("closed", "open")


def test_investigating_to_open():
    check_transition("investigating", "open")


def test_invalid_transition_acknowledged_to_open_from_closed_fails():
    with pytest.raises(InvalidTransitionError):
        check_transition("closed", "acknowledged")


def test_invalid_transition_investigating_to_acknowledged_fails():
    with pytest.raises(InvalidTransitionError):
        check_transition("investigating", "acknowledged")


def test_invalid_transition_message_contains_states():
    with pytest.raises(InvalidTransitionError, match="investigating.*acknowledged"):
        check_transition("investigating", "acknowledged")


# --- apply_triage: status transitions ---

def test_acknowledge_sets_timestamp_and_status():
    row = _alert()
    apply_triage(
        row,
        fields_set={"status"},
        status="acknowledged",
        disposition=None,
        priority=None,
        assigned_to=None,
        triage_notes=None,
        risk_score=None,
        investigation_id=None,
        actor_username="analyst1",
        now=NOW,
    )
    assert row.status == "acknowledged"
    assert row.acknowledged_at == NOW
    assert row.acknowledged_by == "analyst1"


def test_acknowledge_does_not_overwrite_existing_timestamp():
    earlier = datetime(2026, 5, 5, 10, 0, 0)
    row = _alert(status="acknowledged", acknowledged_at=earlier, acknowledged_by="alice")
    apply_triage(
        row,
        fields_set={"status"},
        status="acknowledged",
        disposition=None,
        priority=None,
        assigned_to=None,
        triage_notes=None,
        risk_score=None,
        investigation_id=None,
        actor_username="bob",
        now=NOW,
    )
    assert row.acknowledged_at == earlier
    assert row.acknowledged_by == "alice"


def test_close_sets_closed_fields():
    row = _alert()
    apply_triage(
        row,
        fields_set={"status", "disposition"},
        status="closed",
        disposition="true_positive",
        priority=None,
        assigned_to=None,
        triage_notes=None,
        risk_score=None,
        investigation_id=None,
        actor_username="analyst1",
        now=NOW,
    )
    assert row.status == "closed"
    assert row.disposition == "true_positive"
    assert row.closed_at == NOW
    assert row.closed_by == "analyst1"


def test_close_requires_disposition_raises():
    row = _alert()
    with pytest.raises(MissingDispositionError):
        apply_triage(
            row,
            fields_set={"status"},
            status="closed",
            disposition=None,
            priority=None,
            assigned_to=None,
            triage_notes=None,
            risk_score=None,
            investigation_id=None,
            actor_username="analyst1",
            now=NOW,
        )


def test_close_uses_existing_row_disposition_if_not_provided():
    row = _alert(disposition="benign")
    apply_triage(
        row,
        fields_set={"status"},
        status="closed",
        disposition=None,
        priority=None,
        assigned_to=None,
        triage_notes=None,
        risk_score=None,
        investigation_id=None,
        actor_username="analyst1",
        now=NOW,
    )
    assert row.status == "closed"
    assert row.disposition == "benign"


def test_reopen_clears_closed_fields():
    row = _alert(status="closed", closed_at=NOW, closed_by="analyst1", disposition="benign")
    apply_triage(
        row,
        fields_set={"status"},
        status="open",
        disposition=None,
        priority=None,
        assigned_to=None,
        triage_notes=None,
        risk_score=None,
        investigation_id=None,
        actor_username="analyst2",
        now=NOW,
    )
    assert row.status == "open"
    assert row.closed_at is None
    assert row.closed_by is None


def test_invalid_transition_raises():
    row = _alert(status="closed")
    with pytest.raises(InvalidTransitionError):
        apply_triage(
            row,
            fields_set={"status"},
            status="investigating",
            disposition=None,
            priority=None,
            assigned_to=None,
            triage_notes=None,
            risk_score=None,
            investigation_id=None,
            actor_username="analyst1",
            now=NOW,
        )


# --- apply_triage: field updates ---

def test_priority_updated():
    row = _alert()
    apply_triage(
        row,
        fields_set={"priority"},
        status=None,
        disposition=None,
        priority=2,
        assigned_to=None,
        triage_notes=None,
        risk_score=None,
        investigation_id=None,
        actor_username=None,
        now=NOW,
    )
    assert row.priority == 2


def test_priority_out_of_range_raises():
    row = _alert()
    with pytest.raises(ValueError, match="priority"):
        apply_triage(
            row,
            fields_set={"priority"},
            status=None,
            disposition=None,
            priority=5,
            assigned_to=None,
            triage_notes=None,
            risk_score=None,
            investigation_id=None,
            actor_username=None,
            now=NOW,
        )


def test_risk_score_out_of_range_raises():
    row = _alert()
    with pytest.raises(ValueError, match="risk_score"):
        apply_triage(
            row,
            fields_set={"risk_score"},
            status=None,
            disposition=None,
            priority=None,
            assigned_to=None,
            triage_notes=None,
            risk_score=101,
            investigation_id=None,
            actor_username=None,
            now=NOW,
        )


def test_assigned_to_can_be_cleared():
    row = _alert(assigned_to="alice")
    apply_triage(
        row,
        fields_set={"assigned_to"},
        status=None,
        disposition=None,
        priority=None,
        assigned_to=None,
        triage_notes=None,
        risk_score=None,
        investigation_id=None,
        actor_username=None,
        now=NOW,
    )
    assert row.assigned_to is None


def test_fields_not_in_fields_set_unchanged():
    row = _alert(assigned_to="alice", priority=1)
    apply_triage(
        row,
        fields_set={"triage_notes"},
        status=None,
        disposition=None,
        priority=2,
        assigned_to="bob",
        triage_notes="check this",
        risk_score=None,
        investigation_id=None,
        actor_username=None,
        now=NOW,
    )
    assert row.assigned_to == "alice"
    assert row.priority == 1
    assert row.triage_notes == "check this"


# --- constants ---

def test_valid_statuses_complete():
    assert VALID_STATUSES == frozenset({"open", "acknowledged", "investigating", "closed"})


def test_valid_dispositions_complete():
    assert "true_positive" in VALID_DISPOSITIONS
    assert "false_positive" in VALID_DISPOSITIONS
    assert "unknown" in VALID_DISPOSITIONS
