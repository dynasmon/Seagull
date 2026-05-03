from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:seagull@127.0.0.1:5432/seagull")

from app.features.correlations.engine import (
    build_incidents,
    group_value,
    passes_filter,
    segment_by_window,
)
from app.features.correlations.models import (
    CorrelationEntityStateModel,
    CorrelationIncidentEvidenceModel,
    CorrelationIncidentModel,
    CorrelationRuleModel,
    CorrelationRuleRunModel,
)
from app.features.correlations.schemas import (
    CorrelationAlertRef,
    CorrelationIncidentOut,
    CorrelationIncidentStatusIn,
    CorrelationRunOut,
)
from app.features.correlations.service import (
    _incident_dedup_key,
    _upsert_entity_state,
    _upsert_evidence,
    _upsert_incident,
    list_correlation_incidents,
    run_correlations,
    update_incident_status,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@dataclass
class _Alert:
    id: int
    created_at: datetime
    rule_id: str = "r1"
    severity: str = "high"
    src_ip: Optional[str] = "1.2.3.4"
    dst_ip: Optional[str] = "5.6.7.8"
    dst_port: Optional[int] = 22
    description: str = "test alert"


@dataclass
class _Rule:
    id: int
    name: str
    enabled: bool = True
    severity: str = "high"
    strategy: str = "burst"
    group_by: str = "src_ip"
    window_seconds: int = 600
    min_alerts: int = 2
    include_patterns: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(default_factory=list)
    stages: List[dict] = field(default_factory=list)


def _make_incident_out(
    rule_id: int = 1,
    rule_name: str = "Test Rule",
    group_by: str = "src_ip",
    group_value_str: str = "1.2.3.4",
    started_at: Optional[datetime] = None,
    ended_at: Optional[datetime] = None,
    alert_count: int = 3,
    unique_rules: Optional[List[str]] = None,
    stage_hits: Optional[Dict] = None,
    sample_alerts: Optional[List] = None,
) -> CorrelationIncidentOut:
    t = started_at or datetime(2026, 5, 1, 10, 0, 0)
    return CorrelationIncidentOut(
        id=f"cr{rule_id}:{group_value_str}:{t.isoformat()}",
        correlation_rule_id=rule_id,
        correlation_rule_name=rule_name,
        severity="high",
        group_by=group_by,
        group_value=group_value_str,
        started_at=t,
        ended_at=ended_at or t + timedelta(minutes=5),
        alert_count=alert_count,
        unique_rules=unique_rules or ["r1"],
        stage_hits=stage_hits or {},
        sample_alerts=sample_alerts or [],
    )


class _FakeDB:
    """Minimal in-memory DB session for unit tests."""

    def __init__(self):
        self._added: List[Any] = []
        self._flushed = False
        self._committed = False
        self._query_results: Dict[str, Any] = {}

    def add(self, obj):
        self._added.append(obj)
        if hasattr(obj, "id") and obj.id is None:
            obj.id = len(self._added)

    def flush(self):
        self._flushed = True
        for obj in self._added:
            if hasattr(obj, "id") and obj.id is None:
                obj.id = len(self._added)

    def commit(self):
        self._committed = True

    def refresh(self, obj):
        pass

    def execute(self, stmt):
        return _FakeResult([])

    def get(self, model, pk):
        return None


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None


# ---------------------------------------------------------------------------
# dedup_key tests
# ---------------------------------------------------------------------------

def test_incident_dedup_key_format():
    t = datetime(2026, 5, 3, 14, 35, 22)
    key = _incident_dedup_key(5, "192.168.1.1", t)
    assert key == "cr5:192.168.1.1:20260503T1435"


def test_incident_dedup_key_minute_precision():
    t1 = datetime(2026, 5, 3, 14, 35, 0)
    t2 = datetime(2026, 5, 3, 14, 35, 59)
    assert _incident_dedup_key(1, "x", t1) == _incident_dedup_key(1, "x", t2)


# ---------------------------------------------------------------------------
# _upsert_incident tests
# ---------------------------------------------------------------------------

def test_upsert_incident_creates_new_when_none_open():
    db = _FakeDB()
    rule = _Rule(id=1, name="Rule A")
    inc_out = _make_incident_out(rule_id=1)
    now = datetime.utcnow()

    with patch("app.features.correlations.service.find_open_incident", return_value=None):
        incident, is_new = _upsert_incident(db, rule=rule, incident_out=inc_out, now=now)

    assert is_new is True
    assert isinstance(incident, CorrelationIncidentModel)
    assert incident.correlation_rule_id == 1
    assert incident.status == "open"
    assert incident.group_value == "1.2.3.4"
    assert "cr1:" in incident.dedup_key


def test_upsert_incident_updates_existing_open():
    existing = CorrelationIncidentModel(
        id=99,
        correlation_rule_id=1,
        correlation_rule_name="Rule A",
        status="open",
        severity="high",
        group_by="src_ip",
        group_value="1.2.3.4",
        dedup_key="cr1:1.2.3.4:20260501T1000",
        started_at=datetime(2026, 5, 1, 10, 0),
        last_seen_at=datetime(2026, 5, 1, 10, 5),
        alert_count=2,
        unique_rules=["r1"],
        stage_hits={},
        context={},
        created_at=datetime(2026, 5, 1),
        updated_at=datetime(2026, 5, 1),
    )

    db = _FakeDB()
    rule = _Rule(id=1, name="Rule A")
    inc_out = _make_incident_out(
        rule_id=1,
        alert_count=5,
        unique_rules=["r1", "r2"],
        ended_at=datetime(2026, 5, 1, 10, 10),
    )
    now = datetime.utcnow()

    with patch("app.features.correlations.service.find_open_incident", return_value=existing):
        incident, is_new = _upsert_incident(db, rule=rule, incident_out=inc_out, now=now)

    assert is_new is False
    assert incident is existing
    assert incident.alert_count == 5
    assert "r2" in incident.unique_rules
    assert incident.last_seen_at == datetime(2026, 5, 1, 10, 10)


# ---------------------------------------------------------------------------
# _upsert_evidence tests
# ---------------------------------------------------------------------------

def test_upsert_evidence_creates_for_new_incident():
    db = _FakeDB()
    incident = CorrelationIncidentModel(id=1)
    alerts = [
        _Alert(id=10, created_at=datetime(2026, 5, 1, 10, 0)),
        _Alert(id=11, created_at=datetime(2026, 5, 1, 10, 1)),
    ]
    _upsert_evidence(db, incident=incident, sample_alerts=alerts, is_new=True)
    evidence_items = [o for o in db._added if isinstance(o, CorrelationIncidentEvidenceModel)]
    assert len(evidence_items) == 2
    assert evidence_items[0].alert_id == 10
    assert evidence_items[1].alert_id == 11


def test_upsert_evidence_skips_existing_alert_ids():
    db = _FakeDB()
    incident = CorrelationIncidentModel(id=1)
    alerts = [
        _Alert(id=10, created_at=datetime(2026, 5, 1, 10, 0)),
        _Alert(id=11, created_at=datetime(2026, 5, 1, 10, 1)),  # already in DB
    ]

    with patch("app.features.correlations.service.get_evidence_alert_ids", return_value={11}):
        _upsert_evidence(db, incident=incident, sample_alerts=alerts, is_new=False)

    evidence_items = [o for o in db._added if isinstance(o, CorrelationIncidentEvidenceModel)]
    assert len(evidence_items) == 1
    assert evidence_items[0].alert_id == 10


# ---------------------------------------------------------------------------
# _upsert_entity_state tests
# ---------------------------------------------------------------------------

def test_upsert_entity_state_creates_new():
    db = _FakeDB()
    now = datetime.utcnow()

    with patch("app.features.correlations.service.get_entity_state", return_value=None):
        _upsert_entity_state(db, entity_type="src_ip", entity_value="1.2.3.4", now=now, context={})

    states = [o for o in db._added if isinstance(o, CorrelationEntityStateModel)]
    assert len(states) == 1
    assert states[0].entity_type == "src_ip"
    assert states[0].entity_value == "1.2.3.4"
    assert states[0].seen_count == 1


def test_upsert_entity_state_increments_existing():
    existing = CorrelationEntityStateModel(
        id=5,
        entity_type="src_ip",
        entity_value="1.2.3.4",
        first_seen_at=datetime(2026, 5, 1),
        last_seen_at=datetime(2026, 5, 1),
        seen_count=3,
        last_context={},
        created_at=datetime(2026, 5, 1),
        updated_at=datetime(2026, 5, 1),
    )
    db = _FakeDB()
    now = datetime.utcnow()
    ctx = {"correlation_rule_id": 1}

    with patch("app.features.correlations.service.get_entity_state", return_value=existing):
        _upsert_entity_state(db, entity_type="src_ip", entity_value="1.2.3.4", now=now, context=ctx)

    assert existing.seen_count == 4
    assert existing.last_context == ctx
    assert existing.last_seen_at == now


# ---------------------------------------------------------------------------
# run_correlations tests
# ---------------------------------------------------------------------------

def test_run_correlations_returns_runout_and_persists():
    rule = _Rule(id=1, name="Rule A", strategy="burst", group_by="src_ip", window_seconds=600, min_alerts=2)
    t0 = datetime(2026, 5, 1, 10, 0, 0)
    alerts = [
        _Alert(id=i, created_at=t0 + timedelta(seconds=i * 10), rule_id="r1")
        for i in range(3)
    ]

    sample = [
        CorrelationAlertRef(
            id=a.id, created_at=a.created_at, rule_id=a.rule_id,
            severity=a.severity, src_ip=a.src_ip, dst_ip=a.dst_ip,
            dst_port=a.dst_port, description=a.description,
        )
        for a in alerts[:2]
    ]
    incident_out = _make_incident_out(rule_id=1, sample_alerts=sample)

    db = MagicMock()
    db.add = MagicMock()
    db.flush = MagicMock()
    db.commit = MagicMock()
    db.execute = MagicMock(return_value=_FakeResult([]))

    fake_incident = CorrelationIncidentModel(
        id=42,
        correlation_rule_id=1,
        correlation_rule_name="Rule A",
        status="open",
        severity="high",
        group_by="src_ip",
        group_value="1.2.3.4",
        dedup_key="cr1:1.2.3.4:20260501T1000",
        started_at=datetime(2026, 5, 1, 10, 0),
        last_seen_at=datetime(2026, 5, 1, 10, 5),
        alert_count=3,
        unique_rules=["r1"],
        stage_hits={},
        context={},
        created_at=datetime(2026, 5, 1),
        updated_at=datetime(2026, 5, 1),
    )

    with (
        patch("app.features.correlations.service.list_enabled_rules", return_value=[rule]),
        patch("app.features.correlations.service.list_recent_alerts", return_value=alerts),
        patch("app.features.correlations.service.build_incidents", return_value=[incident_out]),
        patch("app.features.correlations.service._upsert_incident", return_value=(fake_incident, True)),
        patch("app.features.correlations.service._upsert_evidence"),
        patch("app.features.correlations.service._upsert_entity_state"),
    ):
        result = run_correlations(db, limit=100, max_age_minutes=60, sample_limit=10)

    assert isinstance(result, CorrelationRunOut)
    assert result.rules_evaluated == 1
    assert result.alerts_scanned == 3
    assert len(result.incidents) == 1
    assert result.incidents[0].db_id == 42
    assert result.incidents[0].status == "open"
    db.commit.assert_called_once()


def test_run_correlations_backward_compatible_schema():
    db = MagicMock()
    db.add = MagicMock()
    db.flush = MagicMock()
    db.commit = MagicMock()
    db.execute = MagicMock(return_value=_FakeResult([]))

    with (
        patch("app.features.correlations.service.list_enabled_rules", return_value=[]),
        patch("app.features.correlations.service.list_recent_alerts", return_value=[]),
        patch("app.features.correlations.service.build_incidents", return_value=[]),
    ):
        result = run_correlations(db, limit=500, max_age_minutes=1440, sample_limit=25)

    assert result.rules_evaluated == 0
    assert result.alerts_scanned == 0
    assert result.incidents == []


def test_run_correlations_creates_rule_run_record():
    db = MagicMock()
    db.add = MagicMock()
    db.flush = MagicMock()
    db.commit = MagicMock()
    db.execute = MagicMock(return_value=_FakeResult([]))

    with (
        patch("app.features.correlations.service.list_enabled_rules", return_value=[]),
        patch("app.features.correlations.service.list_recent_alerts", return_value=[]),
        patch("app.features.correlations.service.build_incidents", return_value=[]),
    ):
        run_correlations(db, limit=500, max_age_minutes=1440, sample_limit=25)

    added_types = [type(call.args[0]).__name__ for call in db.add.call_args_list]
    assert "CorrelationRuleRunModel" in added_types


# ---------------------------------------------------------------------------
# Status lifecycle tests
# ---------------------------------------------------------------------------

def test_update_incident_status_changes_status():
    incident = CorrelationIncidentModel(
        id=1,
        correlation_rule_id=1,
        correlation_rule_name="Rule A",
        status="open",
        severity="high",
        group_by="src_ip",
        group_value="1.2.3.4",
        dedup_key="cr1:1.2.3.4:20260501T1000",
        started_at=datetime(2026, 5, 1, 10, 0),
        last_seen_at=datetime(2026, 5, 1, 10, 5),
        alert_count=3,
        unique_rules=["r1"],
        stage_hits={},
        context={},
        created_at=datetime(2026, 5, 1),
        updated_at=datetime(2026, 5, 1),
    )

    db = MagicMock()
    db.commit = MagicMock()
    request = MagicMock()
    admin = MagicMock()
    admin.id = 1
    admin.username = "admin"

    payload = CorrelationIncidentStatusIn(status="triaged", summary="Under investigation")

    with (
        patch("app.features.correlations.service.get_incident_by_id", return_value=incident),
        patch("app.features.correlations.service.write_audit_event"),
        patch("app.features.correlations.service.get_correlation_incident") as mock_detail,
    ):
        mock_detail.return_value = MagicMock(status="triaged")
        result = update_incident_status(
            db, incident_id=1, payload=payload, request=request, admin=admin
        )

    assert incident.status == "triaged"
    assert incident.summary == "Under investigation"
    assert incident.closed_at is None  # not closed yet
    db.commit.assert_called_once()


def test_update_incident_status_sets_closed_at_on_close():
    incident = CorrelationIncidentModel(
        id=2,
        correlation_rule_id=1,
        correlation_rule_name="Rule A",
        status="triaged",
        severity="high",
        group_by="src_ip",
        group_value="1.2.3.4",
        dedup_key="cr1:1.2.3.4:20260501T1000",
        started_at=datetime(2026, 5, 1, 10, 0),
        last_seen_at=datetime(2026, 5, 1, 10, 5),
        closed_at=None,
        alert_count=3,
        unique_rules=["r1"],
        stage_hits={},
        context={},
        created_at=datetime(2026, 5, 1),
        updated_at=datetime(2026, 5, 1),
    )

    db = MagicMock()
    db.commit = MagicMock()
    request = MagicMock()
    admin = MagicMock()
    admin.id = 1
    admin.username = "admin"

    payload = CorrelationIncidentStatusIn(status="closed")

    with (
        patch("app.features.correlations.service.get_incident_by_id", return_value=incident),
        patch("app.features.correlations.service.write_audit_event"),
        patch("app.features.correlations.service.get_correlation_incident") as mock_detail,
    ):
        mock_detail.return_value = MagicMock(status="closed")
        update_incident_status(db, incident_id=2, payload=payload, request=request, admin=admin)

    assert incident.status == "closed"
    assert incident.closed_at is not None


def test_update_incident_status_invalid_raises():
    incident = CorrelationIncidentModel(
        id=3,
        status="open",
        correlation_rule_id=1,
        correlation_rule_name="x",
        severity="low",
        group_by="src_ip",
        group_value="x",
        dedup_key="cr1:x:20260501T1000",
        started_at=datetime(2026, 5, 1),
        last_seen_at=datetime(2026, 5, 1),
        alert_count=1,
        unique_rules=[],
        stage_hits={},
        context={},
        created_at=datetime(2026, 5, 1),
        updated_at=datetime(2026, 5, 1),
    )
    db = MagicMock()
    request = MagicMock()
    admin = MagicMock()
    admin.id = 1
    admin.username = "admin"

    payload = CorrelationIncidentStatusIn(status="invalid_status")
    with patch("app.features.correlations.service.get_incident_by_id", return_value=incident):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            update_incident_status(db, incident_id=3, payload=payload, request=request, admin=admin)
    assert exc_info.value.status_code == 422


def test_update_incident_status_not_found_raises():
    db = MagicMock()
    request = MagicMock()
    admin = MagicMock()
    admin.id = 1
    admin.username = "admin"
    payload = CorrelationIncidentStatusIn(status="closed")

    with patch("app.features.correlations.service.get_incident_by_id", return_value=None):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            update_incident_status(db, incident_id=999, payload=payload, request=request, admin=admin)
    assert exc_info.value.status_code == 404


# ---------------------------------------------------------------------------
# list_correlation_incidents test
# ---------------------------------------------------------------------------

def test_list_incidents_delegates_to_repository():
    db = MagicMock()
    incidents = [MagicMock(), MagicMock()]

    with patch("app.features.correlations.service._list_incidents", return_value=incidents) as mock_list:
        result = list_correlation_incidents(db, status="open", limit=50, offset=10)

    mock_list.assert_called_once_with(db, status="open", limit=50, offset=10)
    assert result is incidents


# ---------------------------------------------------------------------------
# Audit event tests
# ---------------------------------------------------------------------------

def test_run_correlations_writes_audit_when_admin_provided():
    db = MagicMock()
    db.add = MagicMock()
    db.flush = MagicMock()
    db.commit = MagicMock()
    db.execute = MagicMock(return_value=_FakeResult([]))

    request = MagicMock()
    admin = MagicMock()
    admin.id = 42
    admin.username = "ops_user"

    with (
        patch("app.features.correlations.service.list_enabled_rules", return_value=[]),
        patch("app.features.correlations.service.list_recent_alerts", return_value=[]),
        patch("app.features.correlations.service.build_incidents", return_value=[]),
        patch("app.features.correlations.service.write_audit_event") as mock_audit,
    ):
        run_correlations(db, limit=100, max_age_minutes=60, sample_limit=10, request=request, admin=admin)

    mock_audit.assert_called_once()
    call_kwargs = mock_audit.call_args[1]
    assert call_kwargs["action"] == "correlation.run"


def test_run_correlations_no_audit_without_admin():
    db = MagicMock()
    db.add = MagicMock()
    db.flush = MagicMock()
    db.commit = MagicMock()
    db.execute = MagicMock(return_value=_FakeResult([]))

    with (
        patch("app.features.correlations.service.list_enabled_rules", return_value=[]),
        patch("app.features.correlations.service.list_recent_alerts", return_value=[]),
        patch("app.features.correlations.service.build_incidents", return_value=[]),
        patch("app.features.correlations.service.write_audit_event") as mock_audit,
    ):
        run_correlations(db, limit=100, max_age_minutes=60, sample_limit=10)

    mock_audit.assert_not_called()


def test_update_incident_status_writes_audit():
    incident = CorrelationIncidentModel(
        id=10,
        correlation_rule_id=1,
        correlation_rule_name="Rule",
        status="open",
        severity="high",
        group_by="src_ip",
        group_value="x",
        dedup_key="cr1:x:20260501T1000",
        started_at=datetime(2026, 5, 1),
        last_seen_at=datetime(2026, 5, 1),
        alert_count=1,
        unique_rules=[],
        stage_hits={},
        context={},
        created_at=datetime(2026, 5, 1),
        updated_at=datetime(2026, 5, 1),
    )
    db = MagicMock()
    db.commit = MagicMock()
    request = MagicMock()
    admin = MagicMock()
    admin.id = 1
    admin.username = "admin"

    payload = CorrelationIncidentStatusIn(status="suppressed")
    with (
        patch("app.features.correlations.service.get_incident_by_id", return_value=incident),
        patch("app.features.correlations.service.write_audit_event") as mock_audit,
        patch("app.features.correlations.service.get_correlation_incident", return_value=MagicMock()),
    ):
        update_incident_status(db, incident_id=10, payload=payload, request=request, admin=admin)

    mock_audit.assert_called_once()
    call_kwargs = mock_audit.call_args[1]
    assert call_kwargs["action"] == "correlation_incident.status_change"
    assert call_kwargs["before"]["status"] == "open"
    assert call_kwargs["after"]["status"] == "suppressed"


# ---------------------------------------------------------------------------
# Model import smoke test
# ---------------------------------------------------------------------------

def test_new_models_importable():
    from app.features.correlations.models import (
        CorrelationEntityStateModel,
        CorrelationIncidentEvidenceModel,
        CorrelationIncidentModel,
        CorrelationRuleRunModel,
    )
    assert CorrelationIncidentModel.__tablename__ == "correlation_incidents"
    assert CorrelationIncidentEvidenceModel.__tablename__ == "correlation_incident_evidence"
    assert CorrelationRuleRunModel.__tablename__ == "correlation_rule_runs"
    assert CorrelationEntityStateModel.__tablename__ == "correlation_entity_states"


def test_new_schemas_importable():
    from app.features.correlations.schemas import (
        CorrelationEvidenceOut,
        CorrelationIncidentDetailOut,
        CorrelationIncidentListItemOut,
        CorrelationIncidentStatusIn,
        CorrelationRuleRunOut,
    )
    s = CorrelationIncidentStatusIn(status="triaged")
    assert s.status == "triaged"


def test_correlation_incident_out_backward_compatible():
    # The existing CorrelationRunOut.incidents items should still work
    inc = CorrelationIncidentOut(
        id="cr1:x:2026-05-01T10:00:00",
        correlation_rule_id=1,
        correlation_rule_name="Rule",
        severity="high",
        group_by="src_ip",
        group_value="1.2.3.4",
        started_at=datetime(2026, 5, 1, 10, 0),
        ended_at=datetime(2026, 5, 1, 10, 5),
        alert_count=3,
    )
    # New optional fields have safe defaults
    assert inc.db_id is None
    assert inc.status == "open"
