from __future__ import annotations

import importlib
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:test@127.0.0.1:5432/seagull_test")

from app.core.db import Base
from app.core.db.model_registry import load_all_models
from app.features.ueba import lifecycle, repository, service
from app.features.ueba.models import (
    UebaBaselineModel,
    UebaDetectorRunModel,
    UebaDetectorStateModel,
    UebaFindingEvidenceModel,
    UebaFindingModel,
)
from app.features.ueba.schemas import UebaBaselinesQuery, UebaFindingsQuery, UebaRunsQuery


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(_type, _compiler, **_kw):
    return "JSON"


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Base.metadata.create_all(
        engine,
        tables=[
            UebaBaselineModel.__table__,
            UebaFindingModel.__table__,
            UebaFindingEvidenceModel.__table__,
            UebaDetectorStateModel.__table__,
            UebaDetectorRunModel.__table__,
        ],
    )
    Session = sessionmaker(bind=engine, future=True)
    db = Session()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(
            engine,
            tables=[
                UebaDetectorRunModel.__table__,
                UebaDetectorStateModel.__table__,
                UebaFindingEvidenceModel.__table__,
                UebaFindingModel.__table__,
                UebaBaselineModel.__table__,
            ],
        )
        engine.dispose()


def _ts(minutes: int = 0) -> datetime:
    return datetime(2026, 5, 18, 12, 0, tzinfo=timezone.utc) + timedelta(minutes=minutes)


def _baseline_payload(*, suffix: str = "1", status: str = "warmup", last_seen_minute: int = 0) -> dict:
    return {
        "baseline_key": f"baseline:{suffix}",
        "detector_id": "ssh_login_hour_v1",
        "detector_version": 1,
        "agent_id": "agent-1",
        "entity_type": "user",
        "entity_value": "alice",
        "metric_name": "login_hour",
        "bucket_key": "weekday",
        "status": status,
        "sample_count": 12,
        "warmup_started_at": _ts(-120),
        "matured_at": (_ts(-30) if status == "mature" else None),
        "window_started_at": _ts(-60),
        "window_ended_at": _ts(-1),
        "last_observed_at": _ts(last_seen_minute),
        "expected_value": 9.0,
        "dispersion": 1.5,
        "lower_bound": 7.0,
        "upper_bound": 11.0,
        "confidence": 80,
        "state": {"method": "ewma"},
    }


def _finding_payload(
    *,
    suffix: str,
    baseline_id: int | None,
    status: str = "open",
    severity: str = "high",
    last_seen_minute: int = 0,
    risk_score: int = 80,
) -> dict:
    return {
        "finding_key": f"finding:{suffix}",
        "dedup_key": f"dedup:{suffix}",
        "detector_id": "ssh_login_hour_v1",
        "detector_version": 1,
        "baseline_id": baseline_id,
        "agent_id": "agent-1",
        "entity_type": "user",
        "entity_value": "alice",
        "metric_name": "login_hour",
        "bucket_key": "weekday",
        "status": status,
        "severity": severity,
        "confidence": 88,
        "risk_score": risk_score,
        "expected_value": 9.0,
        "observed_value": 3.0,
        "deviation_score": 4.0,
        "first_seen_at": _ts(last_seen_minute - 5),
        "last_seen_at": _ts(last_seen_minute),
        "window_started_at": _ts(last_seen_minute - 10),
        "window_ended_at": _ts(last_seen_minute),
        "cooldown_until": _ts(last_seen_minute + 15),
        "closed_at": (_ts(last_seen_minute + 1) if status == "closed" else None),
        "occurrence_count": 1,
        "summary": "User logged in outside normal hour range",
        "reason_codes": ["outside_login_hour_baseline"],
        "explanation": {"expected_range": [7, 11], "observed": 3},
        "mitre_tactic": "initial_access",
        "mitre_technique_id": "T1078",
        "mitre_technique": "Valid Accounts",
    }


def test_ueba_models_are_registered_and_migration_exists() -> None:
    load_all_models()
    for table_name in (
        "ueba_baselines",
        "ueba_findings",
        "ueba_finding_evidence",
        "ueba_detector_states",
        "ueba_detector_runs",
    ):
        assert table_name in Base.metadata.tables

    migration = Path("alembic/versions/20260518_0023_ueba_foundation.py")
    assert migration.exists()
    assert 'revision = "20260518_0023"' in migration.read_text()


def test_ueba_setting_loads_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SEAGULL_UEBA_ENABLED", "false")
    settings_module = importlib.import_module("app.core.config.settings")
    reloaded = importlib.reload(settings_module)
    try:
        assert reloaded.settings.SEAGULL_UEBA_ENABLED is False
        assert reloaded.settings.runtime_config_for_admin()["ueba"]["enabled"] is False
        reloaded.settings.validate_for_service("backend-api")
    finally:
        monkeypatch.setenv("SEAGULL_UEBA_ENABLED", "true")
        importlib.reload(settings_module)


def test_baseline_create_update_and_lookup(db_session) -> None:
    baseline = repository.create_baseline(db_session, **_baseline_payload())
    repository.commit(db_session)
    repository.refresh(db_session, baseline)

    loaded = repository.get_baseline_by_key(db_session, "baseline:1")
    assert loaded is not None
    assert loaded.status == "warmup"
    assert loaded.sample_count == 12

    loaded.status = "mature"
    loaded.matured_at = _ts(1)
    repository.save_baseline(db_session, loaded)
    repository.commit(db_session)

    updated = repository.get_baseline(db_session, int(loaded.id))
    assert updated is not None
    assert updated.status == "mature"
    assert updated.matured_at == _ts(1).replace(tzinfo=None)


def test_baseline_upsert_reuses_stable_identity(db_session) -> None:
    first, created = lifecycle.upsert_baseline(
        db_session,
        **_baseline_payload(status="warmup"),
        updated_at=_ts(),
    )
    repository.commit(db_session)
    repository.refresh(db_session, first)

    second, second_created = lifecycle.upsert_baseline(
        db_session,
        **_baseline_payload(status="mature", last_seen_minute=5),
        updated_at=_ts(5),
    )
    repository.commit(db_session)
    repository.refresh(db_session, second)

    assert created is True
    assert second_created is False
    assert second.id == first.id
    assert second.status == "mature"
    assert second.last_observed_at == _ts(5).replace(tzinfo=None)


def test_finding_persistence_detail_and_dedup_lookup(db_session) -> None:
    baseline = repository.create_baseline(db_session, **_baseline_payload(status="mature"))
    repository.commit(db_session)
    repository.refresh(db_session, baseline)

    finding = repository.create_finding(db_session, **_finding_payload(suffix="1", baseline_id=baseline.id))
    repository.commit(db_session)
    repository.refresh(db_session, finding)
    repository.create_finding_evidence(
        db_session,
        finding_id=finding.id,
        event_id=42,
        evidence_type="event",
        evidence_role="trigger",
        observed_at=_ts(),
        entity_type="user",
        entity_value="alice",
        matched_field="ssh_username",
        matched_value="alice",
        summary="alice logged in at 03:00",
        raw_context={"event_type": "ssh_auth"},
    )
    repository.commit(db_session)

    active = repository.get_open_finding_by_dedup_key(db_session, "dedup:1")
    assert active is not None
    assert active.id == finding.id

    detail = service.get_finding_detail(db_session, finding.id)
    assert detail.baseline is not None
    assert detail.baseline.baseline_key == "baseline:1"
    assert detail.evidence[0].event_id == 42
    assert detail.reason_codes == ["outside_login_hour_baseline"]


def test_finding_observations_roll_up_dedup_cooldown_and_evidence(db_session) -> None:
    baseline = repository.create_baseline(db_session, **_baseline_payload(status="mature"))
    repository.commit(db_session)
    repository.refresh(db_session, baseline)

    first_payload = _finding_payload(suffix="1", baseline_id=baseline.id, risk_score=72)
    first_payload.update({"cooldown_until": _ts(15), "updated_at": _ts()})
    first = lifecycle.record_finding_observation(db_session, **first_payload)
    repository.flush(db_session)
    inserted = lifecycle.append_finding_evidence(
        db_session,
        finding_id=first.finding.id,
        specs=[
            {
                "event_id": 42,
                "evidence_type": "event",
                "evidence_role": "trigger",
                "observed_at": _ts(),
                "entity_type": "user",
                "entity_value": "alice",
                "matched_field": "ssh_username",
                "matched_value": "alice",
                "summary": "alice logged in at 03:00",
                "raw_context": {"event_type": "ssh_auth"},
            }
        ],
    )
    duplicate_inserted = lifecycle.append_finding_evidence(
        db_session,
        finding_id=first.finding.id,
        specs=[
            {
                "event_id": 42,
                "evidence_type": "event",
                "evidence_role": "trigger",
                "observed_at": _ts(),
                "entity_type": "user",
                "entity_value": "alice",
                "matched_field": "ssh_username",
                "matched_value": "alice",
                "summary": "alice logged in at 03:00",
                "raw_context": {"event_type": "ssh_auth"},
            }
        ],
    )
    second_payload = _finding_payload(suffix="2", baseline_id=baseline.id, last_seen_minute=1, risk_score=91)
    second_payload.update(
        {
            "dedup_key": "dedup:1",
            "severity": "critical",
            "confidence": 95,
            "cooldown_until": _ts(20),
            "reason_codes": ["outside_login_hour_baseline", "rare_user_hour"],
            "explanation": {"z_score": 4.2},
            "updated_at": _ts(1),
        }
    )
    second = lifecycle.record_finding_observation(db_session, **second_payload)
    repository.commit(db_session)
    repository.refresh(db_session, second.finding)

    assert first.created is True
    assert second.created is False
    assert second.in_cooldown is True
    assert second.finding.id == first.finding.id
    assert second.finding.finding_key == "finding:1"
    assert second.finding.occurrence_count == 2
    assert second.finding.severity == "critical"
    assert second.finding.risk_score == 91
    assert second.finding.confidence == 95
    assert second.finding.reason_codes == ["outside_login_hour_baseline", "rare_user_hour"]
    assert second.finding.explanation == {"expected_range": [7, 11], "observed": 3, "z_score": 4.2}
    assert second.finding.cooldown_until == _ts(20).replace(tzinfo=None)
    assert inserted == 1
    assert duplicate_inserted == 0
    assert len(repository.list_finding_evidence(db_session, second.finding.id)) == 1


def test_finding_filters_and_cursor_pagination(db_session) -> None:
    baseline = repository.create_baseline(db_session, **_baseline_payload(status="mature"))
    repository.commit(db_session)
    repository.refresh(db_session, baseline)
    rows = [
        repository.create_finding(
            db_session,
            **_finding_payload(suffix="1", baseline_id=baseline.id, last_seen_minute=3, risk_score=90),
        ),
        repository.create_finding(
            db_session,
            **_finding_payload(suffix="2", baseline_id=baseline.id, last_seen_minute=2, risk_score=75),
        ),
        repository.create_finding(
            db_session,
            **_finding_payload(
                suffix="3",
                baseline_id=baseline.id,
                status="closed",
                severity="medium",
                last_seen_minute=1,
                risk_score=40,
            ),
        ),
    ]
    repository.commit(db_session)
    for row in rows:
        repository.refresh(db_session, row)

    page_1 = service.list_findings(
        db_session,
        params=UebaFindingsQuery(page_size=1, status="open", min_risk_score=70),
    )
    assert len(page_1.items) == 1
    assert page_1.items[0].finding_key == "finding:1"
    assert page_1.has_more is True
    assert page_1.next_cursor is not None

    page_2 = service.list_findings(
        db_session,
        params=UebaFindingsQuery(
            page_size=1,
            cursor=page_1.next_cursor,
            status="open",
            min_risk_score=70,
        ),
    )
    assert len(page_2.items) == 1
    assert page_2.items[0].finding_key == "finding:2"
    assert page_2.has_more is False


def test_baseline_visibility_and_summary_empty_state(db_session) -> None:
    summary = service.get_summary(db_session)
    assert summary.total_baselines == 0
    assert summary.open_findings == 0
    assert summary.detectors_total == 0

    repository.create_baseline(db_session, **_baseline_payload(status="warmup", suffix="1", last_seen_minute=1))
    repository.create_baseline(db_session, **_baseline_payload(status="mature", suffix="2", last_seen_minute=2))
    repository.commit(db_session)

    page = service.list_baselines(
        db_session,
        params=UebaBaselinesQuery(page_size=10, status="mature"),
    )
    assert len(page.items) == 1
    assert page.items[0].baseline_key == "baseline:2"

    populated = service.get_summary(db_session)
    assert populated.total_baselines == 2
    assert populated.warming_baselines == 1
    assert populated.mature_baselines == 1


def test_detector_state_and_run_history_persistence(db_session) -> None:
    state = repository.create_detector_state(
        db_session,
        detector_id="ssh_login_hour_v1",
        detector_version=1,
        enabled=True,
        status="healthy",
        consecutive_failures=0,
        baseline_count=2,
        mature_baseline_count=1,
        open_findings=1,
        last_run_at=_ts(),
        last_success_at=_ts(),
        context={"window_minutes": 60},
    )
    run = repository.create_detector_run(
        db_session,
        detector_id="ssh_login_hour_v1",
        detector_version=1,
        started_at=_ts(),
        finished_at=_ts(1),
        status="completed",
        window_started_at=_ts(-60),
        window_ended_at=_ts(),
        scanned_events=100,
        evaluated_entities=8,
        baselines_created=1,
        baselines_updated=1,
        findings_created=1,
        findings_updated=0,
        alerts_created=0,
        suppressions_applied=0,
        duration_ms=125,
        context={"source": "postgres"},
    )
    repository.commit(db_session)
    repository.refresh(db_session, state)
    repository.refresh(db_session, run)

    states = service.list_detector_states(db_session)
    assert states[0].detector_id == "ssh_login_hour_v1"
    assert states[0].baseline_count == 2

    runs = service.list_detector_runs(
        db_session,
        params=UebaRunsQuery(page_size=10, detector_id="ssh_login_hour_v1", status="completed"),
    )
    assert len(runs.items) == 1
    assert runs.items[0].scanned_events == 100
    assert runs.items[0].duration_ms == 125


def test_detector_run_lifecycle_updates_health_and_failure_state(db_session) -> None:
    run = lifecycle.start_detector_run(
        db_session,
        detector_id="ssh_login_hour_v1",
        detector_version=1,
        started_at=_ts(),
        window_started_at=_ts(-60),
        window_ended_at=_ts(),
        context={"source": "postgres"},
    )
    repository.flush(db_session)
    lifecycle.complete_detector_run(
        db_session,
        run=run,
        finished_at=_ts(1),
        scanned_events=100,
        evaluated_entities=8,
        baselines_created=1,
        baselines_updated=2,
        findings_created=1,
        findings_updated=0,
        alerts_created=1,
        suppressions_applied=0,
        baseline_count=5,
        mature_baseline_count=4,
        open_findings=1,
        context_patch={"completed": True},
    )
    repository.commit(db_session)
    repository.refresh(db_session, run)

    state = repository.get_detector_state(db_session, "ssh_login_hour_v1")
    assert run.status == "completed"
    assert run.duration_ms == 60000
    assert run.context == {"source": "postgres", "completed": True}
    assert state is not None
    assert state.status == "healthy"
    assert state.consecutive_failures == 0
    assert state.baseline_count == 5

    failed_run = lifecycle.start_detector_run(
        db_session,
        detector_id="ssh_login_hour_v1",
        detector_version=1,
        started_at=_ts(2),
        window_started_at=_ts(1),
        window_ended_at=_ts(2),
    )
    repository.flush(db_session)
    lifecycle.fail_detector_run(
        db_session,
        run=failed_run,
        failed_at=_ts(3),
        error_type="RuntimeError",
        error_message="source unavailable",
        failing_after=1,
    )
    repository.commit(db_session)
    repository.refresh(db_session, failed_run)

    failed_state = repository.get_detector_state(db_session, "ssh_login_hour_v1")
    assert failed_run.status == "failed"
    assert failed_run.duration_ms == 60000
    assert failed_run.error_type == "RuntimeError"
    assert failed_state is not None
    assert failed_state.status == "failing"
    assert failed_state.consecutive_failures == 1
