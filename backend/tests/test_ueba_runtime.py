from __future__ import annotations

import os
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:test@127.0.0.1:5432/seagull_test")

from app.core.db import Base
from app.features.alerts.models import AlertEvidenceModel, AlertModel
from app.features.events.models import NetEventModel
from app.features.ueba import repository
from app.features.ueba.domain.registry import DetectorExecutionResult, SshSourceDiversityDetector
from app.features.ueba.domain.statistics import (
    RunningStats,
    hour_rarity_bits,
    positive_z_score,
    summarize_hour_histogram,
)
from app.features.ueba.models import (
    UebaBaselineModel,
    UebaDetectorRunModel,
    UebaDetectorStateModel,
    UebaFeedbackModel,
    UebaFindingEvidenceModel,
    UebaFindingModel,
    UebaMlModelModel,
    UebaPeerGroupModel,
    UebaSuppressionModel,
)
from app.features.ueba.worker_runtime import UebaWorkerConfig, run_ueba_cycle


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(_type, _compiler, **_kw):
    return "JSON"


@pytest.fixture()
def db_session(monkeypatch: pytest.MonkeyPatch):
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    tables = [
        NetEventModel.__table__,
        AlertModel.__table__,
        AlertEvidenceModel.__table__,
        UebaBaselineModel.__table__,
        UebaFindingModel.__table__,
        UebaFindingEvidenceModel.__table__,
        UebaFeedbackModel.__table__,
        UebaSuppressionModel.__table__,
        UebaMlModelModel.__table__,
        UebaPeerGroupModel.__table__,
        UebaDetectorStateModel.__table__,
        UebaDetectorRunModel.__table__,
    ]
    Base.metadata.create_all(engine, tables=tables)
    Session = sessionmaker(bind=engine, future=True)

    import app.features.ueba.worker_runtime as worker_runtime

    monkeypatch.setattr(worker_runtime, "SessionLocal", Session)
    db = Session()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(engine, tables=list(reversed(tables)))
        engine.dispose()


def _ts(*, hour: int = 12, minute: int = 0) -> datetime:
    return datetime(2026, 5, 18, hour, minute, tzinfo=timezone.utc)


def _cfg(**overrides) -> UebaWorkerConfig:
    base = UebaWorkerConfig(
        interval_seconds=60.0,
        log_every_seconds=0.0,
        failing_after=1,
        cooldown_minutes=60,
        max_findings_per_detector_cycle=20,
        active_entity_hours=24,
        login_hour_lookback_hours=72,
        login_hour_min_samples=4,
        login_hour_max_events_per_cycle=100,
        login_hour_min_rarity_bits=3.0,
        login_hour_min_z_score=2.5,
        source_diversity_window_minutes=15,
        source_diversity_min_samples=4,
        source_diversity_max_entities_per_cycle=100,
        source_diversity_max_windows_per_cycle=4,
        source_diversity_min_z_score=3.0,
        outbound_bytes_window_minutes=15,
        outbound_bytes_min_samples=10,
        outbound_bytes_max_entities_per_cycle=100,
        outbound_bytes_max_windows_per_cycle=4,
        outbound_bytes_min_z_score=3.5,
        lateral_spread_window_minutes=15,
        lateral_spread_min_samples=8,
        lateral_spread_max_entities_per_cycle=100,
        lateral_spread_max_windows_per_cycle=4,
        lateral_spread_min_z_score=3.0,
        proc_exec_rate_window_minutes=5,
        proc_exec_rate_min_samples=12,
        proc_exec_rate_max_entities_per_cycle=100,
        proc_exec_rate_max_windows_per_cycle=6,
        proc_exec_rate_min_z_score=4.0,
        proc_name_lookback_hours=72,
        proc_name_max_events_per_cycle=100,
        proc_name_min_rarity_bits=4.0,
        proc_name_min_samples_for_maturity=5,
        proc_name_rarity_lookback_hours=168,
        fim_spike_window_minutes=5,
        fim_spike_min_samples=10,
        fim_spike_max_entities_per_cycle=100,
        fim_spike_max_windows_per_cycle=6,
        fim_spike_min_z_score=4.0,
        sudo_hour_lookback_hours=72,
        sudo_hour_min_samples=15,
        sudo_hour_max_events_per_cycle=100,
        sudo_hour_min_rarity_bits=3.0,
        sudo_hour_min_z_score=2.5,
        if_training_min_samples=500,
        if_retraining_interval_seconds=21_600,
        if_model_stale_seconds=86_400,
        if_model_retention_days=30,
        if_model_cache_ttl_seconds=300,
        if_weight=0.6,
        rarity_weight=0.4,
        if_n_estimators=200,
        if_random_state=42,
        if_feature_schema_version=1,
        peer_clustering_interval_seconds=21_600,
        peer_group_retention_days=90,
        peer_min_silhouette_score=0.25,
        peer_distance_percentile=95.0,
        peer_current_window_minutes=60,
        peer_feature_schema_version=1,
        peer_min_agents=4,
        peer_min_mature_days=3,
        peer_max_events_per_clustering=50_000,
    )
    return replace(base, **overrides)


def _ssh_event(
    db,
    *,
    timestamp: datetime,
    username: str = "alice",
    src_ip: str = "203.0.113.10",
    agent_id: str = "agent-1",
) -> NetEventModel:
    row = NetEventModel(
        agent_id=agent_id,
        event_type="ssh_auth",
        schema_version=1,
        timestamp=timestamp,
        src_ip=src_ip,
        ssh_action="accepted",
        ssh_username=username,
        extra={},
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def test_statistics_are_finite_with_zero_variance_and_hour_histograms() -> None:
    stats = RunningStats.empty()
    for _ in range(4):
        stats = stats.update(1)
    assert stats.mean == 1.0
    assert stats.stddev == 0.0
    assert positive_z_score(observed_value=4, expected_value=stats.mean, dispersion=stats.stddev) == 3.0
    assert positive_z_score(observed_value=float("inf"), expected_value=stats.mean, dispersion=0.0) == 0.0

    snapshot = summarize_hour_histogram([0] * 9 + [4] + [0] * 14)
    assert snapshot.mode_hour == 9
    assert snapshot.sample_count == 4
    assert snapshot.dispersion == 0.0
    assert hour_rarity_bits(counts=snapshot.counts, hour=3) > 4.0


def test_login_hour_detector_warms_up_then_creates_explainable_alert_and_dedups(db_session) -> None:
    cfg = _cfg(login_hour_min_z_score=2.0)
    for minute in range(4):
        _ssh_event(db_session, timestamp=_ts(hour=9, minute=minute))

    first = run_ueba_cycle(cfg, now=_ts(hour=10))
    assert first.failed == 0
    baseline = db_session.execute(select(UebaBaselineModel)).scalars().one()
    assert baseline.status == "mature"
    assert baseline.sample_count == 4
    assert baseline.expected_value == 9.0
    assert db_session.execute(select(UebaFindingModel)).scalars().all() == []

    _ssh_event(db_session, timestamp=_ts(hour=3, minute=0))
    second = run_ueba_cycle(cfg, now=_ts(hour=10, minute=1))
    finding = db_session.execute(select(UebaFindingModel)).scalars().one()
    alert = db_session.execute(select(AlertModel)).scalars().one()
    evidence = db_session.execute(select(UebaFindingEvidenceModel)).scalars().all()
    alert_evidence = db_session.execute(select(AlertEvidenceModel)).scalars().all()

    assert second.alerts_created == 1
    assert finding.reason_codes == ["rare_login_hour", "login_hour_far_from_baseline"]
    assert finding.expected_value == 9.0
    assert finding.observed_value == 3.0
    assert finding.deviation_score is not None and finding.deviation_score >= 6.0
    assert finding.explanation["sample_count"] == 4
    assert finding.alert_id == alert.id
    assert alert.detector_type == "ueba"
    assert alert.rule_id == "ssh_login_hour_v1"
    assert alert.mitre_technique_id == "T1078"
    assert len(evidence) == 1
    assert len(alert_evidence) == 1

    _ssh_event(db_session, timestamp=_ts(hour=3, minute=1), src_ip="203.0.113.11")
    third = run_ueba_cycle(cfg, now=_ts(hour=10, minute=2))
    db_session.expire_all()
    finding = db_session.execute(select(UebaFindingModel)).scalars().one()
    alerts = db_session.execute(select(AlertModel)).scalars().all()
    assert third.alerts_created == 0
    assert finding.occurrence_count == 2
    assert len(alerts) == 1


def test_source_diversity_detector_updates_window_baseline_and_finds_outlier(db_session) -> None:
    detector = SshSourceDiversityDetector()
    cfg = _cfg()
    for idx, minute in enumerate((0, 15, 30, 45)):
        _ssh_event(db_session, timestamp=_ts(hour=11, minute=minute), src_ip=f"203.0.113.{10 + idx}")
        result = run_ueba_cycle(
            cfg,
            now=_ts(hour=11, minute=minute) + timedelta(minutes=15),
            detector_set=[detector],
        )
        assert result.failed == 0

    baseline = repository.list_detector_baselines(
        db_session,
        detector_id="ssh_source_diversity_v1",
        limit=10,
    )[0]
    assert baseline.status == "mature"
    assert baseline.expected_value == 1.0
    assert baseline.dispersion == 0.0

    for idx in range(4):
        _ssh_event(
            db_session,
            timestamp=_ts(hour=12, minute=idx),
            src_ip=f"198.51.100.{20 + idx}",
        )
    outlier = run_ueba_cycle(cfg, now=_ts(hour=12, minute=15), detector_set=[detector])
    finding = db_session.execute(
        select(UebaFindingModel).where(UebaFindingModel.detector_id == "ssh_source_diversity_v1")
    ).scalars().one()
    assert outlier.alerts_created == 1
    assert finding.expected_value == 1.0
    assert finding.observed_value == 4.0
    assert finding.deviation_score == 3.0
    assert finding.explanation["effective_dispersion"] == 1.0


def test_detector_failures_are_isolated_and_persist_run_status(db_session) -> None:
    class GoodDetector:
        detector_id = "good_v1"
        detector_version = 1

        def window_bounds(self, _db, *, cfg, now):
            return now - timedelta(minutes=1), now

        def run(self, _db, *, cfg, now):
            return DetectorExecutionResult(detector_id=self.detector_id, detector_version=1)

    class BadDetector:
        detector_id = "bad_v1"
        detector_version = 1

        def window_bounds(self, _db, *, cfg, now):
            return now - timedelta(minutes=1), now

        def run(self, _db, *, cfg, now):
            raise RuntimeError("detector exploded")

    result = run_ueba_cycle(_cfg(), now=_ts(), detector_set=[GoodDetector(), BadDetector()])
    runs = db_session.execute(select(UebaDetectorRunModel).order_by(UebaDetectorRunModel.detector_id)).scalars().all()
    states = db_session.execute(select(UebaDetectorStateModel).order_by(UebaDetectorStateModel.detector_id)).scalars().all()

    assert result.completed == 1
    assert result.failed == 1
    assert [row.status for row in runs] == ["failed", "completed"]
    assert [row.status for row in states] == ["failing", "healthy"]
    assert states[0].error_type == "RuntimeError"
