from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:test@127.0.0.1:5432/seagull_test")

from app.features.auth.session import PortalPrincipal, get_current_user
from app.features.ueba import api as ueba_api
from app.features.ueba.schemas import (
    UebaBaselineOut,
    UebaDetectorRunOut,
    UebaDetectorStateOut,
    UebaFindingDetailOut,
    UebaFindingEvidenceOut,
    UebaFindingListItemOut,
    UebaSummaryOut,
)
from app.main import app
from app.shared.schemas import CursorPage

_NOW = datetime(2026, 5, 18, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _clear_overrides():
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


def _baseline_out() -> UebaBaselineOut:
    return UebaBaselineOut(
        id=1,
        baseline_key="baseline:1",
        detector_id="ssh_login_hour_v1",
        detector_version=1,
        agent_id="agent-1",
        entity_type="user",
        entity_value="alice",
        metric_name="login_hour",
        bucket_key="weekday",
        status="mature",
        sample_count=20,
        warmup_started_at=_NOW,
        matured_at=_NOW,
        window_started_at=_NOW,
        window_ended_at=_NOW,
        last_observed_at=_NOW,
        expected_value=9.0,
        dispersion=1.5,
        lower_bound=7.0,
        upper_bound=11.0,
        confidence=80,
        state={"method": "ewma"},
        created_at=_NOW,
        updated_at=_NOW,
    )


def _finding_out() -> UebaFindingListItemOut:
    return UebaFindingListItemOut(
        id=7,
        finding_key="finding:7",
        dedup_key="dedup:7",
        detector_id="ssh_login_hour_v1",
        detector_version=1,
        baseline_id=1,
        agent_id="agent-1",
        entity_type="user",
        entity_value="alice",
        metric_name="login_hour",
        bucket_key="weekday",
        status="open",
        severity="high",
        confidence=88,
        risk_score=84,
        expected_value=9.0,
        observed_value=3.0,
        deviation_score=4.0,
        first_seen_at=_NOW,
        last_seen_at=_NOW,
        window_started_at=_NOW,
        window_ended_at=_NOW,
        cooldown_until=None,
        closed_at=None,
        occurrence_count=1,
        summary="User logged in outside normal hour range",
        reason_codes=["outside_login_hour_baseline"],
        explanation={"expected_range": [7, 11], "observed": 3},
        alert_id=None,
        mitre_tactic="initial_access",
        mitre_technique_id="T1078",
        mitre_technique="Valid Accounts",
        created_at=_NOW,
        updated_at=_NOW,
    )


def test_ueba_summary_requires_authentication() -> None:
    with TestClient(app) as client:
        response = client.get("/ueba/summary")
    assert response.status_code == 401


def test_ueba_summary_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="analyst", role="user")
    monkeypatch.setattr(
        ueba_api.service,
        "get_summary",
        lambda _db: UebaSummaryOut(
            enabled=True,
            total_baselines=10,
            warming_baselines=2,
            mature_baselines=8,
            stale_baselines=0,
            open_findings=3,
            high_or_critical_open_findings=1,
            linked_alerts=2,
            detectors_total=2,
            detectors_healthy=2,
            detectors_degraded=0,
            detectors_failing=0,
            latest_run_at=_NOW,
            latest_finding_at=_NOW,
        ),
    )
    with TestClient(app) as client:
        response = client.get("/ueba/summary")
    assert response.status_code == 200
    body = response.json()
    assert body["enabled"] is True
    assert body["mature_baselines"] == 8
    assert body["open_findings"] == 3


def test_ueba_findings_forward_filters_and_return_cursor_page(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    def _list_findings(_db, *, params):
        captured["params"] = params
        return CursorPage(items=[_finding_out()], next_cursor="next-1", has_more=True)

    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="analyst", role="user")
    monkeypatch.setattr(ueba_api.service, "list_findings", _list_findings)
    with TestClient(app) as client:
        response = client.get(
            "/ueba/findings",
            params={
                "page_size": 25,
                "detector_id": "ssh_login_hour_v1",
                "agent_id": "agent-1",
                "entity_type": "user",
                "entity_value": "alice",
                "metric_name": "login_hour",
                "status": "open",
                "severity": "high",
                "min_risk_score": 70,
            },
        )
    assert response.status_code == 200
    params = captured["params"]
    assert params.page_size == 25
    assert params.detector_id == "ssh_login_hour_v1"
    assert params.status == "open"
    assert params.min_risk_score == 70
    assert response.json()["next_cursor"] == "next-1"


def test_ueba_finding_detail_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    detail = UebaFindingDetailOut(
        **_finding_out().model_dump(),
        baseline=_baseline_out(),
        evidence=[
            UebaFindingEvidenceOut(
                id=1,
                finding_id=7,
                event_id=42,
                alert_id=None,
                evidence_type="event",
                evidence_role="trigger",
                observed_at=_NOW,
                entity_type="user",
                entity_value="alice",
                matched_field="ssh_username",
                matched_value="alice",
                summary="alice logged in at 03:00",
                raw_context={"event_type": "ssh_auth"},
                created_at=_NOW,
            )
        ],
    )
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="analyst", role="user")
    monkeypatch.setattr(ueba_api.service, "get_finding_detail", lambda _db, finding_id: detail)
    with TestClient(app) as client:
        response = client.get("/ueba/findings/7")
    assert response.status_code == 200
    body = response.json()
    assert body["baseline"]["baseline_key"] == "baseline:1"
    assert body["evidence"][0]["event_id"] == 42


def test_ueba_detectors_and_runs_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="analyst", role="user")
    monkeypatch.setattr(
        ueba_api.service,
        "list_detector_states",
        lambda _db: [
            UebaDetectorStateOut(
                detector_id="ssh_login_hour_v1",
                detector_version=1,
                enabled=True,
                status="healthy",
                consecutive_failures=0,
                baseline_count=10,
                mature_baseline_count=8,
                open_findings=1,
                last_run_at=_NOW,
                last_success_at=_NOW,
                last_error_at=None,
                last_window_started_at=_NOW,
                last_window_ended_at=_NOW,
                next_run_at=None,
                error_type=None,
                error_message=None,
                context={},
                updated_at=_NOW,
            )
        ],
    )
    monkeypatch.setattr(
        ueba_api.service,
        "list_detector_runs",
        lambda _db, *, params: CursorPage(
            items=[
                UebaDetectorRunOut(
                    id=1,
                    detector_id="ssh_login_hour_v1",
                    detector_version=1,
                    started_at=_NOW,
                    finished_at=_NOW,
                    status="completed",
                    window_started_at=_NOW,
                    window_ended_at=_NOW,
                    scanned_events=100,
                    evaluated_entities=8,
                    baselines_created=1,
                    baselines_updated=2,
                    findings_created=1,
                    findings_updated=0,
                    alerts_created=0,
                    suppressions_applied=0,
                    duration_ms=120,
                    context={},
                )
            ],
            next_cursor=None,
            has_more=False,
        ),
    )
    with TestClient(app) as client:
        detectors = client.get("/ueba/detectors")
        runs = client.get("/ueba/runs", params={"detector_id": "ssh_login_hour_v1", "status": "completed"})
    assert detectors.status_code == 200
    assert detectors.json()[0]["status"] == "healthy"
    assert runs.status_code == 200
    assert runs.json()["items"][0]["scanned_events"] == 100


def test_ueba_invalid_query_values_return_422() -> None:
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="analyst", role="user")
    with TestClient(app) as client:
        response = client.get("/ueba/findings", params={"status": "triaged"})
    assert response.status_code == 422
