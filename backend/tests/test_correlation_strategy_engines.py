from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from unittest.mock import patch

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:seagull@127.0.0.1:5432/seagull")

from app.features.alerts.models import AlertModel
from app.features.attack_chain.models import AttackChainCaseModel, AttackChainStepModel
from app.features.correlations.engine import build_incidents
from app.features.correlations.engines import CorrelationDataset
from app.features.correlations.models import CorrelationEntityStateModel, CorrelationIncidentEvidenceModel, CorrelationIncidentModel
from app.features.correlations.schemas import CorrelationEvidenceMatch
from app.features.correlations.service import _upsert_evidence, _upsert_incident
from app.features.exposure.models import ExposureFindingModel


@dataclass
class _Rule:
    id: int
    name: str
    strategy: str
    enabled: bool = True
    severity: str = "high"
    group_by: str = "src_ip"
    window_seconds: int = 600
    min_alerts: int = 1
    include_patterns: list[str] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=list)
    stages: list[dict] = field(default_factory=list)
    entity: dict = field(default_factory=dict)
    strategy_config: dict = field(default_factory=dict)
    risk_config: dict = field(default_factory=dict)
    evidence_config: dict = field(default_factory=dict)
    lifecycle_config: dict = field(default_factory=dict)


class _FakeDB:
    def __init__(self):
        self._added = []

    def add(self, obj):
        self._added.append(obj)
        if getattr(obj, "id", None) is None:
            obj.id = len(self._added)

    def flush(self):
        for obj in self._added:
            if getattr(obj, "id", None) is None:
                obj.id = len(self._added)


def _alert(
    *,
    alert_id: int,
    created_at: datetime,
    rule_id: str,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    dst_port: int | None = None,
    severity: str = "high",
    confidence: int = 80,
    mitre_tactic: str | None = None,
    details: dict | None = None,
) -> AlertModel:
    return AlertModel(
        id=alert_id,
        created_at=created_at,
        rule_id=rule_id,
        severity=severity,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        mitre_tactic=mitre_tactic,
        confidence=confidence,
        description=f"alert:{rule_id}",
        details=details or {},
    )


def test_threshold_strategy_builds_incident() -> None:
    t0 = datetime(2026, 5, 3, 10, 0, 0)
    alerts = [
        _alert(alert_id=1, created_at=t0, rule_id="ssh_failed_password_burst_target_v1", src_ip="1.2.3.4"),
        _alert(alert_id=2, created_at=t0 + timedelta(seconds=20), rule_id="ssh_failed_password_burst_target_v1", src_ip="1.2.3.4"),
        _alert(alert_id=3, created_at=t0 + timedelta(seconds=40), rule_id="ssh_invalid_user_burst_v1", src_ip="1.2.3.4"),
    ]
    rule = _Rule(
        id=1,
        name="Threshold",
        strategy="threshold",
        group_by="src_ip",
        window_seconds=120,
        min_alerts=3,
        include_patterns=["ssh_*"],
        entity={"type": "src_ip", "field": "src_ip"},
    )

    incidents = build_incidents([rule], alerts, sample_limit=5)

    assert len(incidents) == 1
    assert incidents[0].group_value == "1.2.3.4"
    assert incidents[0].alert_count == 3


def test_cardinality_strategy_detects_fanout() -> None:
    t0 = datetime(2026, 5, 3, 11, 0, 0)
    alerts = [
        _alert(alert_id=10, created_at=t0, rule_id="scan_probe_a_v1", src_ip="5.5.5.5", dst_ip="10.0.0.1"),
        _alert(alert_id=11, created_at=t0 + timedelta(seconds=30), rule_id="scan_probe_a_v1", src_ip="5.5.5.5", dst_ip="10.0.0.2"),
        _alert(alert_id=12, created_at=t0 + timedelta(seconds=50), rule_id="scan_probe_b_v1", src_ip="5.5.5.5", dst_ip="10.0.0.3"),
    ]
    rule = _Rule(
        id=2,
        name="Cardinality",
        strategy="cardinality",
        group_by="src_ip",
        window_seconds=180,
        min_alerts=3,
        include_patterns=["scan_probe_*"],
        entity={"type": "src_ip", "field": "src_ip"},
        strategy_config={"source": "alerts", "field": "dst_ip", "threshold": 3},
    )

    incidents = build_incidents([rule], alerts, sample_limit=5)

    assert len(incidents) == 1
    assert incidents[0].context["distinct_count"] == 3
    assert incidents[0].group_value == "5.5.5.5"


def test_sequence_strategy_matches_ordered_stages() -> None:
    t0 = datetime(2026, 5, 3, 12, 0, 0)
    alerts = [
        _alert(alert_id=20, created_at=t0, rule_id="admin_ports_vertical_recon_v1", src_ip="6.6.6.6"),
        _alert(alert_id=21, created_at=t0 + timedelta(minutes=2), rule_id="ssh_failed_password_burst_target_v1", src_ip="6.6.6.6"),
    ]
    rule = _Rule(
        id=3,
        name="Sequence",
        strategy="sequence",
        group_by="src_ip",
        window_seconds=900,
        min_alerts=2,
        include_patterns=["admin_ports_vertical_recon_v1", "ssh_failed_password_burst_target_v1"],
        entity={"type": "src_ip", "field": "src_ip"},
        stages=[
            {"id": "recon", "name": "Recon", "include_patterns": ["admin_ports_vertical_recon_v1"], "min_count": 1},
            {
                "id": "bruteforce",
                "name": "Brute Force",
                "include_patterns": ["ssh_failed_password_burst_target_v1"],
                "after": "recon",
                "within_seconds": 600,
                "min_count": 1,
            },
        ],
    )

    incidents = build_incidents([rule], alerts, sample_limit=5)

    assert len(incidents) == 1
    assert incidents[0].stage_hits["Recon"] == 1
    assert incidents[0].stage_hits["Brute Force"] == 1


def test_temporal_join_strategy_matches_exposure_and_alert() -> None:
    t0 = datetime(2026, 5, 3, 13, 0, 0)
    alerts = [
        _alert(
            alert_id=30,
            created_at=t0 + timedelta(minutes=30),
            rule_id="proc_remote_fetch_exec_v1",
            details={"group_key": {"agent_id": "agent-1"}},
        ),
    ]
    exposure = ExposureFindingModel(
        id=1,
        agent_id="agent-1",
        asset_key="agent:agent-1",
        finding_key="exp-1",
        finding_type="attack_path",
        severity="high",
        score_delta=25,
        confidence=80,
        title="Exploitable exposure",
        summary="critical CVE context",
        status="open",
        reason_codes=["critical_cve"],
        last_seen_at=t0,
        first_seen_at=t0,
    )
    dataset = CorrelationDataset(alerts=alerts, exposure_findings=[exposure])
    rule = _Rule(
        id=4,
        name="Temporal Join",
        strategy="temporal_join",
        group_by="agent_id",
        window_seconds=24 * 3600,
        min_alerts=1,
        entity={"type": "agent_id", "field": "agent_id"},
        evidence_config={
            "families": [
                {
                    "id": "exposure",
                    "name": "Exposure",
                    "source": "exposure_findings",
                    "field_filters": [
                        {"field": "agent_id", "op": "exists"},
                        {"field": "reason_codes", "op": "contains_any", "value": ["critical_cve"]},
                    ],
                },
                {
                    "id": "activity",
                    "name": "Exploit Activity",
                    "source": "alerts",
                    "include_patterns": ["proc_remote_fetch_exec_v1"],
                    "field_filters": [{"field": "agent_id", "op": "exists"}],
                    "after": "exposure",
                    "within_seconds": 24 * 3600,
                },
            ]
        },
    )

    incidents = build_incidents([rule], alerts, sample_limit=5, dataset=dataset)

    assert len(incidents) == 1
    assert incidents[0].group_value == "agent-1"
    assert {item.evidence_type for item in incidents[0].evidence_items} == {"alert", "exposure_finding"}


def test_risk_aggregation_strategy_caps_duplicate_rule_contribution() -> None:
    t0 = datetime(2026, 5, 3, 14, 0, 0)
    alerts = [
        _alert(alert_id=40, created_at=t0, rule_id="beacon_suspect_heuristic_v1", src_ip="8.8.8.8", confidence=95, severity="high", mitre_tactic="command_and_control"),
        _alert(alert_id=41, created_at=t0 + timedelta(seconds=30), rule_id="beacon_suspect_heuristic_v1", src_ip="8.8.8.8", confidence=95, severity="high", mitre_tactic="command_and_control"),
        _alert(alert_id=42, created_at=t0 + timedelta(seconds=40), rule_id="proc_remote_fetch_exec_v1", src_ip="8.8.8.8", confidence=90, severity="high", mitre_tactic="execution"),
    ]
    rule = _Rule(
        id=5,
        name="Risk",
        strategy="risk_aggregation",
        group_by="src_ip",
        window_seconds=300,
        min_alerts=1,
        include_patterns=["*_v1"],
        entity={"type": "src_ip", "field": "src_ip"},
        risk_config={
            "threshold": 70,
            "default_rule_cap": 45,
            "rule_caps": {"beacon_suspect_heuristic_v1": 35},
        },
    )

    incidents = build_incidents([rule], alerts, sample_limit=5)

    assert len(incidents) == 1
    assert incidents[0].risk_score >= 70
    contribs = incidents[0].context["contributions"]
    assert sum(1 for item in contribs if item["rule_id"] == "beacon_suspect_heuristic_v1") == 1


def test_new_entity_strategy_supports_first_seen_and_long_absent() -> None:
    t0 = datetime(2026, 5, 3, 15, 0, 0)
    first_seen_alert = _alert(alert_id=50, created_at=t0, rule_id="beacon_suspect_heuristic_v1", src_ip="9.9.9.9")
    first_seen_rule = _Rule(
        id=6,
        name="New Entity",
        strategy="new_entity",
        group_by="src_ip",
        window_seconds=300,
        min_alerts=1,
        include_patterns=["beacon_suspect_heuristic_v1"],
        entity={"type": "src_ip", "field": "src_ip"},
    )

    incidents = build_incidents([first_seen_rule], [first_seen_alert], sample_limit=5)
    assert len(incidents) == 1
    assert incidents[0].context["reason"] == "first_seen"

    state = CorrelationEntityStateModel(
        entity_type="src_ip",
        entity_value="9.9.9.9",
        first_seen_at=t0 - timedelta(days=10),
        last_seen_at=t0 - timedelta(days=5),
        seen_count=2,
        last_context={},
    )
    long_absent_alert = _alert(alert_id=51, created_at=t0, rule_id="beacon_suspect_heuristic_v1", src_ip="9.9.9.9")
    dataset = CorrelationDataset(alerts=[long_absent_alert], entity_states={("src_ip", "9.9.9.9"): state})
    long_absent_rule = _Rule(
        id=7,
        name="Long Absent",
        strategy="new_entity",
        group_by="src_ip",
        window_seconds=300,
        min_alerts=1,
        include_patterns=["beacon_suspect_heuristic_v1"],
        entity={"type": "src_ip", "field": "src_ip"},
        strategy_config={"long_absent_seconds": 3 * 24 * 3600},
    )

    incidents = build_incidents([long_absent_rule], [long_absent_alert], sample_limit=5, dataset=dataset)
    assert len(incidents) == 1
    assert incidents[0].context["reason"] == "long_absent"


def test_rare_entity_strategy_uses_deterministic_baseline() -> None:
    t0 = datetime(2026, 5, 3, 16, 0, 0)
    alerts = []
    for idx in range(10):
        alerts.append(
            _alert(
                alert_id=100 + idx,
                created_at=t0 + timedelta(seconds=idx),
                rule_id="outbound_contextual_rare_destination_v1",
                details={"group_key": {"agent_id": "agent-rare"}},
                dst_ip=f"203.0.113.{idx}",
            )
        )
    alerts.append(
        _alert(
            alert_id=200,
            created_at=t0 + timedelta(seconds=20),
            rule_id="outbound_contextual_rare_destination_v1",
            details={"group_key": {"agent_id": "agent-rare"}},
            dst_ip="198.51.100.77",
        )
    )
    rule = _Rule(
        id=8,
        name="Rare Entity",
        strategy="rare_entity",
        group_by="dst_ip",
        window_seconds=600,
        min_alerts=1,
        include_patterns=["outbound_contextual_rare_destination_v1"],
        entity={"type": "dst_ip", "field": "dst_ip"},
        strategy_config={
            "source": "alerts",
            "scope_field": "agent_id",
            "target_field": "dst_ip",
            "max_occurrences": 1,
            "min_baseline_observations": 10,
            "min_distinct_values": 8,
            "baseline_window_seconds": 600,
        },
    )

    incidents = build_incidents([rule], alerts, sample_limit=5)

    assert incidents
    assert any(incident.context["target_value"] == "198.51.100.77" for incident in incidents)


def test_burst_strategy_remains_compatible() -> None:
    t0 = datetime(2026, 5, 3, 17, 0, 0)
    alerts = [
        _alert(alert_id=300, created_at=t0, rule_id="ssh_invalid_user_burst_v1", src_ip="10.10.10.10"),
        _alert(alert_id=301, created_at=t0 + timedelta(seconds=30), rule_id="ssh_invalid_user_burst_v1", src_ip="10.10.10.10"),
    ]
    rule = _Rule(
        id=9,
        name="Burst Compatibility",
        strategy="burst",
        group_by="src_ip",
        window_seconds=120,
        min_alerts=2,
        include_patterns=["ssh_invalid_user_burst_v1"],
    )

    incidents = build_incidents([rule], alerts, sample_limit=5)

    assert len(incidents) == 1
    assert incidents[0].context["strategy"] == "burst"


def test_chain_strategy_remains_compatible() -> None:
    t0 = datetime(2026, 5, 3, 18, 0, 0)
    alerts = [
        _alert(alert_id=400, created_at=t0, rule_id="admin_ports_vertical_recon_v1", src_ip="11.11.11.11"),
        _alert(alert_id=401, created_at=t0 + timedelta(minutes=1), rule_id="ssh_failed_password_burst_target_v1", src_ip="11.11.11.11"),
    ]
    rule = _Rule(
        id=10,
        name="Chain Compatibility",
        strategy="chain",
        group_by="src_ip",
        window_seconds=600,
        min_alerts=2,
        include_patterns=["admin_ports_vertical_recon_v1", "ssh_failed_password_burst_target_v1"],
        stages=[
            {"name": "Recon", "patterns": ["admin_ports_vertical_recon_v1"], "min_count": 1},
            {"name": "Brute", "patterns": ["ssh_failed_password_burst_target_v1"], "min_count": 1},
        ],
    )

    incidents = build_incidents([rule], alerts, sample_limit=5)

    assert len(incidents) == 1
    assert incidents[0].context["strategy"] == "chain"


def test_durable_incident_and_evidence_deduplication() -> None:
    now = datetime(2026, 5, 3, 19, 0, 0)
    incident_out = build_incidents(
        [_Rule(id=11, name="Threshold", strategy="threshold", group_by="src_ip", window_seconds=60, min_alerts=2, include_patterns=["x"], entity={"type": "src_ip", "field": "src_ip"})],
        [
            _alert(alert_id=500, created_at=now, rule_id="x", src_ip="12.12.12.12"),
            _alert(alert_id=501, created_at=now + timedelta(seconds=10), rule_id="x", src_ip="12.12.12.12"),
        ],
        sample_limit=5,
    )[0]
    rule = _Rule(id=11, name="Threshold", strategy="threshold")
    db = _FakeDB()

    with patch("app.features.correlations.service.find_open_incident", return_value=None):
        incident, is_new = _upsert_incident(db, rule=rule, incident_out=incident_out, now=now)
    assert is_new is True

    _upsert_evidence(db, incident=incident, sample_alerts=incident_out.sample_alerts, evidence_items=incident_out.evidence_items, is_new=True)
    before_count = len([item for item in db._added if isinstance(item, CorrelationIncidentEvidenceModel)])

    with patch("app.features.correlations.service.list_evidence_for_incident", return_value=[item for item in db._added if isinstance(item, CorrelationIncidentEvidenceModel)]):
        _upsert_evidence(db, incident=incident, sample_alerts=incident_out.sample_alerts, evidence_items=incident_out.evidence_items, is_new=False)
    after_count = len([item for item in db._added if isinstance(item, CorrelationIncidentEvidenceModel)])

    assert before_count == after_count
    assert isinstance(incident, CorrelationIncidentModel)
