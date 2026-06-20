from __future__ import annotations

import os

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:seagull@127.0.0.1:5432/seagull")

from app.features.alerts.public import persist_alert_drafts
from app.shared.alerting import AlertDraft


class _FakeSession:
    def __init__(self):
        self.added = []

    def add(self, row):
        self.added.append(row)


def _draft(**overrides):
    base = dict(
        rule_id="r1",
        severity="high",
        risk_score=42,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        dst_port=443,
        mitre_tactic="discovery",
        mitre_technique_id="T1046",
        mitre_technique="Network Service Discovery",
        confidence=77,
        description="suspicious scan",
        details={"schema_version": 2, "count": 10},
        detector_type="rule",
        rule_version=2,
        rule_hash="abc123",
    )
    base.update(overrides)
    return AlertDraft(**base)


def test_persist_alert_drafts_maps_every_field_and_adds_each_row():
    db = _FakeSession()
    rows = persist_alert_drafts(db, [_draft(), _draft(rule_id="r2", severity="low")])

    assert len(rows) == 2
    assert db.added == rows

    first = rows[0]
    assert first.rule_id == "r1"
    assert first.severity == "high"
    assert first.risk_score == 42
    assert first.src_ip == "10.0.0.1"
    assert first.dst_ip == "10.0.0.2"
    assert first.dst_port == 443
    assert first.mitre_tactic == "discovery"
    assert first.mitre_technique_id == "T1046"
    assert first.mitre_technique == "Network Service Discovery"
    assert first.confidence == 77
    assert first.description == "suspicious scan"
    assert first.details == {"schema_version": 2, "count": 10}
    assert first.detector_type == "rule"
    assert first.rule_version == 2
    assert first.rule_hash == "abc123"

    assert rows[1].rule_id == "r2"
    assert rows[1].severity == "low"


def test_persist_alert_drafts_empty_is_noop():
    db = _FakeSession()
    assert persist_alert_drafts(db, []) == []
    assert db.added == []
