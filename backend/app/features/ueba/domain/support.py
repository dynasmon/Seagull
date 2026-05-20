from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from sqlalchemy.orm import Session

from app.features.ueba import lifecycle, repository
from app.features.ueba.domain import alerting
from app.features.ueba.models import UebaBaselineModel


class DetectorRuntimeConfig(Protocol):
    login_hour_lookback_hours: int
    login_hour_min_samples: int
    login_hour_max_events_per_cycle: int
    login_hour_min_rarity_bits: float
    login_hour_min_z_score: float
    source_diversity_window_minutes: int
    source_diversity_min_samples: int
    source_diversity_max_entities_per_cycle: int
    source_diversity_max_windows_per_cycle: int
    source_diversity_min_z_score: float
    active_entity_hours: int
    cooldown_minutes: int
    max_findings_per_detector_cycle: int
    outbound_bytes_window_minutes: int
    outbound_bytes_min_samples: int
    outbound_bytes_max_entities_per_cycle: int
    outbound_bytes_max_windows_per_cycle: int
    outbound_bytes_min_z_score: float
    lateral_spread_window_minutes: int
    lateral_spread_min_samples: int
    lateral_spread_max_entities_per_cycle: int
    lateral_spread_max_windows_per_cycle: int
    lateral_spread_min_z_score: float
    proc_exec_rate_window_minutes: int
    proc_exec_rate_min_samples: int
    proc_exec_rate_max_entities_per_cycle: int
    proc_exec_rate_max_windows_per_cycle: int
    proc_exec_rate_min_z_score: float
    proc_name_lookback_hours: int
    proc_name_max_events_per_cycle: int
    proc_name_min_rarity_bits: float
    proc_name_min_samples_for_maturity: int
    proc_name_rarity_lookback_hours: int


@dataclass(frozen=True)
class DetectorExecutionResult:
    detector_id: str
    detector_version: int
    scanned_events: int = 0
    evaluated_entities: int = 0
    baselines_created: int = 0
    baselines_updated: int = 0
    findings_created: int = 0
    findings_updated: int = 0
    alerts_created: int = 0
    suppressions_applied: int = 0
    state_context_patch: dict[str, Any] = field(default_factory=dict)
    run_context_patch: dict[str, Any] = field(default_factory=dict)


class UebaDetector(Protocol):
    detector_id: str
    detector_version: int

    def window_bounds(
        self,
        db: Session,
        *,
        cfg: DetectorRuntimeConfig,
        now: datetime,
    ) -> tuple[datetime | None, datetime | None]:
        ...

    def run(self, db: Session, *, cfg: DetectorRuntimeConfig, now: datetime) -> DetectorExecutionResult:
        ...

@dataclass(frozen=True)
class _RecordedFinding:
    created: bool
    alerts_created: int


def _record_finding(
    db: Session,
    *,
    detector_id: str,
    detector_version: int,
    baseline: UebaBaselineModel,
    agent_id: str,
    entity_type: str,
    entity_value: str,
    metric_name: str,
    bucket_key: str,
    observed_at: datetime,
    window_started_at: datetime,
    window_ended_at: datetime,
    expected_value: float,
    observed_value: float,
    deviation_score: float,
    severity: str,
    confidence: int,
    risk_score: int,
    summary: str,
    reason_codes: list[str],
    explanation: dict[str, Any],
    evidence: list[dict[str, Any]],
    cooldown_minutes: int,
    mitre_tactic: str,
    mitre_technique_id: str,
    mitre_technique: str | None,
) -> _RecordedFinding:
    dedup_key = _dedup_key(detector_id, agent_id, entity_type, entity_value, metric_name, bucket_key)
    finding_key = _finding_key(dedup_key, observed_at)
    result = lifecycle.record_finding_observation(
        db,
        finding_key=finding_key,
        dedup_key=dedup_key,
        detector_id=detector_id,
        detector_version=detector_version,
        baseline_id=int(baseline.id),
        agent_id=agent_id,
        entity_type=entity_type,
        entity_value=entity_value,
        metric_name=metric_name,
        bucket_key=bucket_key,
        status="open",
        severity=severity,
        confidence=int(confidence),
        risk_score=int(risk_score),
        expected_value=float(expected_value),
        observed_value=float(observed_value),
        deviation_score=float(deviation_score),
        first_seen_at=observed_at,
        last_seen_at=observed_at,
        window_started_at=window_started_at,
        window_ended_at=window_ended_at,
        cooldown_until=observed_at + timedelta(minutes=max(1, int(cooldown_minutes))),
        summary=summary,
        reason_codes=reason_codes,
        explanation=explanation,
        mitre_tactic=mitre_tactic,
        mitre_technique_id=mitre_technique_id,
        mitre_technique=mitre_technique,
        updated_at=observed_at,
    )
    repository.flush(db)
    lifecycle.append_finding_evidence(db, finding_id=int(result.finding.id), specs=evidence)
    alerts_created = 0
    if result.created:
        alerting.persist_alert_for_finding(db, finding=result.finding, evidence_specs=evidence)
        alerts_created = 1
    return _RecordedFinding(created=bool(result.created), alerts_created=alerts_created)


@dataclass
class _MutableCounters:
    scanned_events: int = 0
    evaluated_entities: int = 0
    baselines_created: int = 0
    baselines_updated: int = 0
    findings_created: int = 0
    findings_updated: int = 0
    alerts_created: int = 0

    def consume_finding_result(self, result: tuple[bool, bool, int]) -> None:
        created, updated, alerts_created = result
        self.findings_created += int(created)
        self.findings_updated += int(updated)
        self.alerts_created += int(alerts_created)


def _baseline_key(
    detector_id: str,
    agent_id: str | None,
    entity_type: str,
    entity_value: str,
    metric_name: str,
    bucket_key: str,
) -> str:
    raw = "|".join(
        [
            detector_id,
            str(agent_id or ""),
            entity_type,
            entity_value,
            metric_name,
            bucket_key,
        ]
    )
    return f"b:{_sha(raw)}"


def _dedup_key(
    detector_id: str,
    agent_id: str | None,
    entity_type: str,
    entity_value: str,
    metric_name: str,
    bucket_key: str,
) -> str:
    return "|".join([detector_id, str(agent_id or ""), entity_type, entity_value, metric_name, bucket_key])[:256]


def _finding_key(dedup_key: str, observed_at: datetime) -> str:
    return f"f:{_sha(f'{dedup_key}|{_iso(observed_at)}')}"


def _sha(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8", errors="ignore")).hexdigest()[:40]


def _as_utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _optional_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return _as_utc(value)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return _as_utc(value).isoformat()


def _parse_iso(value: Any) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        return _as_utc(datetime.fromisoformat(raw))
    except ValueError:
        return None


def _floor_to_window(value: datetime, window_minutes: int) -> datetime:
    aware = _as_utc(value)
    total_minutes = (aware.hour * 60) + aware.minute
    floored_minutes = (total_minutes // max(1, int(window_minutes))) * max(1, int(window_minutes))
    return aware.replace(
        hour=floored_minutes // 60,
        minute=floored_minutes % 60,
        second=0,
        microsecond=0,
    )
