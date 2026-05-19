from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.features.ueba import lifecycle, repository
from app.features.ueba.domain import event_queries
from app.features.ueba.domain.support import (
    DetectorExecutionResult,
    DetectorRuntimeConfig,
    _as_utc,
    _baseline_key,
    _iso,
    _MutableCounters,
    _optional_utc,
    _record_finding,
)
from app.features.ueba.domain.statistics import (
    baseline_confidence,
    circular_hour_distance,
    effective_dispersion,
    hour_rarity_bits,
    risk_from_statistical_score,
    severity_from_risk,
    summarize_hour_histogram,
    update_hour_histogram,
)
from app.features.ueba.models import UebaBaselineModel
from app.shared.taxonomy.catalog import technique_name


@dataclass(frozen=True)
class SshLoginHourDetector:
    detector_id: str = "ssh_login_hour_v1"
    detector_version: int = 1
    metric_name: str = "login_hour"

    def window_bounds(
        self,
        _db: Session,
        *,
        cfg: DetectorRuntimeConfig,
        now: datetime,
    ) -> tuple[datetime, datetime]:
        return now - timedelta(hours=max(1, int(cfg.login_hour_lookback_hours))), now

    def run(self, db: Session, *, cfg: DetectorRuntimeConfig, now: datetime) -> DetectorExecutionResult:
        state = repository.get_detector_state(db, self.detector_id)
        context = dict(getattr(state, "context", None) or {})
        after_id = max(0, int(context.get("last_event_id") or 0))
        since, window_end = self.window_bounds(db, cfg=cfg, now=now)
        events = event_queries.fetch_ssh_accepted_events(
            db,
            after_id=after_id,
            since=since,
            limit=max(1, int(cfg.login_hour_max_events_per_cycle)),
        )

        counters = _MutableCounters(scanned_events=len(events))
        finding_cap = max(0, int(cfg.max_findings_per_detector_cycle))
        latest_id = after_id

        for event in events:
            latest_id = max(latest_id, int(event.id))
            baseline_key = _baseline_key(
                self.detector_id,
                event.agent_id,
                "user",
                event.username,
                self.metric_name,
                "global",
            )
            baseline = repository.get_baseline_by_key(db, baseline_key)
            counters.evaluated_entities += 1

            if (
                baseline is not None
                and baseline.status == "mature"
                and counters.findings_created < finding_cap
            ):
                finding_result = self._evaluate_event(db, cfg=cfg, event=event, baseline=baseline)
                counters.consume_finding_result(finding_result)

            payload = self._updated_baseline_payload(
                baseline=baseline,
                baseline_key=baseline_key,
                event=event,
                cfg=cfg,
                now=now,
            )
            _baseline, created = lifecycle.upsert_baseline(db, **payload)
            counters.baselines_created += int(created)
            counters.baselines_updated += int(not created)

        return DetectorExecutionResult(
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            scanned_events=counters.scanned_events,
            evaluated_entities=counters.evaluated_entities,
            baselines_created=counters.baselines_created,
            baselines_updated=counters.baselines_updated,
            findings_created=counters.findings_created,
            findings_updated=counters.findings_updated,
            alerts_created=counters.alerts_created,
            state_context_patch={"last_event_id": latest_id},
            run_context_patch={
                "source": "postgres",
                "query_mode": "bounded_event_cursor",
                "after_id": after_id,
                "last_event_id": latest_id,
                "lookback_hours": max(1, int(cfg.login_hour_lookback_hours)),
                "event_limit": max(1, int(cfg.login_hour_max_events_per_cycle)),
            },
        )

    def _updated_baseline_payload(
        self,
        *,
        baseline: UebaBaselineModel | None,
        baseline_key: str,
        event: event_queries.SshAcceptedEvent,
        cfg: DetectorRuntimeConfig,
        now: datetime,
    ) -> dict[str, Any]:
        prior_state = dict(getattr(baseline, "state", None) or {})
        snapshot = update_hour_histogram(prior_state.get("hour_counts"), event.timestamp.hour)
        sample_count = int(snapshot.sample_count)
        mature = sample_count >= max(1, int(cfg.login_hour_min_samples))
        status = "mature" if mature else "warmup"
        confidence = baseline_confidence(
            sample_count=sample_count,
            min_samples=max(1, int(cfg.login_hour_min_samples)),
            concentration=snapshot.concentration,
        )
        effective = effective_dispersion(observed_dispersion=snapshot.dispersion, expected_value=snapshot.mode_hour)
        width = max(1.0, min(12.0, 2.0 * effective))
        warmup_started_at = _optional_utc(getattr(baseline, "warmup_started_at", None)) or _as_utc(event.timestamp)
        matured_at = _optional_utc(getattr(baseline, "matured_at", None))
        if mature and matured_at is None:
            matured_at = _as_utc(event.timestamp)
        return {
            "baseline_key": baseline_key,
            "detector_id": self.detector_id,
            "detector_version": self.detector_version,
            "agent_id": event.agent_id,
            "entity_type": "user",
            "entity_value": event.username,
            "metric_name": self.metric_name,
            "bucket_key": "global",
            "status": status,
            "sample_count": sample_count,
            "warmup_started_at": warmup_started_at,
            "matured_at": matured_at,
            "window_started_at": warmup_started_at,
            "window_ended_at": _as_utc(event.timestamp),
            "last_observed_at": _as_utc(event.timestamp),
            "expected_value": float(snapshot.mode_hour),
            "dispersion": float(snapshot.dispersion),
            "lower_bound": max(0.0, float(snapshot.mode_hour) - width),
            "upper_bound": min(23.0, float(snapshot.mode_hour) + width),
            "confidence": confidence,
            "state": {
                "method": "hour_histogram",
                "hour_counts": list(snapshot.counts),
                "mode_hour": int(snapshot.mode_hour),
                "concentration": float(snapshot.concentration),
                "last_nonzero_at": _iso(_as_utc(event.timestamp)),
            },
            "updated_at": now,
        }

    def _evaluate_event(
        self,
        db: Session,
        *,
        cfg: DetectorRuntimeConfig,
        event: event_queries.SshAcceptedEvent,
        baseline: UebaBaselineModel,
    ) -> tuple[bool, bool, int]:
        snapshot = summarize_hour_histogram((baseline.state or {}).get("hour_counts"))
        if snapshot.sample_count < max(1, int(cfg.login_hour_min_samples)):
            return False, False, 0
        observed_hour = int(event.timestamp.hour)
        rarity_bits = hour_rarity_bits(counts=snapshot.counts, hour=observed_hour)
        distance = circular_hour_distance(observed_hour, snapshot.mode_hour)
        denom = max(1.0, effective_dispersion(observed_dispersion=snapshot.dispersion, expected_value=0.0))
        z_score = float(distance / denom)
        if rarity_bits < float(cfg.login_hour_min_rarity_bits) or z_score < float(cfg.login_hour_min_z_score):
            return False, False, 0

        confidence = max(int(baseline.confidence or 0), 50)
        risk_score = risk_from_statistical_score(
            z_score=z_score,
            confidence=confidence,
            rarity_bits=rarity_bits,
            floor=45,
        )
        severity = severity_from_risk(risk_score)
        evidence = [
            {
                "event_id": int(event.id),
                "evidence_type": "event",
                "evidence_role": "trigger",
                "observed_at": _as_utc(event.timestamp),
                "entity_type": "user",
                "entity_value": event.username,
                "matched_field": "ssh_username",
                "matched_value": event.username,
                "summary": f"{event.username} accepted SSH login at {observed_hour:02d}:00 UTC",
                "raw_context": {
                    "agent_id": event.agent_id,
                    "event_type": "ssh_auth",
                    "ssh_action": "accepted",
                    "src_ip": event.src_ip,
                    "observed_hour_utc": observed_hour,
                },
            }
        ]
        finding = _record_finding(
            db,
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            baseline=baseline,
            agent_id=event.agent_id,
            entity_type="user",
            entity_value=event.username,
            metric_name=self.metric_name,
            bucket_key="global",
            observed_at=_as_utc(event.timestamp),
            window_started_at=_as_utc(event.timestamp),
            window_ended_at=_as_utc(event.timestamp),
            expected_value=float(snapshot.mode_hour),
            observed_value=float(observed_hour),
            deviation_score=float(z_score),
            severity=severity,
            confidence=confidence,
            risk_score=risk_score,
            summary=(
                f"Accepted SSH login for {event.username} at {observed_hour:02d}:00 UTC "
                f"deviated from the usual {snapshot.mode_hour:02d}:00 UTC login hour"
            ),
            reason_codes=["rare_login_hour", "login_hour_far_from_baseline"],
            explanation={
                "method": "hour_histogram",
                "expected_hour_utc": int(snapshot.mode_hour),
                "observed_hour_utc": observed_hour,
                "hour_distance": float(distance),
                "rarity_bits": float(rarity_bits),
                "z_score": float(z_score),
                "sample_count": int(snapshot.sample_count),
                "hour_counts": list(snapshot.counts),
            },
            evidence=evidence,
            cooldown_minutes=max(1, int(cfg.cooldown_minutes)),
            mitre_tactic="initial_access",
            mitre_technique_id="T1078",
            mitre_technique=technique_name("T1078"),
        )
        return finding.created, not finding.created, finding.alerts_created
