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
    _floor_to_window,
    _iso,
    _MutableCounters,
    _optional_utc,
    _parse_iso,
    _record_finding,
)
from app.features.ueba.domain.statistics import (
    RunningStats,
    baseline_confidence,
    effective_dispersion,
    positive_z_score,
    risk_from_statistical_score,
    severity_from_risk,
)
from app.features.ueba.models import UebaBaselineModel
from app.shared.taxonomy.catalog import technique_name


@dataclass(frozen=True)
class SshSourceDiversityDetector:
    detector_id: str = "ssh_source_diversity_v1"
    detector_version: int = 1
    metric_name: str = "distinct_successful_source_ips"

    def window_bounds(
        self,
        _db: Session,
        *,
        cfg: DetectorRuntimeConfig,
        now: datetime,
    ) -> tuple[datetime, datetime]:
        end = _floor_to_window(now, max(1, int(cfg.source_diversity_window_minutes)))
        return end - timedelta(minutes=max(1, int(cfg.source_diversity_window_minutes))), end

    def run(self, db: Session, *, cfg: DetectorRuntimeConfig, now: datetime) -> DetectorExecutionResult:
        window_minutes = max(1, int(cfg.source_diversity_window_minutes))
        latest_end = _floor_to_window(now, window_minutes)
        state = repository.get_detector_state(db, self.detector_id)
        context = dict(getattr(state, "context", None) or {})
        last_window_end = _parse_iso(context.get("last_window_end"))
        if last_window_end is None:
            next_end = latest_end
        else:
            next_end = last_window_end + timedelta(minutes=window_minutes)

        counters = _MutableCounters()
        processed_windows = 0
        truncated_windows = 0
        finding_cap = max(0, int(cfg.max_findings_per_detector_cycle))
        last_processed_end = last_window_end

        while (
            next_end <= latest_end
            and processed_windows < max(1, int(cfg.source_diversity_max_windows_per_cycle))
        ):
            window_start = next_end - timedelta(minutes=window_minutes)
            rows, truncated = event_queries.fetch_ssh_source_diversity(
                db,
                window_started_at=window_start,
                window_ended_at=next_end,
                limit=max(1, int(cfg.source_diversity_max_entities_per_cycle)),
            )
            active_baselines = self._active_baselines(db, cfg=cfg, now=next_end)
            current_keys = {
                _baseline_key(self.detector_id, row.agent_id, "user", row.username, self.metric_name, "global")
                for row in rows
            }
            keys_to_process: dict[str, tuple[str, str, int, int]] = {
                _baseline_key(self.detector_id, row.agent_id, "user", row.username, self.metric_name, "global"): (
                    row.agent_id,
                    row.username,
                    row.distinct_sources,
                    row.event_count,
                )
                for row in rows
            }
            for baseline in active_baselines:
                if baseline.baseline_key in current_keys:
                    continue
                keys_to_process[baseline.baseline_key] = (
                    str(baseline.agent_id or ""),
                    str(baseline.entity_value),
                    0,
                    0,
                )

            counters.scanned_events += sum(int(row.event_count) for row in rows)
            counters.evaluated_entities += len(keys_to_process)
            truncated_windows += int(truncated)

            for baseline_key, (agent_id, username, observed, event_count) in keys_to_process.items():
                baseline = repository.get_baseline_by_key(db, baseline_key)
                if (
                    observed > 0
                    and baseline is not None
                    and baseline.status == "mature"
                    and counters.findings_created < finding_cap
                ):
                    finding_result = self._evaluate_window(
                        db,
                        cfg=cfg,
                        baseline=baseline,
                        agent_id=agent_id,
                        username=username,
                        observed=observed,
                        event_count=event_count,
                        window_started_at=window_start,
                        window_ended_at=next_end,
                    )
                    counters.consume_finding_result(finding_result)
                payload = self._updated_baseline_payload(
                    baseline=baseline,
                    baseline_key=baseline_key,
                    agent_id=agent_id,
                    username=username,
                    observed=observed,
                    window_started_at=window_start,
                    window_ended_at=next_end,
                    cfg=cfg,
                    now=now,
                )
                _baseline, created = lifecycle.upsert_baseline(db, **payload)
                counters.baselines_created += int(created)
                counters.baselines_updated += int(not created)

            processed_windows += 1
            last_processed_end = next_end
            next_end = next_end + timedelta(minutes=window_minutes)

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
            state_context_patch=(
                {"last_window_end": _iso(last_processed_end)}
                if last_processed_end is not None
                else {}
            ),
            run_context_patch={
                "source": "postgres",
                "query_mode": "bounded_fixed_windows",
                "window_minutes": window_minutes,
                "processed_windows": processed_windows,
                "latest_complete_window_end": _iso(latest_end),
                "truncated_windows": truncated_windows,
                "entity_limit": max(1, int(cfg.source_diversity_max_entities_per_cycle)),
            },
        )

    def _active_baselines(
        self,
        db: Session,
        *,
        cfg: DetectorRuntimeConfig,
        now: datetime,
    ) -> list[UebaBaselineModel]:
        rows = repository.list_detector_baselines(
            db,
            detector_id=self.detector_id,
            limit=max(1, int(cfg.source_diversity_max_entities_per_cycle)),
        )
        horizon = now - timedelta(hours=max(1, int(cfg.active_entity_hours)))
        out: list[UebaBaselineModel] = []
        for row in rows:
            last_nonzero_at = _parse_iso((row.state or {}).get("last_nonzero_at"))
            if last_nonzero_at is None or last_nonzero_at >= horizon:
                out.append(row)
        return out

    def _updated_baseline_payload(
        self,
        *,
        baseline: UebaBaselineModel | None,
        baseline_key: str,
        agent_id: str,
        username: str,
        observed: int,
        window_started_at: datetime,
        window_ended_at: datetime,
        cfg: DetectorRuntimeConfig,
        now: datetime,
    ) -> dict[str, Any]:
        prior_state = dict(getattr(baseline, "state", None) or {})
        stats = RunningStats.from_state(prior_state.get("running_stats")).update(max(0, int(observed)))
        mature = stats.count >= max(1, int(cfg.source_diversity_min_samples))
        status = "mature" if mature else "warmup"
        confidence = baseline_confidence(
            sample_count=stats.count,
            min_samples=max(1, int(cfg.source_diversity_min_samples)),
            concentration=0.0,
        )
        scoring_dispersion = effective_dispersion(observed_dispersion=stats.stddev, expected_value=stats.mean)
        warmup_started_at = _optional_utc(getattr(baseline, "warmup_started_at", None)) or window_started_at
        matured_at = _optional_utc(getattr(baseline, "matured_at", None))
        if mature and matured_at is None:
            matured_at = window_ended_at
        last_nonzero_at = prior_state.get("last_nonzero_at")
        if observed > 0:
            last_nonzero_at = _iso(window_ended_at)
        return {
            "baseline_key": baseline_key,
            "detector_id": self.detector_id,
            "detector_version": self.detector_version,
            "agent_id": agent_id,
            "entity_type": "user",
            "entity_value": username,
            "metric_name": self.metric_name,
            "bucket_key": "global",
            "status": status,
            "sample_count": int(stats.count),
            "warmup_started_at": warmup_started_at,
            "matured_at": matured_at,
            "window_started_at": window_started_at,
            "window_ended_at": window_ended_at,
            "last_observed_at": window_ended_at,
            "expected_value": float(stats.mean),
            "dispersion": float(stats.stddev),
            "lower_bound": max(0.0, float(stats.mean) - (3.0 * scoring_dispersion)),
            "upper_bound": float(stats.mean) + (3.0 * scoring_dispersion),
            "confidence": confidence,
            "state": {
                "method": "welford_window_counts",
                "running_stats": stats.to_state(),
                "effective_dispersion": float(scoring_dispersion),
                "last_nonzero_at": last_nonzero_at,
            },
            "updated_at": now,
        }

    def _evaluate_window(
        self,
        db: Session,
        *,
        cfg: DetectorRuntimeConfig,
        baseline: UebaBaselineModel,
        agent_id: str,
        username: str,
        observed: int,
        event_count: int,
        window_started_at: datetime,
        window_ended_at: datetime,
    ) -> tuple[bool, bool, int]:
        expected = float(baseline.expected_value or 0.0)
        dispersion = float(baseline.dispersion or 0.0)
        z_score = positive_z_score(
            observed_value=float(observed),
            expected_value=expected,
            dispersion=dispersion,
        )
        if z_score < float(cfg.source_diversity_min_z_score):
            return False, False, 0
        confidence = max(int(baseline.confidence or 0), 50)
        risk_score = risk_from_statistical_score(z_score=z_score, confidence=confidence, floor=45)
        severity = severity_from_risk(risk_score)
        samples = event_queries.fetch_ssh_source_evidence(
            db,
            agent_id=agent_id,
            username=username,
            window_started_at=window_started_at,
            window_ended_at=window_ended_at,
            limit=3,
        )
        evidence = [
            {
                "event_id": int(row["id"]),
                "evidence_type": "event",
                "evidence_role": "trigger",
                "observed_at": _as_utc(row["timestamp"]),
                "entity_type": "user",
                "entity_value": username,
                "matched_field": "src_ip",
                "matched_value": str(row["src_ip"]),
                "summary": f"{username} accepted SSH login from {row['src_ip']}",
                "raw_context": {
                    "agent_id": agent_id,
                    "event_type": "ssh_auth",
                    "ssh_action": "accepted",
                    "src_ip": str(row["src_ip"]),
                },
            }
            for row in samples
        ]
        finding = _record_finding(
            db,
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            baseline=baseline,
            agent_id=agent_id,
            entity_type="user",
            entity_value=username,
            metric_name=self.metric_name,
            bucket_key="global",
            observed_at=window_ended_at,
            window_started_at=window_started_at,
            window_ended_at=window_ended_at,
            expected_value=expected,
            observed_value=float(observed),
            deviation_score=float(z_score),
            severity=severity,
            confidence=confidence,
            risk_score=risk_score,
            summary=(
                f"{username} logged in from {observed} distinct SSH source IPs in one window; "
                f"baseline expected about {expected:.2f}"
            ),
            reason_codes=["ssh_source_diversity_above_baseline"],
            explanation={
                "method": "welford_window_counts",
                "window_minutes": max(1, int(cfg.source_diversity_window_minutes)),
                "expected_distinct_sources": expected,
                "observed_distinct_sources": int(observed),
                "sample_stddev": dispersion,
                "effective_dispersion": effective_dispersion(
                    observed_dispersion=dispersion,
                    expected_value=expected,
                ),
                "z_score": float(z_score),
                "event_count": int(event_count),
                "sample_count": int(baseline.sample_count or 0),
            },
            evidence=evidence,
            cooldown_minutes=max(1, int(cfg.cooldown_minutes)),
            mitre_tactic="initial_access",
            mitre_technique_id="T1078",
            mitre_technique=technique_name("T1078"),
        )
        return finding.created, not finding.created, finding.alerts_created
