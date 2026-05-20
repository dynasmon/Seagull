from __future__ import annotations

import math
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
    _parse_iso,
    _record_finding,
)
from app.features.ueba.domain.statistics import (
    baseline_confidence,
    finite_float,
    risk_from_statistical_score,
    severity_from_risk,
)
from app.features.ueba.models import UebaBaselineModel
from app.shared.taxonomy.catalog import technique_name

_SHELL_PARENTS: frozenset[str] = frozenset({"bash", "sh", "zsh", "python3", "python"})


def _proc_rarity_bits(observation_count: int, total_executions: int, vocab_size: int) -> float:
    probability = (observation_count + 1) / (total_executions + vocab_size + 1)
    return finite_float(-math.log2(max(probability, 1e-9)))


@dataclass(frozen=True)
class RareProcessNameDetector:
    detector_id: str = "rare_process_name_v1"
    detector_version: int = 1
    metric_name: str = "proc_name_frequency"

    def window_bounds(
        self,
        _db: Session,
        *,
        cfg: DetectorRuntimeConfig,
        now: datetime,
    ) -> tuple[datetime, datetime]:
        return _as_utc(now) - timedelta(hours=max(1, int(cfg.proc_name_lookback_hours))), _as_utc(now)

    def run(self, db: Session, *, cfg: DetectorRuntimeConfig, now: datetime) -> DetectorExecutionResult:
        state = repository.get_detector_state(db, self.detector_id)
        context = dict(getattr(state, "context", None) or {})
        after_id = max(0, int(context.get("last_event_id") or 0))
        since = _as_utc(now) - timedelta(hours=max(1, int(cfg.proc_name_lookback_hours)))
        rarity_since = _as_utc(now) - timedelta(hours=max(1, int(cfg.proc_name_rarity_lookback_hours)))

        events = event_queries.fetch_proc_exec_events(
            db,
            after_id=after_id,
            since=since,
            limit=max(1, int(cfg.proc_name_max_events_per_cycle)),
        )

        counters = _MutableCounters(scanned_events=len(events))
        finding_cap = max(0, int(cfg.max_findings_per_detector_cycle))
        latest_id = after_id

        _agent_rarity_cache: dict[str, tuple[int, int]] = {}

        for event in events:
            latest_id = max(latest_id, int(event.id))
            baseline_key = _baseline_key(
                self.detector_id,
                event.agent_id,
                "proc_name",
                event.proc_name,
                self.metric_name,
                event.agent_id,
            )
            baseline = repository.get_baseline_by_key(db, baseline_key)
            counters.evaluated_entities += 1

            if baseline is not None and counters.findings_created < finding_cap:
                if event.agent_id not in _agent_rarity_cache:
                    total_exec = event_queries.fetch_proc_exec_count_for_agent(
                        db, agent_id=event.agent_id, since=rarity_since
                    )
                    vocab = event_queries.fetch_proc_name_baseline_count_for_agent(
                        db, agent_id=event.agent_id, detector_id=self.detector_id
                    )
                    _agent_rarity_cache[event.agent_id] = (total_exec, vocab)
                total_executions, vocab_size = _agent_rarity_cache[event.agent_id]
                finding_result = self._evaluate_event(
                    db,
                    cfg=cfg,
                    event=event,
                    baseline=baseline,
                    total_executions=total_executions,
                    vocab_size=vocab_size,
                )
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
                "lookback_hours": max(1, int(cfg.proc_name_lookback_hours)),
                "event_limit": max(1, int(cfg.proc_name_max_events_per_cycle)),
            },
        )

    def _updated_baseline_payload(
        self,
        *,
        baseline: UebaBaselineModel | None,
        baseline_key: str,
        event: event_queries.ProcExecEvent,
        cfg: DetectorRuntimeConfig,
        now: datetime,
    ) -> dict[str, Any]:
        prior_state = dict(getattr(baseline, "state", None) or {})
        observation_count = max(0, int(prior_state.get("observation_count") or 0)) + 1
        mature = observation_count >= max(1, int(cfg.proc_name_min_samples_for_maturity))
        status = "mature" if mature else "warmup"
        confidence = baseline_confidence(
            sample_count=observation_count,
            min_samples=max(1, int(cfg.proc_name_min_samples_for_maturity)),
            concentration=0.0,
        )
        first_seen_at = _parse_iso(prior_state.get("first_seen_at")) or _as_utc(event.timestamp)
        warmup_started_at = _optional_utc(getattr(baseline, "warmup_started_at", None)) or _as_utc(event.timestamp)
        matured_at = _optional_utc(getattr(baseline, "matured_at", None))
        if mature and matured_at is None:
            matured_at = _as_utc(event.timestamp)
        return {
            "baseline_key": baseline_key,
            "detector_id": self.detector_id,
            "detector_version": self.detector_version,
            "agent_id": event.agent_id,
            "entity_type": "proc_name",
            "entity_value": event.proc_name,
            "metric_name": self.metric_name,
            "bucket_key": event.agent_id,
            "status": status,
            "sample_count": int(observation_count),
            "warmup_started_at": warmup_started_at,
            "matured_at": matured_at,
            "window_started_at": first_seen_at,
            "window_ended_at": _as_utc(event.timestamp),
            "last_observed_at": _as_utc(event.timestamp),
            "expected_value": float(observation_count),
            "dispersion": 0.0,
            "lower_bound": 0.0,
            "upper_bound": float(observation_count),
            "confidence": confidence,
            "state": {
                "method": "frequency_rarity",
                "observation_count": int(observation_count),
                "first_seen_at": _iso(first_seen_at),
                "last_seen_at": _iso(_as_utc(event.timestamp)),
            },
            "updated_at": now,
        }

    def _evaluate_event(
        self,
        db: Session,
        *,
        cfg: DetectorRuntimeConfig,
        event: event_queries.ProcExecEvent,
        baseline: UebaBaselineModel,
        total_executions: int,
        vocab_size: int,
    ) -> tuple[bool, bool, int]:
        prior_state = dict(getattr(baseline, "state", None) or {})
        observation_count = max(0, int(prior_state.get("observation_count") or 0))
        is_warmup = baseline.status == "warmup"

        rarity_bits = _proc_rarity_bits(observation_count, total_executions, vocab_size)

        if not is_warmup and rarity_bits < float(cfg.proc_name_min_rarity_bits):
            return False, False, 0

        reason_codes = ["rare_process_name"] if is_warmup else ["rare_process_name_reappeared"]
        parent = str(event.proc_parent_name or "")
        technique_id = "T1059" if parent in _SHELL_PARENTS else "T1204"

        confidence = max(int(baseline.confidence or 0), 20)
        risk_score = risk_from_statistical_score(z_score=0.0, confidence=confidence, rarity_bits=rarity_bits)
        severity = severity_from_risk(risk_score)

        evidence = [
            {
                "event_id": int(event.id),
                "evidence_type": "event",
                "evidence_role": "trigger",
                "observed_at": _as_utc(event.timestamp),
                "entity_type": "proc_name",
                "entity_value": str(event.proc_name)[:255],
                "matched_field": "proc_name",
                "matched_value": str(event.proc_name)[:255],
                "summary": f"Process {event.proc_name!r} executed on agent {event.agent_id}",
                "raw_context": {
                    "agent_id": event.agent_id,
                    "event_type": "proc_exec",
                    "proc_name": event.proc_name,
                    "proc_exe": event.proc_exe,
                    "proc_parent_name": event.proc_parent_name,
                    "observation_count": int(observation_count),
                    "rarity_bits": float(rarity_bits),
                },
            }
        ]
        finding = _record_finding(
            db,
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            baseline=baseline,
            agent_id=event.agent_id,
            entity_type="proc_name",
            entity_value=event.proc_name,
            metric_name=self.metric_name,
            bucket_key=event.agent_id,
            observed_at=_as_utc(event.timestamp),
            window_started_at=_as_utc(event.timestamp),
            window_ended_at=_as_utc(event.timestamp),
            expected_value=float(observation_count),
            observed_value=float(observation_count + 1),
            deviation_score=float(rarity_bits),
            severity=severity,
            confidence=confidence,
            risk_score=risk_score,
            summary=(
                f"Process {event.proc_name!r} is {'new' if is_warmup else 'rare'} "
                f"on agent {event.agent_id}"
            ),
            reason_codes=reason_codes,
            explanation={
                "method": "frequency_rarity",
                "proc_name": event.proc_name,
                "proc_exe": event.proc_exe,
                "proc_parent_name": event.proc_parent_name,
                "observation_count": int(observation_count),
                "total_executions": int(total_executions),
                "vocab_size": int(vocab_size),
                "rarity_bits": float(rarity_bits),
                "is_warmup": is_warmup,
            },
            evidence=evidence,
            cooldown_minutes=max(1, int(cfg.cooldown_minutes)),
            mitre_tactic="execution",
            mitre_technique_id=technique_id,
            mitre_technique=technique_name(technique_id),
        )
        return finding.created, not finding.created, finding.alerts_created
