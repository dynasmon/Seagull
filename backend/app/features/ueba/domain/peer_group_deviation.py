from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from app.core.observability import log_event
from app.features.ueba import lifecycle, repository
from app.features.ueba.domain import event_queries, peer_groups
from app.features.ueba.domain.statistics import baseline_confidence
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

logger = logging.getLogger("seagull.ueba.peer_groups")


@dataclass(frozen=True)
class PeerGroupDeviationDetector:
    detector_id: str = peer_groups.PEER_GROUP_DETECTOR_ID
    detector_version: int = 1
    metric_name: str = "peer_group_distance"

    def window_bounds(
        self,
        _db: Session,
        *,
        cfg: DetectorRuntimeConfig,
        now: datetime,
    ) -> tuple[datetime, datetime]:
        end = _as_utc(now)
        start = end - timedelta(minutes=max(5, int(cfg.peer_current_window_minutes)))
        return start, end

    def run(self, db: Session, *, cfg: DetectorRuntimeConfig, now: datetime) -> DetectorExecutionResult:
        now_v = _as_utc(now)
        state = repository.get_detector_state(db, self.detector_id)
        context = dict(getattr(state, "context", None) or {})
        counters = _MutableCounters()
        clustered = self._cluster_if_due(db, cfg=cfg, now=now_v, context=context)

        run_id = repository.latest_peer_group_run_id(db)
        if not run_id:
            return self._result(counters, context_patch=clustered)

        group_rows = repository.list_peer_groups_for_run(db, run_id=run_id)
        agent_ids = [row.agent_id for row in group_rows if row.scoring_enabled]
        if not agent_ids:
            return self._result(counters, context_patch=clustered)

        current_start = now_v - timedelta(minutes=max(5, int(cfg.peer_current_window_minutes)))
        current_events = event_queries.fetch_behavior_events_for_agents(
            db,
            agent_ids=agent_ids,
            since=current_start,
            until=now_v,
            limit=max(1000, int(cfg.peer_max_events_per_clustering)),
        )
        current_fps = {
            fp.agent_id: fp
            for fp in peer_groups.build_fingerprints(
                current_events,
                agent_ids=agent_ids,
                since=current_start,
                until=now_v,
            )
        }

        finding_cap = max(0, int(cfg.max_findings_per_detector_cycle))
        for row in group_rows:
            if counters.findings_created >= finding_cap:
                break
            if not row.scoring_enabled or row.distance_threshold is None:
                continue
            fp = current_fps.get(row.agent_id)
            if fp is None:
                continue
            vector_payload = row.fingerprint_vector if isinstance(row.fingerprint_vector, dict) else {}
            normalization = vector_payload.get("normalization") if isinstance(vector_payload.get("normalization"), dict) else {}
            normalized = peer_groups.normalize_current_vector(
                fp.values,
                means=normalization.get("means") if isinstance(normalization.get("means"), dict) else {},
                stddevs=normalization.get("stddevs") if isinstance(normalization.get("stddevs"), dict) else {},
            )
            centroid = row.centroid_vector if isinstance(row.centroid_vector, dict) else {}
            covariance = row.covariance_matrix if isinstance(row.covariance_matrix, dict) else {}
            distance = peer_groups.mahalanobis_distance(normalized, centroid=centroid, covariance=covariance)
            threshold = float(row.distance_threshold or 0.0)
            if threshold <= 0 or distance <= threshold:
                continue
            counters.evaluated_entities += 1
            finding = self._record_peer_finding(
                db,
                cfg=cfg,
                now=now_v,
                agent_id=row.agent_id,
                group_row=row,
                current_raw=fp.values,
                current_normalized=normalized,
                distance=distance,
                threshold=threshold,
            )
            counters.consume_finding_result(finding)

        return self._result(counters, context_patch=clustered)

    def _cluster_if_due(
        self,
        db: Session,
        *,
        cfg: DetectorRuntimeConfig,
        now: datetime,
        context: dict[str, Any],
    ) -> dict[str, Any]:
        raw_last = context.get("last_clustering_at")
        last = _optional_utc(raw_last) if isinstance(raw_last, datetime) else _parse_iso(raw_last)
        interval = timedelta(seconds=max(60, int(cfg.peer_clustering_interval_seconds)))
        if last is not None and last + interval > now and repository.latest_peer_group_run_id(db):
            return {}

        matured_before = now - timedelta(days=max(0, int(cfg.peer_min_mature_days)))
        agents = repository.list_mature_agent_ids(db, matured_before=matured_before)
        all_agents_with_data = set(repository.list_all_agent_ids_with_baselines(db))
        ungrouped_agents = sorted(all_agents_with_data - set(agents))

        run_id = str(uuid4())

        if len(agents) < max(2, int(cfg.peer_min_agents)):
            for agent_id in ungrouped_agents + list(agents):
                repository.create_peer_group(
                    db,
                    run_id=run_id,
                    agent_id=agent_id,
                    group_id=0,
                    silhouette_score=None,
                    fingerprint_vector={},
                    computed_at=now,
                    feature_schema_version=int(cfg.peer_feature_schema_version),
                    centroid_vector={},
                    covariance_matrix={},
                    distance_threshold=None,
                    group_size=0,
                    peer_agents=[],
                    scoring_enabled=False,
                )
            patch = {
                "last_clustering_at": _iso(now),
                "last_clustered_agents": len(agents),
                "last_ungrouped_agents": len(ungrouped_agents),
                "peer_scoring_enabled": False,
            }
            log_event(
                logger, "info", "ueba_peer_group_clustering",
                agents=len(agents), ungrouped=len(ungrouped_agents), groups=0, scoring_enabled=False,
            )
            return patch

        since = now - timedelta(days=7)
        events = event_queries.fetch_behavior_events_for_agents(
            db,
            agent_ids=agents,
            since=since,
            until=now,
            limit=max(1000, int(cfg.peer_max_events_per_clustering)),
        )
        fingerprints = peer_groups.build_fingerprints(events, agent_ids=agents, since=since, until=now)
        normalized = peer_groups.normalize_fingerprints(fingerprints)
        assignments = peer_groups.choose_peer_assignments(
            normalized.vectors,
            min_silhouette_score=float(cfg.peer_min_silhouette_score),
            min_agents=int(cfg.peer_min_agents),
        )
        stats = peer_groups.compute_group_stats(
            normalized.vectors,
            assignments,
            distance_percentile=float(cfg.peer_distance_percentile),
        )
        by_agent = {fp.agent_id: fp for fp in fingerprints}
        assignment_by_agent = {item.agent_id: item for item in assignments}
        for agent_id in sorted(by_agent):
            assignment = assignment_by_agent[agent_id]
            stat = stats.get(assignment.group_id)
            repository.create_peer_group(
                db,
                run_id=run_id,
                agent_id=agent_id,
                group_id=assignment.group_id,
                silhouette_score=assignment.silhouette_score,
                fingerprint_vector={
                    "raw": by_agent[agent_id].values,
                    "normalized": normalized.vectors.get(agent_id, {}),
                    "normalization": {"means": normalized.means, "stddevs": normalized.stddevs},
                },
                computed_at=now,
                feature_schema_version=int(cfg.peer_feature_schema_version),
                centroid_vector=(stat.centroid if stat else {}),
                covariance_matrix=(stat.covariance if stat else {}),
                distance_threshold=(stat.threshold_distance if stat else None),
                group_size=(len(stat.peer_agents) if stat else 0),
                peer_agents=(stat.peer_agents if stat else []),
                scoring_enabled=bool(assignment.scoring_enabled and stat and stat.threshold_distance is not None),
            )
        for agent_id in ungrouped_agents:
            repository.create_peer_group(
                db,
                run_id=run_id,
                agent_id=agent_id,
                group_id=0,
                silhouette_score=None,
                fingerprint_vector={},
                computed_at=now,
                feature_schema_version=int(cfg.peer_feature_schema_version),
                centroid_vector={},
                covariance_matrix={},
                distance_threshold=None,
                group_size=0,
                peer_agents=[],
                scoring_enabled=False,
            )
        enabled = any(item.scoring_enabled for item in assignments)
        group_count = len({item.group_id for item in assignments if item.scoring_enabled})
        log_event(
            logger,
            "info",
            "ueba_peer_group_clustering",
            run_id=run_id,
            agents=len(agents),
            ungrouped=len(ungrouped_agents),
            groups=group_count,
            scoring_enabled=enabled,
            events=len(events),
        )
        return {
            "last_clustering_at": _iso(now),
            "last_peer_run_id": run_id,
            "last_clustered_agents": len(agents),
            "last_ungrouped_agents": len(ungrouped_agents),
            "last_peer_group_count": group_count,
            "peer_scoring_enabled": enabled,
        }

    def _record_peer_finding(
        self,
        db: Session,
        *,
        cfg: DetectorRuntimeConfig,
        now: datetime,
        agent_id: str,
        group_row: Any,
        current_raw: dict[str, float],
        current_normalized: dict[str, float],
        distance: float,
        threshold: float,
    ):
        baseline_key = _baseline_key(
            self.detector_id,
            agent_id,
            "agent",
            agent_id,
            self.metric_name,
            "global",
        )
        baseline = repository.get_baseline_by_key(db, baseline_key)
        prior_samples = max(0, int(getattr(baseline, "sample_count", 0) or 0))
        confidence = baseline_confidence(sample_count=prior_samples + 1, min_samples=3, concentration=1.0)
        baseline_payload = {
            "baseline_key": baseline_key,
            "detector_id": self.detector_id,
            "detector_version": self.detector_version,
            "agent_id": agent_id,
            "entity_type": "agent",
            "entity_value": agent_id,
            "metric_name": self.metric_name,
            "bucket_key": "global",
            "status": "mature",
            "sample_count": prior_samples + 1,
            "warmup_started_at": (_optional_utc(getattr(baseline, "warmup_started_at", None)) or now),
            "matured_at": (_optional_utc(getattr(baseline, "matured_at", None)) or now),
            "window_started_at": now - timedelta(minutes=max(5, int(cfg.peer_current_window_minutes))),
            "window_ended_at": now,
            "last_observed_at": now,
            "expected_value": threshold,
            "dispersion": 1.0,
            "lower_bound": 0.0,
            "upper_bound": threshold,
            "confidence": confidence,
            "state": {"method": "peer_group_mahalanobis", "group_id": int(group_row.group_id)},
            "updated_at": now,
        }
        baseline, _created = lifecycle.upsert_baseline(db, **baseline_payload)

        risk_score = peer_groups.risk_from_peer_distance(distance, threshold)
        severity = peer_groups.severity_from_peer_distance(distance, threshold)
        peer_agents = list(group_row.peer_agents or [])
        explanation = {
            "group_id": int(group_row.group_id),
            "group_size": int(group_row.group_size or len(peer_agents)),
            "mahalanobis_distance": float(distance),
            "threshold_distance": float(threshold),
            "centroid_delta": peer_groups.centroid_delta(
                current_normalized,
                centroid=(group_row.centroid_vector if isinstance(group_row.centroid_vector, dict) else {}),
            ),
            "peer_agents": peer_agents[:50],
            "current_fingerprint": current_raw,
            "current_normalized": current_normalized,
            "peer_run_id": str(group_row.run_id),
        }
        return _record_finding(
            db,
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            baseline=baseline,
            agent_id=agent_id,
            entity_type="agent",
            entity_value=agent_id,
            metric_name=self.metric_name,
            bucket_key="global",
            observed_at=now,
            window_started_at=now - timedelta(minutes=max(5, int(cfg.peer_current_window_minutes))),
            window_ended_at=now,
            expected_value=threshold,
            observed_value=distance,
            deviation_score=(distance / threshold if threshold > 0 else distance),
            severity=severity,
            confidence=confidence,
            risk_score=risk_score,
            summary=f"Agent {agent_id} deviated from peer group {group_row.group_id}",
            reason_codes=["peer_group_deviation"],
            explanation=explanation,
            evidence=[
                {
                    "event_id": None,
                    "evidence_type": "aggregate",
                    "evidence_role": "trigger",
                    "observed_at": now,
                    "entity_type": "agent",
                    "entity_value": agent_id,
                    "matched_field": "peer_group_distance",
                    "matched_value": f"{distance:.4f}",
                    "summary": f"Mahalanobis distance {distance:.2f} exceeded peer threshold {threshold:.2f}",
                    "raw_context": explanation,
                }
            ],
            cooldown_minutes=max(1, int(cfg.cooldown_minutes)),
            mitre_tactic="defense_evasion",
            mitre_technique_id="T1036",
            mitre_technique="Masquerading",
        )

    def _result(self, counters: _MutableCounters, *, context_patch: dict[str, Any]) -> DetectorExecutionResult:
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
            suppressions_applied=counters.suppressions_applied,
            state_context_patch=context_patch,
            run_context_patch={"source": "postgres", "mode": "peer_group_offline"},
        )
