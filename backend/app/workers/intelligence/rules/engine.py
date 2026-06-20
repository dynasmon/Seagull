import logging
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List

from app.core.db import SessionLocal
from app.core.observability import log_event
from app.features.alerts.evidence import extract_evidence_specs
from app.features.alerts.models import AlertEvidenceModel, AlertModel
from app.features.alerts.public import persist_alert_drafts
from app.features.alerts.realtime import publish_alert_created_from_row
from app.features.alerts.repository import rule_false_positive_rates
from app.features.alerts.rule_registry_runtime import prepare_effective_rules
from app.features.detections.executors import V1RuleExecutor, V2RuleExecutor
from app.features.detections.pipeline import (
    AlertPipeline,
    EnrichmentStage,
    GovernanceStage,
    ScoringStage,
    SuppressionStage,
    build_default_registry,
)
from app.features.detections.repository import get_rule_health_map
from app.features.detections.rules.compiler import _v2_mitre_meta, _v2_resolve_params

from .conditions import _parse_window
from .dedup import _recent_alert_index
from .health import RuleExecResult, _content_hash, emit_detection_metrics, flush_cycle_health
from .heuristics import _emit_heuristic_signals
from .mitre import _extract_mitre_meta
from .suppression import _schedule_allows
from .tuning import _load_agent_context

logger = logging.getLogger("seagull.worker.rules")

_EXECUTORS = (V1RuleExecutor(), V2RuleExecutor())
_ENRICHMENT_REGISTRY = build_default_registry()


def _health(rule: Dict[str, Any], duration_ms: int, **kw) -> RuleExecResult:
    return RuleExecResult(
        rule_id=rule.get("id"), rule_version=int(rule.get("rule_version") or 1),
        content_hash=_content_hash(rule), duration_ms=duration_ms, **kw,
    )


def _rule_since_until(rule: Dict[str, Any], now: datetime):
    if int(rule.get("schema_version") or 1) == 2:
        window = _v2_resolve_params(rule)[0]
    else:
        try:
            window = timedelta(seconds=_parse_window(rule.get("window") or "5m"))
        except Exception:
            window = timedelta(minutes=5)
    return now - window, now


def _run_rule(executor, rule, *, db, now, recent_idx, agent_ctx_map, fp_rates):
    since, until = _rule_since_until(rule, now)
    candidates = executor.execute(rule, db=db, since=since, until=until)
    alerts: List[AlertModel] = []
    if int(rule.get("schema_version") or 1) == 2:
        mitre = _v2_mitre_meta(rule)
    else:
        mitre = _extract_mitre_meta(rule)
    if candidates:
        meta = candidates[0].extra
        drafts = AlertPipeline([
            GovernanceStage(recent_idx, agent_ctx_map, now),
            SuppressionStage(meta.get("effective_suppressions") or [], now),
            EnrichmentStage(_ENRICHMENT_REGISTRY),
            ScoringStage(fp_rates, mitre),
        ]).run(candidates, db=db, recent_idx=recent_idx)
        alerts = persist_alert_drafts(db, drafts)
    return alerts, sum(int(c.extra.get("event_count") or c.count_value or 0) for c in candidates)


def run_rules_once():
    now = datetime.utcnow()
    cycle_started = time.perf_counter()
    created_alerts: List[AlertModel] = []
    health_results: List[RuleExecResult] = []

    db = SessionLocal()
    try:
        rules = prepare_effective_rules(db)
        max_cooldown_s = 0
        for rule in rules:
            try:
                max_cooldown_s = max(max_cooldown_s, int(_parse_window(rule.get("cooldown") or "0")))
            except Exception as exc:
                log_event(logger, "warning", "rule_cooldown_parse_error", rule_id=rule.get("id"), error=repr(exc))

        recent_idx = _recent_alert_index(db, timedelta(seconds=max(120, max_cooldown_s)))
        agent_ctx_map = _load_agent_context(db)
        existing_health = get_rule_health_map(db)
        fp_rates = rule_false_positive_rates(db, since=now - timedelta(days=14))

        for rule in rules:
            rule_id = rule.get("id")
            if not rule_id:
                continue
            if not rule.get("enabled", True):
                health_results.append(_health(rule, 0, disabled=True))
                continue
            if not _schedule_allows(rule, now):
                continue
            executor = next((e for e in _EXECUTORS if e.can_execute(rule)), None)
            if executor is None:
                continue

            t_start = time.monotonic()
            try:
                alerts, scanned = _run_rule(executor, rule, db=db, now=now, recent_idx=recent_idx, agent_ctx_map=agent_ctx_map, fp_rates=fp_rates)
                created_alerts.extend(alerts)
                health_results.append(_health(rule, int((time.monotonic() - t_start) * 1000), alerts_created=len(alerts), events_scanned=scanned))
            except Exception as exc:
                log_event(logger, "error", "rule_exec_error", rule_id=rule_id, schema_version=int(rule.get("schema_version") or 1), error=repr(exc))
                health_results.append(_health(rule, int((time.monotonic() - t_start) * 1000), error=exc))

        try:
            _, heuristic_alerts = _emit_heuristic_signals(db, now)
            if heuristic_alerts:
                for al in heuristic_alerts:
                    al.detector_type = "heuristic"
                    db.add(al)
                created_alerts.extend(heuristic_alerts)
        except Exception as exc:
            log_event(logger, "error", "heuristic_signals_error", error=repr(exc))

        if created_alerts:
            try:
                db.flush()
                for alert in created_alerts:
                    for spec in extract_evidence_specs(alert):
                        db.add(AlertEvidenceModel(alert_id=alert.id, **spec))
            except Exception as exc:
                log_event(logger, "error", "evidence_flush_error", error=repr(exc))

        flush_cycle_health(db, health_results, existing_health, now)
        db.commit()
        for alert in created_alerts:
            publish_alert_created_from_row(alert)
    finally:
        db.close()

    emit_detection_metrics(health_results, time.perf_counter() - cycle_started)
    return created_alerts


def run_all_rules():
    return run_rules_once()
