from __future__ import annotations

from datetime import timedelta
from typing import Any, Protocol

from sqlalchemy.orm import Session

from app.features.alerts.models import AlertModel
from app.features.detections.domain.scoring import build_rule_provenance, score_alert_for_endpoints
from app.workers.intelligence.rules.conditions import _evaluate_condition, _extract_alert_key
from app.workers.intelligence.rules.dedup import _recent_alert_last_at
from app.workers.intelligence.rules.suppression import _is_suppressed
from app.workers.intelligence.rules.tuning import (
    _build_rule_context,
    _is_tuning_allowlisted,
    _resolve_tuning_eval,
)

from .enrichment import EnrichmentRegistry
from .types import AlertContext


class PipelineStage(Protocol):
    def process(self, ctx: AlertContext, *, db: Session) -> AlertContext: ...


class GovernanceStage:
    def __init__(self, recent_idx: dict, agent_ctx_map: dict, now: Any) -> None:
        self.recent_idx = recent_idx
        self.agent_ctx_map = agent_ctx_map
        self.now = now

    def process(self, ctx: AlertContext, *, db: Session) -> AlertContext:
        cand = ctx.candidate
        extra = cand.extra
        base_condition = extra.get("base_condition") or {}
        base_severity = str(extra.get("severity") or "low")

        src_ip, dst_ip, dst_port = _extract_alert_key(cand.group_key, cand.match_hints)
        ctx.src_ip, ctx.dst_ip, ctx.dst_port = src_ip, dst_ip, dst_port

        sup_ctx = _build_rule_context(
            group_key=cand.group_key,
            match=cand.match_hints,
            rule_id=cand.rule_id,
            severity=base_severity,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            agent_ctx_map=self.agent_ctx_map,
        )
        eval_cfg = _resolve_tuning_eval(
            cand.rule,
            ctx=sup_ctx,
            base_min_events=int(extra.get("base_min_events") or 0),
            base_condition=base_condition,
            base_cooldown_seconds=int(extra.get("base_cooldown_seconds") or 0),
            base_severity=base_severity,
        )
        eff_min_events = int(eval_cfg.get("min_events") or 0)
        eff_condition = eval_cfg.get("condition") if isinstance(eval_cfg.get("condition"), dict) else base_condition
        eff_cooldown = timedelta(seconds=max(0, int(eval_cfg.get("cooldown_seconds") or 0)))
        eff_severity = str(eval_cfg.get("severity") or base_severity)
        sup_ctx["severity"] = eff_severity

        ctx.eff_min_events = eff_min_events
        ctx.eff_condition = eff_condition
        ctx.eff_cooldown = eff_cooldown
        ctx.eff_severity = eff_severity
        ctx.applied_scopes = list(eval_cfg.get("applied_scopes") or [])
        ctx.rule_context = sup_ctx

        if eff_min_events and cand.min_events_check < eff_min_events:
            ctx.reject("below_min_events")
            return ctx
        if not _evaluate_condition(cand.count_value, eff_condition):
            ctx.reject("condition_not_met")
            return ctx

        last_at = _recent_alert_last_at(self.recent_idx, cand.rule_id, src_ip, dst_ip, dst_port)
        if last_at and eff_cooldown.total_seconds() > 0 and (self.now - last_at) < eff_cooldown:
            ctx.reject("cooldown_active")
            return ctx

        allowlisted, _ = _is_tuning_allowlisted(cand.rule, sup_ctx)
        if allowlisted:
            ctx.reject("allowlisted")
        return ctx


class SuppressionStage:
    def __init__(self, effective_suppressions: list) -> None:
        self.effective_suppressions = list(effective_suppressions or [])

    def process(self, ctx: AlertContext, *, db: Session) -> AlertContext:
        cand = ctx.candidate
        rule_for_sup = {**cand.rule, "suppressions": self.effective_suppressions}
        suppressed, _ = _is_suppressed(rule_for_sup, ctx.rule_context, cand.until)
        if suppressed:
            ctx.reject("suppressed")
        return ctx


class EnrichmentStage:
    def __init__(self, registry: EnrichmentRegistry) -> None:
        self.registry = registry

    def process(self, ctx: AlertContext, *, db: Session) -> AlertContext:
        return self.registry.resolve(ctx, db=db)


class ScoringStage:
    def __init__(self, fp_rates: Any, mitre: dict) -> None:
        self.fp_rates = fp_rates
        self.mitre = mitre or {}

    def process(self, ctx: AlertContext, *, db: Session) -> AlertContext:
        cand = ctx.candidate
        details = build_alert_details(ctx, mitre=self.mitre)
        scored = score_alert_for_endpoints(
            cand.rule, cand.rule_id, ctx.eff_severity, details, src_ip=ctx.src_ip, dst_ip=ctx.dst_ip, fp_rates=self.fp_rates
        )
        ctx.risk_score = scored.risk_score
        ctx.confidence = scored.confidence
        ctx.score_breakdown = scored.breakdown
        return ctx


def build_alert_details(ctx: AlertContext, *, mitre: dict) -> dict[str, Any]:
    cand = ctx.candidate
    extra = cand.extra
    details: dict[str, Any] = {
        "schema_version": int(extra.get("schema_version") or 1),
        "type": extra.get("agg_type"),
        "group_by": list(extra.get("group_by") or []),
        "group_key": cand.group_key,
        "window_seconds": int(extra.get("window_seconds") or 0),
        "enrichment": ctx.enrichment,
        "rule_meta": build_rule_provenance(cand.rule),
    }
    if extra.get("count") is not None:
        details["count"] = extra.get("count")
    if extra.get("distinct_field") is not None:
        details["distinct_field"] = extra.get("distinct_field")
    if extra.get("distinct_count") is not None:
        details["distinct_count"] = extra.get("distinct_count")
    if extra.get("event_count") is not None:
        details["event_count"] = extra.get("event_count")
    if extra.get("distinct_results") is not None:
        details["distinct"] = extra.get("distinct_results")
    if ctx.applied_scopes:
        details["tuning"] = {
            "applied_scopes": list(ctx.applied_scopes),
            "effective_min_events": ctx.eff_min_events,
            "effective_condition": ctx.eff_condition,
            "effective_cooldown_seconds": int(ctx.eff_cooldown.total_seconds()),
            "effective_severity": ctx.eff_severity,
        }
    if ctx.enrichment.get("src_ips"):
        details["src_ips"] = ctx.enrichment["src_ips"]
        details["unique_src_ips"] = ctx.enrichment.get("unique_src_ips", 0)
    if mitre:
        details["mitre"] = mitre
    return details


class AlertFactory:
    @staticmethod
    def build(ctx: AlertContext, *, description: str, mitre: dict, rule_hash: str | None) -> AlertModel:
        cand = ctx.candidate
        details = build_alert_details(ctx, mitre=mitre)
        details["risk_score"] = ctx.risk_score
        details["confidence"] = ctx.confidence
        details["score_breakdown"] = ctx.score_breakdown
        return AlertModel(
            rule_id=cand.rule_id,
            severity=ctx.eff_severity,
            risk_score=ctx.risk_score,
            src_ip=ctx.src_ip,
            dst_ip=ctx.dst_ip,
            dst_port=ctx.dst_port,
            mitre_tactic=mitre.get("tactic"),
            mitre_technique_id=mitre.get("technique_id"),
            mitre_technique=mitre.get("technique"),
            confidence=ctx.confidence,
            description=description,
            details=details,
            detector_type="rule",
            rule_version=int(cand.rule.get("rule_version") or 1),
            rule_hash=rule_hash,
        )
