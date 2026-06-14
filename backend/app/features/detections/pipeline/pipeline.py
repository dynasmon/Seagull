from __future__ import annotations

from sqlalchemy.orm import Session

from app.features.alerts.models import AlertModel
from app.workers.intelligence.rules.dedup import _index_add

from .stages import AlertFactory, PipelineStage
from .types import AlertCandidate, AlertContext


class AlertPipeline:
    def __init__(self, stages: list[PipelineStage]) -> None:
        self.stages = list(stages)

    def run(self, candidates: list[AlertCandidate], *, db: Session, recent_idx: dict) -> list[AlertModel]:
        results: list[AlertModel] = []
        for candidate in candidates:
            ctx = AlertContext(candidate=candidate)
            for stage in self.stages:
                ctx = stage.process(ctx, db=db)
                if ctx.rejected:
                    break
            if ctx.rejected:
                continue

            extra = candidate.extra
            alert = AlertFactory.build(
                ctx,
                description=str(extra.get("description") or ""),
                mitre=extra.get("mitre") or {},
                rule_hash=extra.get("rule_hash"),
            )
            db.add(alert)
            _index_add(recent_idx, candidate.rule_id, ctx.src_ip, ctx.dst_ip, ctx.dst_port)
            results.append(alert)
        return results
