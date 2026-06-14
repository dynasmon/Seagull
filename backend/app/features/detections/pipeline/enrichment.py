from __future__ import annotations

from typing import Any, Protocol

from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from app.features.events.worker_runtime import NetEventModel
from app.workers.intelligence.rules.conditions import _build_match_filters, _extract_alert_key

from .types import AlertContext


class AlertEnricher(Protocol):
    def matches(self, rule_id: str, rule: dict) -> bool: ...

    def enrich(self, ctx: AlertContext, *, db: Session) -> AlertContext: ...


class DDoSEnricher:
    def matches(self, rule_id: str, rule: dict) -> bool:
        return str(rule_id or "").startswith(("ddos_", "dos_", "l7_"))

    def enrich(self, ctx: AlertContext, *, db: Session) -> AlertContext:
        cand = ctx.candidate
        match = cand.match_hints or {}
        group_key = cand.group_key or {}
        since = cand.since
        until = cand.until
        src_ip, dst_ip, dst_port = _extract_alert_key(group_key, match)
        enrichment: dict[str, Any] = {}

        dst = group_key.get("dst_ip") or dst_ip
        if dst:
            filters = _build_match_filters(match, since, until)
            filters.append(NetEventModel.dst_ip == dst)

            gp_port = group_key.get("dst_port") or dst_port
            if gp_port is not None:
                try:
                    filters.append(NetEventModel.dst_port == int(gp_port))
                except Exception:
                    pass

            gp_proto = group_key.get("proto")
            if gp_proto:
                filters.append(NetEventModel.proto == str(gp_proto))

            filters.append(NetEventModel.src_ip.is_not(None))

            stmt_top = (
                select(NetEventModel.src_ip, func.count().label("cnt"))
                .where(and_(*filters))
                .group_by(NetEventModel.src_ip)
                .order_by(func.count().desc())
                .limit(10)
            )
            rows = db.execute(stmt_top).all()

            top_list = []
            for r in rows:
                ip = r[0]
                cnt = int(r[1])
                if ip:
                    top_list.append({"ip": ip, "count": cnt})

            if top_list:
                enrichment["src_ips"] = top_list
                enrichment["top_src_ip"] = top_list[0]["ip"]
                enrichment["top_src_count"] = top_list[0]["count"]

                if src_ip is None or src_ip == "":
                    src_ip = top_list[0]["ip"]
                    enrichment["src_ip"] = "top_src_ip"

            stmt_uniq = select(func.count(func.distinct(NetEventModel.src_ip))).where(and_(*filters))
            uniq = db.execute(stmt_uniq).scalar() or 0
            enrichment["unique_src_ips"] = int(uniq)

        ctx.src_ip = src_ip
        ctx.dst_ip = dst_ip
        ctx.dst_port = dst_port
        ctx.enrichment = enrichment
        return ctx


class SSHBruteforceEnricher:
    def matches(self, rule_id: str, rule: dict) -> bool:
        return str(rule_id or "").startswith("ssh_bruteforce_")

    def enrich(self, ctx: AlertContext, *, db: Session) -> AlertContext:
        cand = ctx.candidate
        match = cand.match_hints or {}
        group_key = cand.group_key or {}
        src_ip, dst_ip, dst_port = _extract_alert_key(group_key, match)
        enrichment: dict[str, Any] = {}

        if dst_ip is None or dst_ip == "":
            src = group_key.get("src_ip") or src_ip
            if src:
                filters = _build_match_filters(match, cand.since, cand.until)
                filters.append(NetEventModel.src_ip == src)
                filters.append(NetEventModel.dst_ip.is_not(None))

                stmt = (
                    select(NetEventModel.dst_ip)
                    .where(and_(*filters))
                    .order_by(NetEventModel.timestamp.desc())
                    .limit(1)
                )

                row = db.execute(stmt).first()
                if row and row[0]:
                    dst_ip = row[0]
                    enrichment["dst_ip"] = "latest_dst_ip"

        ctx.src_ip = src_ip
        ctx.dst_ip = dst_ip
        ctx.dst_port = dst_port
        ctx.enrichment = enrichment
        return ctx


class DefaultEnricher:
    def matches(self, rule_id: str, rule: dict) -> bool:
        return True

    def enrich(self, ctx: AlertContext, *, db: Session) -> AlertContext:
        cand = ctx.candidate
        src_ip, dst_ip, dst_port = _extract_alert_key(cand.group_key or {}, cand.match_hints or {})
        ctx.src_ip = src_ip
        ctx.dst_ip = dst_ip
        ctx.dst_port = dst_port
        return ctx


class EnrichmentRegistry:
    def __init__(self) -> None:
        self._enrichers: list[AlertEnricher] = []

    def register(self, enricher: AlertEnricher) -> None:
        self._enrichers.append(enricher)

    def resolve(self, ctx: AlertContext, *, db: Session) -> AlertContext:
        cand = ctx.candidate
        for enricher in self._enrichers:
            if enricher.matches(cand.rule_id, cand.rule):
                return enricher.enrich(ctx, db=db)
        src_ip, dst_ip, dst_port = _extract_alert_key(cand.group_key or {}, cand.match_hints or {})
        ctx.src_ip = src_ip
        ctx.dst_ip = dst_ip
        ctx.dst_port = dst_port
        return ctx


def build_default_registry() -> EnrichmentRegistry:
    registry = EnrichmentRegistry()
    registry.register(DDoSEnricher())
    registry.register(SSHBruteforceEnricher())
    registry.register(DefaultEnricher())
    return registry
