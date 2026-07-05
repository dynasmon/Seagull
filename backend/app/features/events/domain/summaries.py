from __future__ import annotations

import logging
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import HTTPException
from sqlalchemy import Integer, String, cast, func, or_, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.integrations.clickhouse import (
    clickhouse_events_table_ref,
    clickhouse_mv_covers_window,
    clickhouse_mvs_read_enabled,
    clickhouse_proto_intel_overview_table_ref,
    clickhouse_proto_intel_table_ref,
    clickhouse_ssh_ip_1h_table_ref,
    get_clickhouse_client_new,
    ssh_action_totals_1h_read_sql,
    ssh_source_ips_1h_read_sql,
    ssh_top_ips_1h_read_sql,
    ssh_top_users_1h_read_sql,
    ssh_unique_ips_1h_read_sql,
)
from app.core.integrations.es import search_backend_mode
from app.core.observability import incr_counter, log_event, observe_hist
from app.features.events import repository
from app.features.events.domain.cache import _cache_get_json, _cache_set_json
from app.features.events.domain.filters import _ch_where, _es_base_filters
from app.features.events.domain.normalizers import (
    _freshness_seconds,
    _guess_app_protocols_from_port_counts,
    _meta,
    _now_utc,
    _parse_iso_dt,
    _parse_iso_dt_or_none,
)
from app.features.events.domain.queries import (
    _ch_client_or_none,
    _ch_deduped_events_source_sql,
    _ch_query_dicts,
    _ch_top_counts,
    _es_client_or_none,
    _es_failover_allowed,
    _es_index_pattern,
    _missing_protocol_summary_field,
    _pg_has_newer_event,
    _pg_has_protocol_metadata,
    _pg_rollup_l4_snapshot,
)
from app.features.events.models import NetEventModel
from app.features.events.schemas import (
    ProtocolIntelSummaryResponse,
    ProtoCount,
    ProtoDnsQueryStat,
    ProtoJa4Stat,
    SshAuthEvent,
    SshIpStat,
    SshLoginEvent,
    SshSummaryResponse,
    SshUserStat,
    SudoEventSummary,
)
from app.shared.enrichment.models import IpEnrichmentCacheModel
from app.shared.indexing.watermark import (
    clickhouse_watermark_lag_seconds,
    read_proto_intel_materialization_floor,
)
from app.shared.network.ip_classification import classify_ip

logger = logging.getLogger("seagull.api.events")


def _ssh_geo_value_present(value: Any) -> bool:
    if value is None:
        return False
    return bool(str(value).strip())


def _load_ssh_geo_cache(db: Session, ips: set[str]) -> dict[str, dict[str, str | None]]:
    clean_ips = sorted({str(ip).strip() for ip in ips if str(ip).strip()})
    if not clean_ips:
        return {}
    rows = (
        db.execute(
            select(
                IpEnrichmentCacheModel.ip,
                IpEnrichmentCacheModel.country,
                IpEnrichmentCacheModel.org,
                IpEnrichmentCacheModel.asn,
                IpEnrichmentCacheModel.asn_org,
            )
            .where(IpEnrichmentCacheModel.ip.in_(clean_ips))
            .where(or_(IpEnrichmentCacheModel.expires_at.is_(None), IpEnrichmentCacheModel.expires_at > _now_utc()))
        )
        .mappings()
        .all()
    )
    out: dict[str, dict[str, str | None]] = {}
    for row in rows:
        rec = {
            "geo_country": row.get("country"),
            "geo_org": row.get("org"),
            "asn": row.get("asn"),
            "asn_org": row.get("asn_org"),
        }
        if any(_ssh_geo_value_present(value) for value in rec.values()):
            out[str(row["ip"])] = rec
    return out


def _overlay_ssh_geo_from_cache(
    db: Session,
    payload: SshSummaryResponse,
    *,
    source_ips: set[str] | None = None,
) -> None:
    groups = [
        payload.recent_auth_events,
        payload.successful_logins,
        payload.failed_attempts,
        payload.invalid_user_attempts,
        payload.most_active_ips,
        payload.root_logins,
    ]
    ips = set(source_ips or set())
    for group in groups:
        for item in group:
            src_ip = getattr(item, "src_ip", None)
            if src_ip:
                ips.add(str(src_ip))
    cache = _load_ssh_geo_cache(db, ips)
    if not cache:
        return
    for group in groups:
        for item in group:
            rec = cache.get(str(getattr(item, "src_ip", "") or ""))
            if not rec:
                continue
            for field, value in rec.items():
                if _ssh_geo_value_present(value) and not _ssh_geo_value_present(getattr(item, field, None)):
                    setattr(item, field, value)
    count_base = source_ips if source_ips is not None else ips
    cached_enriched = sum(1 for ip in count_base if ip in cache)
    payload.enriched_source_ips = max(int(payload.enriched_source_ips or 0), cached_enriched)


def _overlay_ip_classification(payload: SshSummaryResponse) -> None:
    groups = [
        payload.recent_auth_events,
        payload.successful_logins,
        payload.failed_attempts,
        payload.invalid_user_attempts,
        payload.most_active_ips,
        payload.root_logins,
    ]
    seen: dict[str, dict] = {}
    for group in groups:
        for item in group:
            src_ip = getattr(item, "src_ip", None)
            if not src_ip:
                continue
            ip_str = str(src_ip)
            if ip_str not in seen:
                seen[ip_str] = classify_ip(ip_str)
            cls = seen[ip_str]
            item.src_ip_scope = cls["scope"]
            item.src_ip_label = cls["label"]
            item.src_is_internal = cls["is_internal"]
            item.src_is_public = cls["is_public"]


_SSH_MV_MIN_WINDOW_MINUTES = 360
_SSH_TRACKED_ACTIONS: tuple[str, ...] = ("accepted", "failed_password", "invalid_user")
_SSH_FAILED_ACTIONS: tuple[str, ...] = ("failed_password", "invalid_user")


def _ch_query_fresh_client(sql: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    client = get_clickhouse_client_new()
    try:
        return _ch_query_dicts(client, sql, params)
    finally:
        try:
            client.close()
        except Exception:
            pass


def _ssh_recent_auth_sql(source_sql: str, limit: int) -> str:
    return (
        "SELECT timestamp, agent_id, ifNull(ssh_action, '') AS action, src_ip, "
        "ifNull(ssh_username, '') AS username, "
        "JSONExtractString(extra_json, 'geo_country') AS geo_country, "
        "JSONExtractString(extra_json, 'geo_org') AS geo_org, "
        "JSONExtractString(extra_json, 'asn') AS asn, "
        "JSONExtractString(extra_json, 'asn_org') AS asn_org "
        f"FROM ({source_sql}) "
        "WHERE ifNull(ssh_action, '') IN ('accepted','failed_password','invalid_user') "
        "ORDER BY timestamp DESC "
        f"LIMIT {int(limit)}"
    )


def _ssh_root_logins_sql(source_sql: str, limit: int) -> str:
    return (
        "SELECT timestamp, agent_id, src_ip, "
        "ifNull(ssh_username, '') AS username, "
        "JSONExtractString(extra_json, 'geo_country') AS geo_country, "
        "JSONExtractString(extra_json, 'geo_org') AS geo_org, "
        "JSONExtractString(extra_json, 'asn') AS asn, "
        "JSONExtractString(extra_json, 'asn_org') AS asn_org "
        f"FROM ({source_sql}) "
        "WHERE ifNull(ssh_action, '') = 'accepted' "
        "AND ifNull(ssh_username, '') = 'root' "
        "ORDER BY timestamp DESC "
        f"LIMIT {int(limit)}"
    )


def _ssh_sudo_recent_sql(source_sql: str, limit: int) -> str:
    return (
        "SELECT timestamp, agent_id, "
        "sudo_username AS username, "
        "sudo_target_user AS target_user, "
        "sudo_command AS command, "
        "sudo_tty AS tty, "
        "JSONExtractString(extra_json, 'pwd') AS pwd "
        f"FROM ({source_sql}) "
        "ORDER BY timestamp DESC "
        f"LIMIT {int(limit)}"
    )


def _mv_ssh_summary(
    db: Session,
    *,
    since_minutes: int,
    limit: int,
    agent_id: Optional[str],
    cache_key: str,
    started: float,
    query_end: datetime,
    since_ts: datetime,
) -> Optional[SshSummaryResponse]:
    ch = _ch_client_or_none()
    if ch is None:
        return None

    since_bucket = since_ts.replace(minute=0, second=0, microsecond=0)
    if not clickhouse_mv_covers_window(ch, table_ref=clickhouse_ssh_ip_1h_table_ref(), start_ts=since_bucket):
        return None

    try:
        with_agent = bool(agent_id)
        mv_params: dict[str, Any] = {"start_ts": since_bucket}
        table = clickhouse_events_table_ref()
        ssh_where_sql, ssh_params = _ch_where(since=since_ts, agent_id=agent_id, event_type="ssh_auth")
        ssh_source_sql = _ch_deduped_events_source_sql(table=table, where_sql=ssh_where_sql)
        sudo_where_sql, sudo_params = _ch_where(since=since_ts, agent_id=agent_id, event_type="sudo_cmd")
        sudo_source_sql = _ch_deduped_events_source_sql(table=table, where_sql=sudo_where_sql)
        if agent_id:
            mv_params["agent_id"] = agent_id

        def _top_ips_worker(action: str) -> list[SshIpStat]:
            rows = _ch_query_fresh_client(
                ssh_top_ips_1h_read_sql(with_agent=with_agent, actions=(action,), limit=int(limit)),
                mv_params,
            )
            return [SshIpStat(**dict(r)) for r in rows]

        pool_size = max(1, int(getattr(settings, "SEAGULL_CLICKHOUSE_QUERY_POOL_SIZE", 6) or 6))
        with ThreadPoolExecutor(max_workers=pool_size) as executor:
            fut_totals = executor.submit(
                _ch_query_fresh_client,
                ssh_action_totals_1h_read_sql(with_agent=with_agent, actions=_SSH_TRACKED_ACTIONS),
                mv_params,
            )
            fut_uniq = executor.submit(
                _ch_query_fresh_client,
                ssh_unique_ips_1h_read_sql(with_agent=with_agent, actions=_SSH_TRACKED_ACTIONS),
                mv_params,
            )
            fut_recent = executor.submit(_ch_query_fresh_client, _ssh_recent_auth_sql(ssh_source_sql, int(limit)), ssh_params)
            fut_success = executor.submit(_top_ips_worker, "accepted")
            fut_failed = executor.submit(_top_ips_worker, "failed_password")
            fut_invalid = executor.submit(_top_ips_worker, "invalid_user")
            fut_active = executor.submit(
                _ch_query_fresh_client,
                ssh_top_ips_1h_read_sql(with_agent=with_agent, actions=_SSH_TRACKED_ACTIONS, limit=int(limit)),
                mv_params,
            )
            fut_root = executor.submit(_ch_query_fresh_client, _ssh_root_logins_sql(ssh_source_sql, int(limit)), ssh_params)
            fut_users = executor.submit(
                _ch_query_fresh_client,
                ssh_top_users_1h_read_sql(with_agent=with_agent, actions=_SSH_FAILED_ACTIONS, limit=int(limit)),
                mv_params,
            )
            fut_sudo = executor.submit(_ch_query_fresh_client, _ssh_sudo_recent_sql(sudo_source_sql, int(limit)), sudo_params)
            fut_source_ips = executor.submit(
                _ch_query_fresh_client,
                ssh_source_ips_1h_read_sql(with_agent=with_agent, actions=_SSH_TRACKED_ACTIONS),
                mv_params,
            )

            action_totals = {str(r.get("action") or ""): int(r.get("count") or 0) for r in fut_totals.result()}
            uniq_row = (fut_uniq.result() or [{}])[0]
            recent_auth_events = [SshAuthEvent(**dict(r)) for r in fut_recent.result()]
            successful_logins = fut_success.result()
            failed_attempts = fut_failed.result()
            invalid_user_attempts = fut_invalid.result()
            most_active_ips = [SshIpStat(**dict(r)) for r in fut_active.result()]
            root_logins = [SshLoginEvent(**dict(r)) for r in fut_root.result()]
            users_attempted = [SshUserStat(**dict(r)) for r in fut_users.result()]
            sudo_recent = [SudoEventSummary(**dict(r)) for r in fut_sudo.result()]
            source_ips = {
                str(r.get("src_ip") or "").strip()
                for r in fut_source_ips.result()
                if str(r.get("src_ip") or "").strip()
            }

        total_accepted = int(action_totals.get("accepted", 0))
        total_failed_password = int(action_totals.get("failed_password", 0))
        total_invalid_user = int(action_totals.get("invalid_user", 0))

        payload = SshSummaryResponse(
            generated_at=datetime.now(timezone.utc),
            since_minutes=int(since_minutes),
            agent_id=agent_id,
            total_accepted=total_accepted,
            total_failed_password=total_failed_password,
            total_invalid_user=total_invalid_user,
            total_actions=total_accepted + total_failed_password + total_invalid_user,
            unique_source_ips=int(uniq_row.get("unique_source_ips", 0) or 0),
            enriched_source_ips=int(uniq_row.get("enriched_source_ips", 0) or 0),
            recent_auth_events=recent_auth_events,
            successful_logins=successful_logins,
            failed_attempts=failed_attempts,
            invalid_user_attempts=invalid_user_attempts,
            most_active_ips=most_active_ips,
            root_logins=root_logins,
            users_attempted=users_attempted,
            sudo_recent=sudo_recent,
            meta=_meta(
                source="clickhouse",
                fallback_chain=["clickhouse_mv"],
                degraded_reason=None,
                source_freshness_seconds=_freshness_seconds(
                    query_end,
                    max(
                        ([x.timestamp for x in recent_auth_events] + [x.timestamp for x in sudo_recent])
                        or [None]
                    ),
                ),
                query_latency_ms=(time.perf_counter() - started) * 1000.0,
                cache_hit=False,
                approximate=True,
                query_window_start=since_bucket,
                query_window_end=query_end,
            ),
        )
        _overlay_ssh_geo_from_cache(db, payload, source_ips=source_ips)
        _overlay_ip_classification(payload)
        _cache_set_json(
            cache_key,
            payload.dict(),
            int(getattr(settings, "SEAGULL_EVENTS_SUMMARY_CACHE_TTL_SECONDS", 15) or 15),
        )
        observe_hist(
            "api_route_latency_seconds",
            time.perf_counter() - started,
            route="/events/ssh/summary",
            source="clickhouse",
        )
        return payload
    except Exception as exc:
        log_event(logger, "warning", "events_ssh_summary_mv_error", error_type=type(exc).__name__)
        return None


def get_ssh_summary(
    db: Session,
    *,
    since_minutes: int = 60 * 24,
    limit: int = 50,
    agent_id: Optional[str] = None,
) -> SshSummaryResponse:
    started = time.perf_counter()
    query_end = _now_utc()
    since_ts = query_end - timedelta(minutes=int(since_minutes))
    cache_key = f"seagull:events:ssh_summary:v3:sm={int(since_minutes)}:l={int(limit)}:a={agent_id or '*'}"
    cached = _cache_get_json(cache_key)
    if cached is not None:
        out_cached = dict(cached)
        existing_meta = out_cached.get("meta")
        if isinstance(existing_meta, dict) and str(existing_meta.get("source") or "").strip():
            incr_counter("api_cache_hit_total", route="/events/ssh/summary")
            cached_meta = dict(existing_meta)
            cached_meta["cache_hit"] = True
            cached_meta["query_latency_ms"] = round((time.perf_counter() - started) * 1000.0, 2)
            out_cached["meta"] = cached_meta
            return SshSummaryResponse(**out_cached)

    tracked_actions = ["accepted", "failed_password", "invalid_user"]
    attempted_sources: list[str] = []
    degraded_reason: str | None = None

    if clickhouse_mvs_read_enabled() and int(since_minutes) >= _SSH_MV_MIN_WINDOW_MINUTES:
        mv_payload = _mv_ssh_summary(
            db,
            since_minutes=since_minutes,
            limit=limit,
            agent_id=agent_id,
            cache_key=cache_key,
            started=started,
            query_end=query_end,
            since_ts=since_ts,
        )
        if mv_payload is not None:
            return mv_payload

    ch = _ch_client_or_none()
    if ch is not None:
        attempted_sources.append("clickhouse")
        try:
            table = clickhouse_events_table_ref()
            ssh_where_sql, ssh_params = _ch_where(since=since_ts, agent_id=agent_id, event_type="ssh_auth")
            ssh_source_sql = _ch_deduped_events_source_sql(table=table, where_sql=ssh_where_sql)
            sudo_where_sql, sudo_params = _ch_where(since=since_ts, agent_id=agent_id, event_type="sudo_cmd")
            sudo_source_sql = _ch_deduped_events_source_sql(table=table, where_sql=sudo_where_sql)

            _q = _ch_query_fresh_client

            def _top_ips_worker(action: str) -> list[SshIpStat]:
                sql = (
                    "SELECT src_ip, count() AS count, "
                    "any(JSONExtractString(extra_json, 'geo_country')) AS geo_country, "
                    "any(JSONExtractString(extra_json, 'geo_org')) AS geo_org, "
                    "any(JSONExtractString(extra_json, 'asn')) AS asn, "
                    "any(JSONExtractString(extra_json, 'asn_org')) AS asn_org "
                    f"FROM ({ssh_source_sql}) "
                    "WHERE src_ip IS NOT NULL AND ifNull(ssh_action, '') = {action:String} "
                    "GROUP BY src_ip ORDER BY count DESC "
                    f"LIMIT {int(limit)}"
                )
                rows = _q(sql, {**ssh_params, "action": action})
                return [SshIpStat(**dict(r)) for r in rows]

            totals_sql = (
                "SELECT "
                "countIf(ifNull(ssh_action, '') = 'accepted') AS total_accepted, "
                "countIf(ifNull(ssh_action, '') = 'failed_password') AS total_failed_password, "
                "countIf(ifNull(ssh_action, '') = 'invalid_user') AS total_invalid_user, "
                "uniqExactIf(src_ip, src_ip IS NOT NULL AND ifNull(ssh_action, '') IN ('accepted','failed_password','invalid_user')) AS unique_source_ips, "
                "uniqExactIf(src_ip, src_ip IS NOT NULL AND ifNull(ssh_action, '') IN ('accepted','failed_password','invalid_user') AND ("
                "JSONExtractString(extra_json, 'geo_country') != '' OR "
                "JSONExtractString(extra_json, 'geo_org') != '' OR "
                "JSONExtractString(extra_json, 'asn') != '' OR "
                "JSONExtractString(extra_json, 'asn_org') != '')) AS enriched_source_ips "
                f"FROM ({ssh_source_sql})"
            )
            recent_auth_sql = _ssh_recent_auth_sql(ssh_source_sql, int(limit))
            active_sql = (
                "SELECT src_ip, count() AS count, "
                "any(JSONExtractString(extra_json, 'geo_country')) AS geo_country, "
                "any(JSONExtractString(extra_json, 'geo_org')) AS geo_org, "
                "any(JSONExtractString(extra_json, 'asn')) AS asn, "
                "any(JSONExtractString(extra_json, 'asn_org')) AS asn_org "
                f"FROM ({ssh_source_sql}) "
                "WHERE src_ip IS NOT NULL AND ifNull(ssh_action, '') IN ('accepted','failed_password','invalid_user') "
                "GROUP BY src_ip ORDER BY count DESC "
                f"LIMIT {int(limit)}"
            )
            root_sql = _ssh_root_logins_sql(ssh_source_sql, int(limit))
            users_sql = (
                "SELECT ssh_username AS username, count() AS count "
                f"FROM ({ssh_source_sql}) "
                "WHERE ifNull(ssh_action, '') IN ('failed_password','invalid_user') "
                "AND ifNull(ssh_username, '') != '' "
                "GROUP BY username ORDER BY count DESC "
                f"LIMIT {int(limit)}"
            )
            sudo_sql = _ssh_sudo_recent_sql(sudo_source_sql, int(limit))
            source_ips_sql = (
                "SELECT src_ip "
                f"FROM ({ssh_source_sql}) "
                "WHERE src_ip IS NOT NULL AND ifNull(ssh_action, '') IN ('accepted','failed_password','invalid_user') "
                "GROUP BY src_ip "
                "LIMIT 10000"
            )

            pool_size = max(1, int(getattr(settings, "SEAGULL_CLICKHOUSE_QUERY_POOL_SIZE", 6) or 6))
            with ThreadPoolExecutor(max_workers=pool_size) as executor:
                fut_totals = executor.submit(_q, totals_sql, ssh_params)
                fut_recent = executor.submit(_q, recent_auth_sql, ssh_params)
                fut_success = executor.submit(_top_ips_worker, "accepted")
                fut_failed = executor.submit(_top_ips_worker, "failed_password")
                fut_invalid = executor.submit(_top_ips_worker, "invalid_user")
                fut_active = executor.submit(_q, active_sql, ssh_params)
                fut_root = executor.submit(_q, root_sql, ssh_params)
                fut_users = executor.submit(_q, users_sql, ssh_params)
                fut_sudo = executor.submit(_q, sudo_sql, sudo_params)
                fut_source_ips = executor.submit(_q, source_ips_sql, ssh_params)

                totals_row = (fut_totals.result() or [{}])[0]
                recent_auth_events = [SshAuthEvent(**dict(r)) for r in fut_recent.result()]
                successful_logins = fut_success.result()
                failed_attempts = fut_failed.result()
                invalid_user_attempts = fut_invalid.result()
                most_active_ips = [SshIpStat(**dict(r)) for r in fut_active.result()]
                root_logins = [SshLoginEvent(**dict(r)) for r in fut_root.result()]
                users_attempted = [SshUserStat(**dict(r)) for r in fut_users.result()]
                sudo_recent = [SudoEventSummary(**dict(r)) for r in fut_sudo.result()]
                source_ips = {
                    str(r.get("src_ip") or "").strip()
                    for r in fut_source_ips.result()
                    if str(r.get("src_ip") or "").strip()
                }

            total_accepted = int(totals_row.get("total_accepted", 0) or 0)
            total_failed_password = int(totals_row.get("total_failed_password", 0) or 0)
            total_invalid_user = int(totals_row.get("total_invalid_user", 0) or 0)
            unique_source_ips = int(totals_row.get("unique_source_ips", 0) or 0)
            enriched_source_ips = int(totals_row.get("enriched_source_ips", 0) or 0)

            payload = SshSummaryResponse(
                generated_at=datetime.now(timezone.utc),
                since_minutes=int(since_minutes),
                agent_id=agent_id,
                total_accepted=total_accepted,
                total_failed_password=total_failed_password,
                total_invalid_user=total_invalid_user,
                total_actions=total_accepted + total_failed_password + total_invalid_user,
                unique_source_ips=unique_source_ips,
                enriched_source_ips=enriched_source_ips,
                recent_auth_events=recent_auth_events,
                successful_logins=successful_logins,
                failed_attempts=failed_attempts,
                invalid_user_attempts=invalid_user_attempts,
                most_active_ips=most_active_ips,
                root_logins=root_logins,
                users_attempted=users_attempted,
                sudo_recent=sudo_recent,
                meta=_meta(
                    source="clickhouse",
                    fallback_chain=attempted_sources,
                    degraded_reason=degraded_reason,
                    source_freshness_seconds=_freshness_seconds(
                        query_end,
                        max(
                            ([x.timestamp for x in recent_auth_events] + [x.timestamp for x in sudo_recent])
                            or [None]
                        ),
                    ),
                    query_latency_ms=(time.perf_counter() - started) * 1000.0,
                    cache_hit=False,
                    approximate=False,
                    query_window_start=since_ts,
                    query_window_end=query_end,
                ),
            )
            _overlay_ssh_geo_from_cache(db, payload, source_ips=source_ips)
            _overlay_ip_classification(payload)
            _cache_set_json(
                cache_key,
                payload.dict(),
                int(getattr(settings, "SEAGULL_EVENTS_SUMMARY_CACHE_TTL_SECONDS", 15) or 15),
            )
            observe_hist(
                "api_route_latency_seconds",
                time.perf_counter() - started,
                route="/events/ssh/summary",
                source="clickhouse",
            )
            return payload
        except Exception as exc:
            log_event(logger, "warning", "events_ssh_summary_clickhouse_error", error_type=type(exc).__name__)
            degraded_reason = f"clickhouse_fallback:{type(exc).__name__}"[:200]

    es = _es_client_or_none()
    if es is not None:
        attempted_sources.append("elasticsearch")
        try:
            base = _es_base_filters(since=since_ts, agent_id=agent_id)

            def _top_ips(action: str) -> list[SshIpStat]:
                body = {
                    "size": 0,
                    "query": {
                        "bool": {
                            "filter": base
                            + [
                                {"term": {"event_type": "ssh_auth"}},
                                {"term": {"ssh_action": action}},
                                {"exists": {"field": "src_ip"}},
                            ]
                        }
                    },
                    "aggs": {
                        "ips": {
                            "terms": {"field": "src_ip", "size": int(limit), "order": {"_count": "desc"}},
                            "aggs": {
                                "sample": {
                                    "top_hits": {
                                        "size": 1,
                                        "_source": {"includes": ["geo_country", "geo_org", "asn", "asn_org"]},
                                        "sort": [{"timestamp": {"order": "desc"}}],
                                    }
                                }
                            },
                        }
                    },
                }
                res = es.search(index=_es_index_pattern(), body=body, ignore_unavailable=True, allow_no_indices=True)
                buckets = ((res.get("aggregations") or {}).get("ips") or {}).get("buckets") or []
                out: list[SshIpStat] = []
                for bucket in buckets:
                    sample_hits = (((bucket.get("sample") or {}).get("hits") or {}).get("hits") or [])
                    sample_src = (sample_hits[0].get("_source") if sample_hits else {}) or {}
                    out.append(
                        SshIpStat(
                            src_ip=str(bucket.get("key")),
                            count=int(bucket.get("doc_count", 0) or 0),
                            geo_country=sample_src.get("geo_country"),
                            geo_org=sample_src.get("geo_org"),
                            asn=sample_src.get("asn"),
                            asn_org=sample_src.get("asn_org"),
                        )
                    )
                return out

            totals_body = {
                "size": 0,
                "query": {
                    "bool": {
                        "filter": base + [{"term": {"event_type": "ssh_auth"}}]
                    }
                },
                "aggs": {
                    "total_accepted": {"filter": {"term": {"ssh_action": "accepted"}}},
                    "total_failed_password": {"filter": {"term": {"ssh_action": "failed_password"}}},
                    "total_invalid_user": {"filter": {"term": {"ssh_action": "invalid_user"}}},
                    "unique_source_ips": {
                        "filter": {
                            "bool": {
                                "filter": [
                                    {"terms": {"ssh_action": tracked_actions}},
                                    {"exists": {"field": "src_ip"}},
                                ]
                            }
                        },
                        "aggs": {"value": {"cardinality": {"field": "src_ip"}}},
                    },
                    "enriched_source_ips": {
                        "filter": {
                            "bool": {
                                "filter": [
                                    {"terms": {"ssh_action": tracked_actions}},
                                    {"exists": {"field": "src_ip"}},
                                ],
                                "should": [
                                    {"exists": {"field": "geo_country"}},
                                    {"exists": {"field": "geo_org"}},
                                    {"exists": {"field": "asn"}},
                                    {"exists": {"field": "asn_org"}},
                                ],
                                "minimum_should_match": 1,
                            }
                        },
                        "aggs": {"value": {"cardinality": {"field": "src_ip"}}},
                    },
                },
            }
            totals_res = es.search(index=_es_index_pattern(), body=totals_body, ignore_unavailable=True, allow_no_indices=True)
            aggs = totals_res.get("aggregations") or {}
            total_accepted = int(((aggs.get("total_accepted") or {}).get("doc_count")) or 0)
            total_failed_password = int(((aggs.get("total_failed_password") or {}).get("doc_count")) or 0)
            total_invalid_user = int(((aggs.get("total_invalid_user") or {}).get("doc_count")) or 0)
            unique_source_ips = int((((aggs.get("unique_source_ips") or {}).get("value") or {}).get("value")) or 0)
            enriched_source_ips = int((((aggs.get("enriched_source_ips") or {}).get("value") or {}).get("value")) or 0)

            recent_auth_body = {
                "size": int(limit),
                "sort": [{"timestamp": {"order": "desc"}}, {"id": {"order": "desc"}}],
                "query": {
                    "bool": {
                        "filter": base
                        + [
                            {"term": {"event_type": "ssh_auth"}},
                            {"terms": {"ssh_action": tracked_actions}},
                        ]
                    }
                },
                "_source": {
                    "includes": [
                        "timestamp",
                        "agent_id",
                        "src_ip",
                        "ssh_action",
                        "ssh_username",
                        "geo_country",
                        "geo_org",
                        "asn",
                        "asn_org",
                    ]
                },
            }
            recent_auth_res = es.search(
                index=_es_index_pattern(),
                body=recent_auth_body,
                ignore_unavailable=True,
                allow_no_indices=True,
            )
            recent_auth_events: list[SshAuthEvent] = []
            for hit in ((recent_auth_res.get("hits") or {}).get("hits") or []):
                src = hit.get("_source") or {}
                recent_auth_events.append(
                    SshAuthEvent(
                        timestamp=_parse_iso_dt(src.get("timestamp") if isinstance(src.get("timestamp"), str) else None),
                        agent_id=str(src.get("agent_id") or ""),
                        action=src.get("ssh_action"),
                        src_ip=src.get("src_ip"),
                        username=src.get("ssh_username"),
                        geo_country=src.get("geo_country"),
                        geo_org=src.get("geo_org"),
                        asn=src.get("asn"),
                        asn_org=src.get("asn_org"),
                    )
                )

            successful_logins = _top_ips("accepted")
            failed_attempts = _top_ips("failed_password")
            invalid_user_attempts = _top_ips("invalid_user")

            body = {
                "size": 0,
                "query": {
                    "bool": {
                        "filter": base
                        + [
                            {"term": {"event_type": "ssh_auth"}},
                            {"terms": {"ssh_action": tracked_actions}},
                            {"exists": {"field": "src_ip"}},
                        ]
                    }
                },
                "aggs": {
                    "ips": {
                        "terms": {"field": "src_ip", "size": int(limit), "order": {"_count": "desc"}},
                        "aggs": {
                            "sample": {
                                "top_hits": {
                                    "size": 1,
                                    "_source": {"includes": ["geo_country", "geo_org", "asn", "asn_org"]},
                                    "sort": [{"timestamp": {"order": "desc"}}],
                                }
                            }
                        },
                    }
                },
            }
            res = es.search(index=_es_index_pattern(), body=body, ignore_unavailable=True, allow_no_indices=True)
            buckets = ((res.get("aggregations") or {}).get("ips") or {}).get("buckets") or []
            most_active_ips: list[SshIpStat] = []
            for bucket in buckets:
                sample_hits = (((bucket.get("sample") or {}).get("hits") or {}).get("hits") or [])
                sample_src = (sample_hits[0].get("_source") if sample_hits else {}) or {}
                most_active_ips.append(
                    SshIpStat(
                        src_ip=str(bucket.get("key")),
                        count=int(bucket.get("doc_count", 0) or 0),
                        geo_country=sample_src.get("geo_country"),
                        geo_org=sample_src.get("geo_org"),
                        asn=sample_src.get("asn"),
                        asn_org=sample_src.get("asn_org"),
                    )
                )

            body = {
                "size": int(limit),
                "sort": [{"timestamp": {"order": "desc"}}, {"id": {"order": "desc"}}],
                "query": {
                    "bool": {
                        "filter": base
                        + [
                            {"term": {"event_type": "ssh_auth"}},
                            {"term": {"ssh_action": "accepted"}},
                            {"term": {"ssh_username": "root"}},
                        ]
                    }
                },
                "_source": {
                    "includes": [
                        "timestamp",
                        "agent_id",
                        "src_ip",
                        "ssh_username",
                        "geo_country",
                        "geo_org",
                        "asn",
                        "asn_org",
                    ]
                },
            }
            res = es.search(index=_es_index_pattern(), body=body, ignore_unavailable=True, allow_no_indices=True)
            root_logins: list[SshLoginEvent] = []
            for hit in ((res.get("hits") or {}).get("hits") or []):
                src = hit.get("_source") or {}
                root_logins.append(
                    SshLoginEvent(
                        timestamp=_parse_iso_dt(src.get("timestamp") if isinstance(src.get("timestamp"), str) else None),
                        agent_id=str(src.get("agent_id") or ""),
                        src_ip=src.get("src_ip"),
                        username=src.get("ssh_username"),
                        geo_country=src.get("geo_country"),
                        geo_org=src.get("geo_org"),
                        asn=src.get("asn"),
                        asn_org=src.get("asn_org"),
                    )
                )

            body = {
                "size": 0,
                "query": {
                    "bool": {
                        "filter": base
                        + [
                            {"term": {"event_type": "ssh_auth"}},
                            {"terms": {"ssh_action": ["failed_password", "invalid_user"]}},
                            {"exists": {"field": "ssh_username"}},
                        ]
                    }
                },
                "aggs": {
                    "users": {
                        "terms": {"field": "ssh_username", "size": int(limit), "order": {"_count": "desc"}}
                    }
                },
            }
            res = es.search(index=_es_index_pattern(), body=body, ignore_unavailable=True, allow_no_indices=True)
            buckets = ((res.get("aggregations") or {}).get("users") or {}).get("buckets") or []
            users_attempted = [
                SshUserStat(username=str(bucket.get("key")), count=int(bucket.get("doc_count", 0) or 0))
                for bucket in buckets
            ]

            body = {
                "size": int(limit),
                "sort": [{"timestamp": {"order": "desc"}}, {"id": {"order": "desc"}}],
                "query": {
                    "bool": {
                        "filter": base + [{"term": {"event_type": "sudo_cmd"}}]
                    }
                },
                "_source": {
                    "includes": [
                        "timestamp",
                        "agent_id",
                        "sudo_username",
                        "sudo_target_user",
                        "sudo_command",
                        "sudo_tty",
                        "sudo_pwd",
                    ]
                },
            }
            res = es.search(index=_es_index_pattern(), body=body, ignore_unavailable=True, allow_no_indices=True)
            sudo_recent: list[SudoEventSummary] = []
            for hit in ((res.get("hits") or {}).get("hits") or []):
                src = hit.get("_source") or {}
                sudo_recent.append(
                    SudoEventSummary(
                        timestamp=_parse_iso_dt(src.get("timestamp") if isinstance(src.get("timestamp"), str) else None),
                        agent_id=str(src.get("agent_id") or ""),
                        username=src.get("sudo_username"),
                        target_user=src.get("sudo_target_user"),
                        command=src.get("sudo_command"),
                        tty=src.get("sudo_tty"),
                        pwd=src.get("sudo_pwd"),
                    )
                )

            payload = SshSummaryResponse(
                generated_at=datetime.now(timezone.utc),
                since_minutes=int(since_minutes),
                agent_id=agent_id,
                total_accepted=total_accepted,
                total_failed_password=total_failed_password,
                total_invalid_user=total_invalid_user,
                total_actions=total_accepted + total_failed_password + total_invalid_user,
                unique_source_ips=unique_source_ips,
                enriched_source_ips=enriched_source_ips,
                recent_auth_events=recent_auth_events,
                successful_logins=successful_logins,
                failed_attempts=failed_attempts,
                invalid_user_attempts=invalid_user_attempts,
                most_active_ips=most_active_ips,
                root_logins=root_logins,
                users_attempted=users_attempted,
                sudo_recent=sudo_recent,
                meta=_meta(
                    source="elasticsearch",
                    fallback_chain=attempted_sources,
                    degraded_reason=degraded_reason,
                    source_freshness_seconds=_freshness_seconds(
                        query_end,
                        max(
                            ([x.timestamp for x in recent_auth_events] + [x.timestamp for x in sudo_recent])
                            or [None]
                        ),
                    ),
                    query_latency_ms=(time.perf_counter() - started) * 1000.0,
                    cache_hit=False,
                    approximate=False,
                    query_window_start=since_ts,
                    query_window_end=query_end,
                ),
            )
            _overlay_ip_classification(payload)
            _cache_set_json(
                cache_key,
                payload.dict(),
                int(getattr(settings, "SEAGULL_EVENTS_SUMMARY_CACHE_TTL_SECONDS", 15) or 15),
            )
            observe_hist(
                "api_route_latency_seconds",
                time.perf_counter() - started,
                route="/events/ssh/summary",
                source="elasticsearch",
            )
            return payload
        except Exception as exc:
            if not _es_failover_allowed():
                raise HTTPException(status_code=503, detail=f"Elasticsearch error: {type(exc).__name__}") from None
            degraded_reason = f"elasticsearch_fallback:{type(exc).__name__}"[:200]

    attempted_sources.append("postgres")

    ssh_action = func.coalesce(NetEventModel.ssh_action, NetEventModel.extra["action"].astext)
    ssh_user = func.coalesce(NetEventModel.ssh_username, NetEventModel.extra["username"].astext)
    geo_country = NetEventModel.extra["geo_country"].astext
    geo_org = NetEventModel.extra["geo_org"].astext
    asn = NetEventModel.extra["asn"].astext
    asn_org = NetEventModel.extra["asn_org"].astext
    has_enrichment = or_(
        func.coalesce(geo_country, "") != "",
        func.coalesce(geo_org, "") != "",
        func.coalesce(asn, "") != "",
        func.coalesce(asn_org, "") != "",
    )

    def _top_ips(action: str) -> list[SshIpStat]:
        stmt = (
            select(
                NetEventModel.src_ip.label("src_ip"),
                func.count().label("count"),
                func.max(geo_country).label("geo_country"),
                func.max(geo_org).label("geo_org"),
                func.max(asn).label("asn"),
                func.max(asn_org).label("asn_org"),
            )
            .where(
                NetEventModel.event_type == "ssh_auth",
                ssh_action == action,
                NetEventModel.timestamp >= since_ts,
                NetEventModel.src_ip.is_not(None),
            )
            .group_by(NetEventModel.src_ip)
            .order_by(func.count().desc())
            .limit(int(limit))
        )
        if agent_id:
            stmt = stmt.where(NetEventModel.agent_id == agent_id)
        rows = repository.run(db, stmt).mappings().all()
        return [SshIpStat(**dict(r)) for r in rows]

    totals_stmt = (
        select(
            func.count().filter(ssh_action == "accepted").label("total_accepted"),
            func.count().filter(ssh_action == "failed_password").label("total_failed_password"),
            func.count().filter(ssh_action == "invalid_user").label("total_invalid_user"),
            func.count(func.distinct(NetEventModel.src_ip))
            .filter(
                NetEventModel.src_ip.is_not(None),
                ssh_action.in_(tracked_actions),
            )
            .label("unique_source_ips"),
            func.count(func.distinct(NetEventModel.src_ip))
            .filter(
                NetEventModel.src_ip.is_not(None),
                ssh_action.in_(tracked_actions),
                has_enrichment,
            )
            .label("enriched_source_ips"),
        )
        .where(
            NetEventModel.event_type == "ssh_auth",
            NetEventModel.timestamp >= since_ts,
        )
    )
    if agent_id:
        totals_stmt = totals_stmt.where(NetEventModel.agent_id == agent_id)
    totals_row = repository.run(db, totals_stmt).mappings().one()
    total_accepted = int(totals_row.get("total_accepted", 0) or 0)
    total_failed_password = int(totals_row.get("total_failed_password", 0) or 0)
    total_invalid_user = int(totals_row.get("total_invalid_user", 0) or 0)
    unique_source_ips = int(totals_row.get("unique_source_ips", 0) or 0)
    enriched_source_ips = int(totals_row.get("enriched_source_ips", 0) or 0)

    recent_stmt = (
        select(
            NetEventModel.timestamp.label("timestamp"),
            NetEventModel.agent_id.label("agent_id"),
            ssh_action.label("action"),
            NetEventModel.src_ip.label("src_ip"),
            ssh_user.label("username"),
            geo_country.label("geo_country"),
            geo_org.label("geo_org"),
            asn.label("asn"),
            asn_org.label("asn_org"),
        )
        .where(
            NetEventModel.event_type == "ssh_auth",
            ssh_action.in_(tracked_actions),
            NetEventModel.timestamp >= since_ts,
        )
        .order_by(NetEventModel.timestamp.desc(), NetEventModel.id.desc())
        .limit(int(limit))
    )
    if agent_id:
        recent_stmt = recent_stmt.where(NetEventModel.agent_id == agent_id)
    recent_auth_events = [SshAuthEvent(**dict(r)) for r in repository.run(db, recent_stmt).mappings().all()]

    successful_logins = _top_ips("accepted")
    failed_attempts = _top_ips("failed_password")
    invalid_user_attempts = _top_ips("invalid_user")

    stmt = (
        select(
            NetEventModel.src_ip.label("src_ip"),
            func.count().label("count"),
            func.max(geo_country).label("geo_country"),
            func.max(geo_org).label("geo_org"),
            func.max(asn).label("asn"),
            func.max(asn_org).label("asn_org"),
        )
        .where(
            NetEventModel.event_type == "ssh_auth",
            ssh_action.in_(tracked_actions),
            NetEventModel.timestamp >= since_ts,
            NetEventModel.src_ip.is_not(None),
        )
        .group_by(NetEventModel.src_ip)
        .order_by(func.count().desc())
        .limit(int(limit))
    )
    if agent_id:
        stmt = stmt.where(NetEventModel.agent_id == agent_id)
    rows = repository.run(db, stmt).mappings().all()
    most_active_ips = [SshIpStat(**dict(r)) for r in rows]

    stmt = (
        select(
            NetEventModel.timestamp.label("timestamp"),
            NetEventModel.agent_id.label("agent_id"),
            NetEventModel.src_ip.label("src_ip"),
            ssh_user.label("username"),
            geo_country.label("geo_country"),
            geo_org.label("geo_org"),
            asn.label("asn"),
            asn_org.label("asn_org"),
        )
        .where(
            NetEventModel.event_type == "ssh_auth",
            ssh_action == "accepted",
            ssh_user == "root",
            NetEventModel.timestamp >= since_ts,
        )
        .order_by(NetEventModel.timestamp.desc())
        .limit(int(limit))
    )
    if agent_id:
        stmt = stmt.where(NetEventModel.agent_id == agent_id)
    rows = repository.run(db, stmt).mappings().all()
    root_logins = [SshLoginEvent(**dict(r)) for r in rows]

    stmt = (
        select(
            ssh_user.label("username"),
            func.count().label("count"),
        )
        .where(
            NetEventModel.event_type == "ssh_auth",
            ssh_action.in_(["failed_password", "invalid_user"]),
            NetEventModel.timestamp >= since_ts,
            ssh_user.is_not(None),
        )
        .group_by(ssh_user)
        .order_by(func.count().desc())
        .limit(int(limit))
    )
    if agent_id:
        stmt = stmt.where(NetEventModel.agent_id == agent_id)
    rows = repository.run(db, stmt).mappings().all()
    users_attempted = [SshUserStat(**dict(r)) for r in rows]

    stmt = (
        select(
            NetEventModel.timestamp.label("timestamp"),
            NetEventModel.agent_id.label("agent_id"),
            ssh_user.label("username"),
            NetEventModel.extra["target_user"].astext.label("target_user"),
            NetEventModel.extra["command"].astext.label("command"),
            NetEventModel.extra["tty"].astext.label("tty"),
            NetEventModel.extra["pwd"].astext.label("pwd"),
        )
        .where(
            NetEventModel.event_type == "sudo_cmd",
            NetEventModel.timestamp >= since_ts,
        )
        .order_by(NetEventModel.timestamp.desc())
        .limit(int(limit))
    )
    if agent_id:
        stmt = stmt.where(NetEventModel.agent_id == agent_id)
    rows = repository.run(db, stmt).mappings().all()
    sudo_recent = [SudoEventSummary(**dict(r)) for r in rows]

    payload = SshSummaryResponse(
        generated_at=datetime.now(timezone.utc),
        since_minutes=int(since_minutes),
        agent_id=agent_id,
        total_accepted=total_accepted,
        total_failed_password=total_failed_password,
        total_invalid_user=total_invalid_user,
        total_actions=total_accepted + total_failed_password + total_invalid_user,
        unique_source_ips=unique_source_ips,
        enriched_source_ips=enriched_source_ips,
        recent_auth_events=recent_auth_events,
        successful_logins=successful_logins,
        failed_attempts=failed_attempts,
        invalid_user_attempts=invalid_user_attempts,
        most_active_ips=most_active_ips,
        root_logins=root_logins,
        users_attempted=users_attempted,
        sudo_recent=sudo_recent,
        meta=_meta(
            source="postgres",
            fallback_chain=attempted_sources,
            degraded_reason=degraded_reason,
            source_freshness_seconds=_freshness_seconds(
                query_end,
                max(
                    ([x.timestamp for x in recent_auth_events] + [x.timestamp for x in sudo_recent])
                    or [None]
                ),
            ),
            query_latency_ms=(time.perf_counter() - started) * 1000.0,
            cache_hit=False,
            approximate=False,
            query_window_start=since_ts,
            query_window_end=query_end,
        ),
    )
    _overlay_ip_classification(payload)
    _cache_set_json(
        cache_key,
        payload.dict(),
        int(getattr(settings, "SEAGULL_EVENTS_SUMMARY_CACHE_TTL_SECONDS", 15) or 15),
    )
    observe_hist(
        "api_route_latency_seconds",
        time.perf_counter() - started,
        route="/events/ssh/summary",
        source="postgres",
    )
    return payload


def get_protocol_intel_summary(
    db: Session,
    *,
    since_minutes: int = 60 * 12,
    limit: int = 25,
    agent_id: Optional[str] = None,
) -> ProtocolIntelSummaryResponse:
    started = time.perf_counter()
    query_end = _now_utc()
    since_ts = query_end - timedelta(minutes=int(since_minutes))
    cache_key = (
        "seagull:events:network_summary:v4:"
        f"sb={search_backend_mode()}:sm={int(since_minutes)}:l={int(limit)}:a={agent_id or '*'}"
    )
    cached = _cache_get_json(cache_key)
    if cached is not None:
        out_cached = dict(cached)
        existing_meta = out_cached.get("meta")
        if isinstance(existing_meta, dict) and str(existing_meta.get("source") or "").strip():
            incr_counter("api_cache_hit_total", route="/events/network/summary")
            cached_meta = dict(existing_meta)
            cached_meta["cache_hit"] = True
            cached_meta["query_latency_ms"] = round((time.perf_counter() - started) * 1000.0, 2)
            out_cached["meta"] = cached_meta
            return ProtocolIntelSummaryResponse(**out_cached)

    attempted_sources: list[str] = []
    degraded_reason: str | None = None

    ch = _ch_client_or_none()
    if ch is not None:
        attempted_sources.append("clickhouse")
        try:
            table = clickhouse_events_table_ref()
            where_sql, params = _ch_where(since=since_ts, agent_id=agent_id)
            dedup_source_sql = _ch_deduped_events_source_sql(table=table, where_sql=where_sql)

            overview_sql = (
                "SELECT "
                "count() AS total_events, "
                "countIf("
                "ifNull(d.app_proto, '') != '' OR "
                "ifNull(d.dns_qname, '') != '' OR "
                "ifNull(d.http_host, '') != '' OR "
                "ifNull(d.http_method, '') != '' OR "
                "ifNull(d.ja4, '') != '' OR "
                "ifNull(d.ja3, '') != '' OR "
                "ifNull(d.tls_sni, '') != ''"
                ") AS with_proto_metadata, "
                "countIf(ifNull(d.dns_qname, '') != '') AS dns_events, "
                "countIf(ifNull(d.http_host, '') != '' OR ifNull(d.http_method, '') != '') AS http_events, "
                "countIf(ifNull(d.ja4, '') != '' OR ifNull(d.ja3, '') != '' OR ifNull(d.tls_sni, '') != '') AS tls_events "
                f"FROM ({dedup_source_sql}) AS d"
            )
            ov = (_ch_query_dicts(ch, overview_sql, params) or [{}])[0]
            ch_total_events = int(ov.get("total_events") or 0)
            if ch_total_events <= 0:
                raise LookupError("clickhouse_empty")
            if int(ov.get("with_proto_metadata") or 0) <= 0 and _pg_has_protocol_metadata(
                db,
                since=since_ts,
                agent_id=agent_id,
            ):
                raise LookupError("clickhouse_proto_metadata_stale")

            last_ts_sql = f"SELECT max(timestamp) AS last_ts FROM ({dedup_source_sql}) AS d"
            last_ts_row = (_ch_query_dicts(ch, last_ts_sql, params) or [{}])[0]
            ch_last_ts = _parse_iso_dt_or_none(last_ts_row.get("last_ts"))
            if ch_last_ts is None:
                raise LookupError("clickhouse_no_last_ts")
            if _pg_has_newer_event(db, latest_ts=ch_last_ts, agent_id=agent_id):
                raise LookupError("clickhouse_stale")

            app_protocols = _ch_top_counts(
                ch,
                source_sql=dedup_source_sql,
                params=params,
                key_expr="ifNull(d.app_proto, '')",
                limit=int(limit),
            )
            transport_protocols = _ch_top_counts(
                ch,
                source_sql=dedup_source_sql,
                params=params,
                key_expr="lowerUTF8(ifNull(d.proto, ''))",
                limit=int(limit),
            )
            top_dst_ports = _ch_top_counts(
                ch,
                source_sql=dedup_source_sql,
                params=params,
                key_expr="toString(d.dst_port)",
                limit=int(limit),
            )
            top_src_ports = _ch_top_counts(
                ch,
                source_sql=dedup_source_sql,
                params=params,
                key_expr="toString(d.src_port)",
                limit=int(limit),
            )
            missing_field = _missing_protocol_summary_field(
                db,
                since=since_ts,
                agent_id=agent_id,
                field_presence={"app_proto": bool(app_protocols)},
            )
            if missing_field:
                raise LookupError(f"clickhouse_proto_metadata_stale:{missing_field}")
            if not app_protocols and ch_total_events > 0:
                guess_sql = (
                    "SELECT "
                    "multiIf("
                    "d.dst_port IN (53,5353), 'dns', "
                    "d.dst_port IN (80,8080,8000,8888), 'http', "
                    "d.dst_port IN (443,8443), 'tls', "
                    "d.dst_port = 22, 'ssh', "
                    "ifNull(lowerUTF8(d.proto), '') != '', lowerUTF8(d.proto), "
                    "'unknown'"
                    ") AS k, "
                    "count() AS c "
                    f"FROM ({dedup_source_sql}) AS d "
                    "GROUP BY k "
                    "ORDER BY c DESC "
                    f"LIMIT {int(limit)}"
                )
                guess_rows = _ch_query_dicts(ch, guess_sql, params)
                app_protocols = [
                    ProtoCount(key=str(row.get("k")), count=int(row.get("c") or 0))
                    for row in guess_rows
                    if row.get("k")
                ]
            app_proto_reasons = _ch_top_counts(
                ch,
                source_sql=dedup_source_sql,
                params=params,
                key_expr="ifNull(d.app_proto_reason, '')",
                limit=int(limit),
            )
            app_proto_conf_bands = _ch_top_counts(
                ch,
                source_sql=dedup_source_sql,
                params=params,
                key_expr="ifNull(d.app_proto_conf_band, '')",
                limit=int(limit),
            )
            ja4_ptypes = _ch_top_counts(
                ch,
                source_sql=dedup_source_sql,
                params=params,
                key_expr="if(ifNull(d.ja4_ptype, '') = '', 't', d.ja4_ptype)",
                limit=int(limit),
                nonempty=False,
            )
            http_methods = _ch_top_counts(
                ch,
                source_sql=dedup_source_sql,
                params=params,
                key_expr="upperUTF8(ifNull(d.http_method, ''))",
                limit=int(limit),
            )

            dns_sql = (
                "SELECT d.dns_qname AS qname, "
                "max(toInt32OrZero(JSONExtractString(d.extra_json, 'dns_risk'))) AS risk, "
                "count() AS c "
                f"FROM ({dedup_source_sql}) AS d "
                "GROUP BY qname HAVING qname != '' "
                f"ORDER BY c DESC LIMIT {int(limit)}"
            )
            dns_rows = _ch_query_dicts(ch, dns_sql, params)
            top_dns_queries = [
                ProtoDnsQueryStat(
                    qname=str(row.get("qname")),
                    risk=int(row.get("risk") or 0),
                    count=int(row.get("c") or 0),
                )
                for row in dns_rows
                if row.get("qname")
            ]

            top_http_hosts = _ch_top_counts(
                ch,
                source_sql=dedup_source_sql,
                params=params,
                key_expr="lowerUTF8(ifNull(d.http_host, ''))",
                limit=int(limit),
            )
            top_tls_sni = _ch_top_counts(
                ch,
                source_sql=dedup_source_sql,
                params=params,
                key_expr="lowerUTF8(ifNull(d.tls_sni, ''))",
                limit=int(limit),
            )
            top_alpn = _ch_top_counts(
                ch,
                source_sql=dedup_source_sql,
                params=params,
                key_expr="lowerUTF8(ifNull(d.tls_alpn_first, ''))",
                limit=int(limit),
            )

            ja4_sql = (
                "SELECT "
                "ja4, any(ptype) AS ptype, count() AS c "
                "FROM ("
                "SELECT ifNull(d.ja4, '') AS ja4, "
                "if(ifNull(d.ja4_ptype, '') = '', 't', d.ja4_ptype) AS ptype "
                f"FROM ({dedup_source_sql}) AS d"
                ") "
                "GROUP BY ja4 HAVING ja4 != '' "
                f"ORDER BY c DESC LIMIT {int(limit)}"
            )
            ja4_rows = _ch_query_dicts(ch, ja4_sql, params)
            top_ja4 = [
                ProtoJa4Stat(
                    ja4=str(row.get("ja4")),
                    ptype=str(row.get("ptype") or "t"),
                    count=int(row.get("c") or 0),
                )
                for row in ja4_rows
                if row.get("ja4")
            ]

            top_ja3 = _ch_top_counts(
                ch,
                source_sql=dedup_source_sql,
                params=params,
                key_expr="ifNull(d.ja3, '')",
                limit=int(limit),
            )
            missing_field = _missing_protocol_summary_field(
                db,
                since=since_ts,
                agent_id=agent_id,
                field_presence={
                    "app_proto_reason": bool(app_proto_reasons),
                    "app_proto_conf_band": bool(app_proto_conf_bands),
                    "dns_qname": bool(top_dns_queries),
                    "http_host": bool(top_http_hosts),
                    "http_method": bool(http_methods),
                    "tls_sni": bool(top_tls_sni),
                    "tls_alpn_first": bool(top_alpn),
                    "ja3": bool(top_ja3),
                    "ja4": bool(top_ja4),
                    "ja4_ptype": bool(ja4_ptypes),
                },
            )
            if missing_field:
                raise LookupError(f"clickhouse_proto_metadata_partial:{missing_field}")

            payload = ProtocolIntelSummaryResponse(
                generated_at=datetime.now(timezone.utc),
                since_minutes=int(since_minutes),
                agent_id=agent_id,
                total_events=ch_total_events,
                with_proto_metadata=int(ov.get("with_proto_metadata") or 0),
                dns_events=int(ov.get("dns_events") or 0),
                http_events=int(ov.get("http_events") or 0),
                tls_events=int(ov.get("tls_events") or 0),
                app_protocols=app_protocols,
                transport_protocols=transport_protocols,
                top_dst_ports=top_dst_ports,
                top_src_ports=top_src_ports,
                app_proto_reasons=app_proto_reasons,
                app_proto_conf_bands=app_proto_conf_bands,
                ja4_ptypes=ja4_ptypes,
                http_methods=http_methods,
                top_dns_queries=top_dns_queries,
                top_http_hosts=top_http_hosts,
                top_tls_sni=top_tls_sni,
                top_alpn=top_alpn,
                top_ja4=top_ja4,
                top_ja3=top_ja3,
                meta=_meta(
                    source="clickhouse",
                    fallback_chain=attempted_sources,
                    degraded_reason=degraded_reason,
                    source_freshness_seconds=_freshness_seconds(query_end, ch_last_ts),
                    query_latency_ms=(time.perf_counter() - started) * 1000.0,
                    cache_hit=False,
                    approximate=False,
                    query_window_start=since_ts,
                    query_window_end=query_end,
                ),
            )
            _cache_set_json(
                cache_key,
                payload.dict(),
                int(getattr(settings, "SEAGULL_EVENTS_SUMMARY_CACHE_TTL_SECONDS", 15) or 15),
            )
            observe_hist(
                "api_route_latency_seconds",
                time.perf_counter() - started,
                route="/events/network/summary",
                source="clickhouse",
            )
            return payload
        except Exception as exc:
            if not isinstance(exc, LookupError):
                log_event(logger, "warning", "events_network_summary_clickhouse_error", error_type=type(exc).__name__)
            degraded_reason = f"clickhouse_fallback:{str(exc)[:120]}"[:200]

    es = _es_client_or_none()
    if es is not None:
        attempted_sources.append("elasticsearch")
        try:
            base = _es_base_filters(since=since_ts, agent_id=agent_id)
            body: dict[str, Any] = {
                "size": 0,
                "query": {"bool": {"filter": base}},
                "aggs": {
                    "with_proto_metadata": {
                        "filter": {
                            "bool": {
                                "should": [
                                    {"exists": {"field": "app_proto"}},
                                    {"exists": {"field": "dns_qname"}},
                                    {"exists": {"field": "http_host"}},
                                    {"exists": {"field": "http_method"}},
                                    {"exists": {"field": "ja4"}},
                                    {"exists": {"field": "ja3"}},
                                    {"exists": {"field": "tls_sni"}},
                                ],
                                "minimum_should_match": 1,
                            }
                        }
                    },
                    "dns_events": {"filter": {"exists": {"field": "dns_qname"}}},
                    "http_events": {
                        "filter": {
                            "bool": {
                                "should": [
                                    {"exists": {"field": "http_host"}},
                                    {"exists": {"field": "http_method"}},
                                ],
                                "minimum_should_match": 1,
                            }
                        }
                    },
                    "tls_events": {
                        "filter": {
                            "bool": {
                                "should": [
                                    {"exists": {"field": "ja4"}},
                                    {"exists": {"field": "ja3"}},
                                    {"exists": {"field": "tls_sni"}},
                                ],
                                "minimum_should_match": 1,
                            }
                        }
                    },
                    "app_protocols": {"terms": {"field": "app_proto", "size": int(limit), "order": {"_count": "desc"}}},
                    "transport_protocols": {"terms": {"field": "proto", "size": int(limit), "order": {"_count": "desc"}}},
                    "top_dst_ports": {"terms": {"field": "dst_port", "size": int(limit), "order": {"_count": "desc"}}},
                    "top_src_ports": {"terms": {"field": "src_port", "size": int(limit), "order": {"_count": "desc"}}},
                    "app_proto_reasons": {"terms": {"field": "app_proto_reason", "size": int(limit), "order": {"_count": "desc"}}},
                    "app_proto_conf_bands": {
                        "terms": {"field": "app_proto_conf_band", "size": int(limit), "order": {"_count": "desc"}}
                    },
                    "ja4_ptypes": {"terms": {"field": "ja4_ptype", "size": int(limit), "order": {"_count": "desc"}}},
                    "http_methods": {"terms": {"field": "http_method", "size": int(limit), "order": {"_count": "desc"}}},
                    "top_dns_queries": {
                        "terms": {"field": "dns_qname", "size": int(limit), "order": {"_count": "desc"}},
                        "aggs": {"risk": {"max": {"field": "dns_risk"}}},
                    },
                    "top_http_hosts": {"terms": {"field": "http_host", "size": int(limit), "order": {"_count": "desc"}}},
                    "top_tls_sni": {"terms": {"field": "tls_sni", "size": int(limit), "order": {"_count": "desc"}}},
                    "top_alpn": {"terms": {"field": "tls_alpn_first", "size": int(limit), "order": {"_count": "desc"}}},
                    "top_ja4": {
                        "terms": {"field": "ja4", "size": int(limit), "order": {"_count": "desc"}},
                        "aggs": {"ptype": {"terms": {"field": "ja4_ptype", "size": 1, "order": {"_count": "desc"}}}},
                    },
                    "top_ja3": {"terms": {"field": "ja3", "size": int(limit), "order": {"_count": "desc"}}},
                    "latest_ts": {"max": {"field": "timestamp"}},
                },
            }

            res = es.search(index=_es_index_pattern(), body=body, ignore_unavailable=True, allow_no_indices=True)

            total_events = int(((res.get("hits") or {}).get("total") or {}).get("value", 0) or 0)
            if total_events == 0:
                total_events = int(
                    es.count(
                        index=_es_index_pattern(),
                        body={"query": {"bool": {"filter": base}}},
                        ignore_unavailable=True,
                        allow_no_indices=True,
                    ).get("count", 0)
                )

            aggs = res.get("aggregations") or {}
            with_proto_metadata = int(((aggs.get("with_proto_metadata") or {}).get("doc_count", 0)) or 0)
            dns_events = int(((aggs.get("dns_events") or {}).get("doc_count", 0)) or 0)
            http_events = int(((aggs.get("http_events") or {}).get("doc_count", 0)) or 0)
            tls_events = int(((aggs.get("tls_events") or {}).get("doc_count", 0)) or 0)
            es_latest_ts: datetime | None = None
            latest_ts_value = (aggs.get("latest_ts") or {}).get("value")
            if latest_ts_value is not None:
                try:
                    es_latest_ts = datetime.fromtimestamp(float(latest_ts_value) / 1000.0, tz=timezone.utc)
                except Exception:
                    es_latest_ts = None

            if _es_failover_allowed():
                if total_events <= 0:
                    raise LookupError("es_empty_summary")
                if with_proto_metadata <= 0 and _pg_has_protocol_metadata(db, since=since_ts, agent_id=agent_id):
                    raise LookupError("es_proto_metadata_stale")
                if es_latest_ts is not None and _pg_has_newer_event(db, latest_ts=es_latest_ts, agent_id=agent_id):
                    raise LookupError("es_stale_summary")

            def _buckets(name: str) -> list[dict[str, Any]]:
                return ((aggs.get(name) or {}).get("buckets") or [])

            app_protocols = [
                ProtoCount(key=str(bucket.get("key")), count=int(bucket.get("doc_count", 0) or 0))
                for bucket in _buckets("app_protocols")
                if bucket.get("key") is not None
            ]
            transport_protocols = [
                ProtoCount(key=str(bucket.get("key")), count=int(bucket.get("doc_count", 0) or 0))
                for bucket in _buckets("transport_protocols")
                if bucket.get("key") is not None
            ]
            top_dst_ports = [
                ProtoCount(key=str(bucket.get("key")), count=int(bucket.get("doc_count", 0) or 0))
                for bucket in _buckets("top_dst_ports")
                if bucket.get("key") is not None
            ]
            top_src_ports = [
                ProtoCount(key=str(bucket.get("key")), count=int(bucket.get("doc_count", 0) or 0))
                for bucket in _buckets("top_src_ports")
                if bucket.get("key") is not None
            ]
            missing_field = _missing_protocol_summary_field(
                db,
                since=since_ts,
                agent_id=agent_id,
                field_presence={"app_proto": bool(app_protocols)},
            )
            if missing_field:
                raise LookupError(f"es_proto_metadata_stale:{missing_field}")
            if not app_protocols and total_events > 0:
                app_protocols = _guess_app_protocols_from_port_counts(top_dst_ports)
                if not app_protocols:
                    app_protocols = [
                        ProtoCount(key=str(item.key), count=int(item.count or 0))
                        for item in transport_protocols
                    ]
            app_proto_reasons = [
                ProtoCount(key=str(bucket.get("key")), count=int(bucket.get("doc_count", 0) or 0))
                for bucket in _buckets("app_proto_reasons")
                if bucket.get("key") is not None
            ]
            app_proto_conf_bands = [
                ProtoCount(key=str(bucket.get("key")), count=int(bucket.get("doc_count", 0) or 0))
                for bucket in _buckets("app_proto_conf_bands")
                if bucket.get("key") is not None
            ]
            ja4_ptypes = [
                ProtoCount(key=str(bucket.get("key")), count=int(bucket.get("doc_count", 0) or 0))
                for bucket in _buckets("ja4_ptypes")
                if bucket.get("key") is not None
            ]
            http_methods = [
                ProtoCount(key=str(bucket.get("key")), count=int(bucket.get("doc_count", 0) or 0))
                for bucket in _buckets("http_methods")
                if bucket.get("key") is not None
            ]

            top_dns_queries: list[ProtoDnsQueryStat] = []
            for bucket in _buckets("top_dns_queries"):
                key = bucket.get("key")
                if key is None:
                    continue
                risk_val = ((bucket.get("risk") or {}).get("value") or 0) or 0
                top_dns_queries.append(
                    ProtoDnsQueryStat(
                        qname=str(key),
                        risk=int(risk_val),
                        count=int(bucket.get("doc_count", 0) or 0),
                    )
                )

            top_http_hosts = [
                ProtoCount(key=str(bucket.get("key")), count=int(bucket.get("doc_count", 0) or 0))
                for bucket in _buckets("top_http_hosts")
                if bucket.get("key") is not None
            ]
            top_tls_sni = [
                ProtoCount(key=str(bucket.get("key")), count=int(bucket.get("doc_count", 0) or 0))
                for bucket in _buckets("top_tls_sni")
                if bucket.get("key") is not None
            ]
            top_alpn = [
                ProtoCount(key=str(bucket.get("key")), count=int(bucket.get("doc_count", 0) or 0))
                for bucket in _buckets("top_alpn")
                if bucket.get("key") is not None
            ]

            top_ja4: list[ProtoJa4Stat] = []
            for bucket in _buckets("top_ja4"):
                key = bucket.get("key")
                if key is None:
                    continue
                ptype_buckets = ((bucket.get("ptype") or {}).get("buckets") or [])
                ptype = str(ptype_buckets[0].get("key")) if ptype_buckets else "t"
                top_ja4.append(
                    ProtoJa4Stat(ja4=str(key), ptype=ptype, count=int(bucket.get("doc_count", 0) or 0))
                )

            top_ja3 = [
                ProtoCount(key=str(bucket.get("key")), count=int(bucket.get("doc_count", 0) or 0))
                for bucket in _buckets("top_ja3")
                if bucket.get("key") is not None
            ]
            missing_field = _missing_protocol_summary_field(
                db,
                since=since_ts,
                agent_id=agent_id,
                field_presence={
                    "app_proto_reason": bool(app_proto_reasons),
                    "app_proto_conf_band": bool(app_proto_conf_bands),
                    "dns_qname": bool(top_dns_queries),
                    "http_host": bool(top_http_hosts),
                    "http_method": bool(http_methods),
                    "tls_sni": bool(top_tls_sni),
                    "tls_alpn_first": bool(top_alpn),
                    "ja3": bool(top_ja3),
                    "ja4": bool(top_ja4),
                    "ja4_ptype": bool(ja4_ptypes),
                },
            )
            if missing_field:
                raise LookupError(f"es_proto_metadata_partial:{missing_field}")

            payload = ProtocolIntelSummaryResponse(
                generated_at=datetime.now(timezone.utc),
                since_minutes=int(since_minutes),
                agent_id=agent_id,
                total_events=total_events,
                with_proto_metadata=with_proto_metadata,
                dns_events=dns_events,
                http_events=http_events,
                tls_events=tls_events,
                app_protocols=app_protocols,
                transport_protocols=transport_protocols,
                top_dst_ports=top_dst_ports,
                top_src_ports=top_src_ports,
                app_proto_reasons=app_proto_reasons,
                app_proto_conf_bands=app_proto_conf_bands,
                ja4_ptypes=ja4_ptypes,
                http_methods=http_methods,
                top_dns_queries=top_dns_queries,
                top_http_hosts=top_http_hosts,
                top_tls_sni=top_tls_sni,
                top_alpn=top_alpn,
                top_ja4=top_ja4,
                top_ja3=top_ja3,
                meta=_meta(
                    source="elasticsearch",
                    fallback_chain=attempted_sources,
                    degraded_reason=degraded_reason,
                    source_freshness_seconds=_freshness_seconds(query_end, es_latest_ts),
                    query_latency_ms=(time.perf_counter() - started) * 1000.0,
                    cache_hit=False,
                    approximate=False,
                    query_window_start=since_ts,
                    query_window_end=query_end,
                ),
            )
            _cache_set_json(
                cache_key,
                payload.dict(),
                int(getattr(settings, "SEAGULL_EVENTS_SUMMARY_CACHE_TTL_SECONDS", 15) or 15),
            )
            observe_hist(
                "api_route_latency_seconds",
                time.perf_counter() - started,
                route="/events/network/summary",
                source="elasticsearch",
            )
            return payload
        except Exception as exc:
            if not _es_failover_allowed():
                raise HTTPException(status_code=503, detail=f"Elasticsearch error: {type(exc).__name__}") from None
            degraded_reason = f"elasticsearch_fallback:{type(exc).__name__}"[:200]

    attempted_sources.append("postgres")

    app_proto_expr = func.coalesce(NetEventModel.app_proto, NetEventModel.extra["app_proto"].astext)
    app_proto_reason_expr = func.coalesce(NetEventModel.app_proto_reason, NetEventModel.extra["app_proto_reason"].astext)
    app_proto_conf_expr = func.coalesce(NetEventModel.app_proto_conf_band, NetEventModel.extra["app_proto_conf_band"].astext)
    dns_qname_expr = func.coalesce(NetEventModel.dns_qname, NetEventModel.extra["dns_qname"].astext)
    http_host_expr = func.coalesce(NetEventModel.http_host, NetEventModel.extra["http_host"].astext)
    http_method_expr = func.coalesce(NetEventModel.http_method, NetEventModel.extra["http_method"].astext)
    tls_sni_expr = func.coalesce(NetEventModel.tls_sni, NetEventModel.extra["tls_sni"].astext)
    tls_alpn_expr = func.coalesce(NetEventModel.tls_alpn_first, NetEventModel.extra["tls_alpn_first"].astext)
    ja4_expr = func.coalesce(NetEventModel.ja4, NetEventModel.extra["ja4"].astext)
    ja4_ptype_expr = func.coalesce(NetEventModel.ja4_ptype, NetEventModel.extra["ja4_ptype"].astext, "t")
    ja3_expr = func.coalesce(NetEventModel.ja3, NetEventModel.extra["ja3"].astext)

    base_conds = [NetEventModel.timestamp >= since_ts]
    if agent_id:
        base_conds.append(NetEventModel.agent_id == agent_id)

    counts = repository.run(
        db,
        select(
            func.count().label("total_events"),
            func.count().filter(
                or_(
                    func.nullif(app_proto_expr, "").is_not(None),
                    func.nullif(dns_qname_expr, "").is_not(None),
                    func.nullif(http_host_expr, "").is_not(None),
                    func.nullif(http_method_expr, "").is_not(None),
                    func.nullif(ja4_expr, "").is_not(None),
                    func.nullif(ja3_expr, "").is_not(None),
                    func.nullif(tls_sni_expr, "").is_not(None),
                )
            ).label("with_proto_metadata"),
            func.count().filter(func.nullif(dns_qname_expr, "").is_not(None)).label("dns_events"),
            func.count().filter(
                or_(
                    func.nullif(http_host_expr, "").is_not(None),
                    func.nullif(http_method_expr, "").is_not(None),
                )
            ).label("http_events"),
            func.count().filter(
                or_(
                    func.nullif(ja4_expr, "").is_not(None),
                    func.nullif(ja3_expr, "").is_not(None),
                    func.nullif(tls_sni_expr, "").is_not(None),
                )
            ).label("tls_events"),
        ).where(*base_conds),
    ).mappings().one()

    total_events = int(counts.get("total_events") or 0)
    with_proto_metadata = int(counts.get("with_proto_metadata") or 0)
    dns_events = int(counts.get("dns_events") or 0)
    http_events = int(counts.get("http_events") or 0)
    tls_events = int(counts.get("tls_events") or 0)

    def _top_k(expr, *, nonempty: bool = True) -> list[ProtoCount]:
        stmt = select(expr.label("key"), func.count().label("count")).where(*base_conds)
        if nonempty:
            stmt = stmt.where(expr.is_not(None), expr != "")
        stmt = stmt.group_by(expr).order_by(func.count().desc()).limit(int(limit))
        rows = repository.run(db, stmt).all()
        return [ProtoCount(key=str(row.key), count=int(row.count or 0)) for row in rows if row.key is not None]

    app_protocols = _top_k(app_proto_expr)
    transport_protocols = _top_k(func.lower(NetEventModel.proto))
    top_dst_ports = _top_k(cast(NetEventModel.dst_port, String))
    top_src_ports = _top_k(cast(NetEventModel.src_port, String))
    if not app_protocols and total_events > 0:
        app_protocols = _guess_app_protocols_from_port_counts(top_dst_ports)
        if not app_protocols:
            app_protocols = [ProtoCount(key=str(item.key), count=int(item.count or 0)) for item in transport_protocols]
    app_proto_reasons = _top_k(app_proto_reason_expr)
    app_proto_conf_bands = _top_k(app_proto_conf_expr)
    ja4_ptypes = _top_k(
        func.coalesce(func.nullif(ja4_ptype_expr, ""), "t"),
        nonempty=False,
    )
    http_methods = _top_k(func.upper(http_method_expr))

    dns_qname = dns_qname_expr
    dns_risk_txt = NetEventModel.extra["dns_risk"].astext
    dns_risk_int = cast(
        func.coalesce(
            func.nullif(
                func.regexp_replace(func.coalesce(dns_risk_txt, ""), r"[^0-9-]", "", "g"),
                "",
            ),
            "0",
        ),
        Integer,
    )
    dns_rows = repository.run(
        db,
        select(
            dns_qname.label("qname"),
            func.coalesce(func.max(dns_risk_int), 0).label("risk"),
            func.count().label("count"),
        )
        .where(*base_conds, dns_qname.is_not(None), dns_qname != "")
        .group_by(dns_qname)
        .order_by(func.count().desc())
        .limit(int(limit)),
    ).all()
    top_dns_queries = [
        ProtoDnsQueryStat(qname=str(row.qname), risk=int(row.risk or 0), count=int(row.count or 0))
        for row in dns_rows
    ]

    top_http_hosts = _top_k(func.lower(http_host_expr))
    top_tls_sni = _top_k(func.lower(tls_sni_expr))
    top_alpn = _top_k(func.lower(tls_alpn_expr))

    ja4_rows = repository.run(
        db,
        select(
            ja4_expr.label("ja4"),
            func.coalesce(func.nullif(func.max(ja4_ptype_expr), ""), "t").label("ptype"),
            func.count().label("count"),
        )
        .where(*base_conds, ja4_expr.is_not(None), ja4_expr != "")
        .group_by(ja4_expr)
        .order_by(func.count().desc())
        .limit(int(limit)),
    ).all()
    top_ja4 = [
        ProtoJa4Stat(ja4=str(row.ja4), ptype=str(row.ptype or "t"), count=int(row.count or 0))
        for row in ja4_rows
    ]

    top_ja3 = _top_k(ja3_expr)

    if total_events <= 0:
        r_total, r_transport, r_dst_ports = _pg_rollup_l4_snapshot(
            db,
            since_ts=since_ts,
            limit=int(limit),
            agent_id=agent_id,
        )
        if r_total > 0:
            total_events = int(r_total)
            if not transport_protocols:
                transport_protocols = r_transport
            if not top_dst_ports:
                top_dst_ports = r_dst_ports
            if not app_protocols:
                app_protocols = _guess_app_protocols_from_port_counts(top_dst_ports)
                if not app_protocols:
                    app_protocols = [
                        ProtoCount(key=str(item.key), count=int(item.count or 0))
                        for item in transport_protocols
                    ]

    payload = ProtocolIntelSummaryResponse(
        generated_at=datetime.now(timezone.utc),
        since_minutes=int(since_minutes),
        agent_id=agent_id,
        total_events=total_events,
        with_proto_metadata=with_proto_metadata,
        dns_events=dns_events,
        http_events=http_events,
        tls_events=tls_events,
        app_protocols=app_protocols,
        transport_protocols=transport_protocols,
        top_dst_ports=top_dst_ports,
        top_src_ports=top_src_ports,
        app_proto_reasons=app_proto_reasons,
        app_proto_conf_bands=app_proto_conf_bands,
        ja4_ptypes=ja4_ptypes,
        http_methods=http_methods,
        top_dns_queries=top_dns_queries,
        top_http_hosts=top_http_hosts,
        top_tls_sni=top_tls_sni,
        top_alpn=top_alpn,
        top_ja4=top_ja4,
        top_ja3=top_ja3,
        meta=_meta(
            source="postgres",
            fallback_chain=attempted_sources,
            degraded_reason=degraded_reason,
            source_freshness_seconds=_freshness_seconds(query_end, None),
            query_latency_ms=(time.perf_counter() - started) * 1000.0,
            cache_hit=False,
            approximate=bool(total_events > 0 and with_proto_metadata <= 0 and len(app_protocols) > 0),
            query_window_start=since_ts,
            query_window_end=query_end,
        ),
    )
    _cache_set_json(
        cache_key,
        payload.dict(),
        int(getattr(settings, "SEAGULL_EVENTS_SUMMARY_CACHE_TTL_SECONDS", 15) or 15),
    )
    observe_hist(
        "api_route_latency_seconds",
        time.perf_counter() - started,
        route="/events/network/summary",
        source="postgres",
    )
    return payload


def _mv_protocol_intel_summary(
    *,
    since_minutes: int,
    limit: int,
    agent_id: Optional[str] = None,
) -> Optional[ProtocolIntelSummaryResponse]:
    ch = _ch_client_or_none()
    if ch is None:
        return None

    query_end = _now_utc()
    since_ts = query_end - timedelta(minutes=int(since_minutes))
    since_floor = since_ts.replace(second=0, microsecond=0)

    threshold = int(getattr(settings, "SEAGULL_CH_WATERMARK_STALE_SECONDS", 120) or 120)
    lag = clickhouse_watermark_lag_seconds(now=query_end)
    if lag is not None and lag > float(max(1, threshold)):
        return None

    floor = read_proto_intel_materialization_floor()
    if floor is None or since_floor < floor:
        return None

    try:
        overview_table = clickhouse_proto_intel_overview_table_ref()
        facet_table = clickhouse_proto_intel_table_ref()
        params: dict[str, Any] = {"since": since_floor}
        agent_clause = ""
        if agent_id:
            params["agent"] = str(agent_id)
            agent_clause = " AND agent_id = {agent:String}"

        overview_sql = (
            "SELECT countMerge(total) AS total_events, "
            "sumMerge(with_proto) AS with_proto_metadata, "
            "sumMerge(dns) AS dns_events, "
            "sumMerge(http) AS http_events, "
            "sumMerge(tls) AS tls_events, "
            "maxMerge(last_ts) AS last_ts "
            f"FROM {overview_table} "
            "WHERE bucket_ts >= {since:DateTime('UTC')}"
            f"{agent_clause}"
        )
        ov = (_ch_query_dicts(ch, overview_sql, params) or [{}])[0]
        total_events = int(ov.get("total_events") or 0)
        if total_events <= 0:
            return None

        facet_sql = (
            "SELECT dimension, value, countMerge(cnt) AS c, maxMerge(risk_max) AS risk, anyMerge(assoc) AS assoc "
            f"FROM {facet_table} "
            "WHERE bucket_ts >= {since:DateTime('UTC')}"
            f"{agent_clause} "
            "GROUP BY dimension, value "
            "ORDER BY dimension ASC, c DESC "
            f"LIMIT {int(limit)} BY dimension"
        )
        rows = _ch_query_dicts(ch, facet_sql, params)

        buckets: dict[str, list[tuple[str, int, int, str]]] = defaultdict(list)
        for row in rows:
            dim = str(row.get("dimension") or "")
            val = str(row.get("value") or "")
            if not dim or val == "":
                continue
            buckets[dim].append(
                (val, int(row.get("c") or 0), int(row.get("risk") or 0), str(row.get("assoc") or ""))
            )

        def _counts(dim: str) -> list[ProtoCount]:
            return [ProtoCount(key=item[0], count=item[1]) for item in buckets.get(dim, [])]

        app_protocols = _counts("app_proto")
        transport_protocols = _counts("transport")
        top_dst_ports = _counts("dst_port")
        top_src_ports = _counts("src_port")
        if not app_protocols and total_events > 0:
            app_protocols = _guess_app_protocols_from_port_counts(top_dst_ports) or [
                ProtoCount(key=str(item.key), count=int(item.count or 0)) for item in transport_protocols
            ]

        top_dns_queries = [
            ProtoDnsQueryStat(qname=item[0], risk=item[2], count=item[1]) for item in buckets.get("dns_qname", [])
        ]
        top_ja4 = [
            ProtoJa4Stat(ja4=item[0], ptype=(item[3] or "t"), count=item[1]) for item in buckets.get("ja4", [])
        ]

        ch_last_ts = _parse_iso_dt_or_none(ov.get("last_ts"))

        return ProtocolIntelSummaryResponse(
            generated_at=datetime.now(timezone.utc),
            since_minutes=int(since_minutes),
            agent_id=agent_id,
            total_events=total_events,
            with_proto_metadata=int(ov.get("with_proto_metadata") or 0),
            dns_events=int(ov.get("dns_events") or 0),
            http_events=int(ov.get("http_events") or 0),
            tls_events=int(ov.get("tls_events") or 0),
            app_protocols=app_protocols,
            transport_protocols=transport_protocols,
            top_dst_ports=top_dst_ports,
            top_src_ports=top_src_ports,
            app_proto_reasons=_counts("app_proto_reason"),
            app_proto_conf_bands=_counts("app_proto_conf_band"),
            ja4_ptypes=_counts("ja4_ptype"),
            http_methods=_counts("http_method"),
            top_dns_queries=top_dns_queries,
            top_http_hosts=_counts("http_host"),
            top_tls_sni=_counts("tls_sni"),
            top_alpn=_counts("tls_alpn_first"),
            top_ja4=top_ja4,
            top_ja3=_counts("ja3"),
            meta=_meta(
                source="clickhouse",
                fallback_chain=["clickhouse_mv"],
                degraded_reason=None,
                source_freshness_seconds=_freshness_seconds(query_end, ch_last_ts),
                query_latency_ms=0.0,
                cache_hit=False,
                approximate=False,
                query_window_start=since_ts,
                query_window_end=query_end,
            ),
        )
    except Exception as exc:
        log_event(logger, "warning", "events_network_summary_mv_error", error_type=type(exc).__name__)
        return None


def resolve_protocol_intel_summary(
    db: Session,
    *,
    since_minutes: int = 60 * 12,
    limit: int = 25,
    agent_id: Optional[str] = None,
) -> ProtocolIntelSummaryResponse:
    if bool(getattr(settings, "SEAGULL_PROTO_INTEL_MV_ENABLED", True)):
        mv = _mv_protocol_intel_summary(since_minutes=since_minutes, limit=limit, agent_id=agent_id)
        if mv is not None:
            return mv
    return get_protocol_intel_summary(db, since_minutes=since_minutes, limit=limit, agent_id=agent_id)
