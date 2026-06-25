
from __future__ import annotations

import logging
import time
from typing import Optional

from sqlalchemy.exc import OperationalError

from app.core.config import settings
from app.core.observability import log_event, setup_logging
from app.shared.network.ip_classification import classify_ip

from .cache import (
    _ensure_bootstrap,
    _fetch_batch,
    _fetch_threat_geo_candidates,
    _get_cached_ip,
    _get_last_id,
    _patch_event,
    _pick_batch_max_id,
    _set_last_id,
    _upsert_cache,
)
from .normalization import (
    GEOIP_PROVIDER_MAXMIND,
    GEOIP_PROVIDER_NONE,
    _compact,
    _env_float,
    _env_int,
    _env_str,
    _utc_now,
)
from .providers import _lookup_ip, _provider_config, _resolve_provider


def _enrich_ip_into_cache(
    ip: str,
    provider_name: str,
    cfg: dict,
    timeout_s: float,
    cache_ttl_days: int,
) -> bool:
    if _get_cached_ip(ip) is not None:
        return False
    rec = _lookup_ip(ip, provider_name, cfg, timeout_s)
    _upsert_cache(ip, rec, cache_ttl_days)
    return True


def _run_threat_geo_pass(
    provider_name: str,
    cfg: dict,
    timeout_s: float,
    cache_ttl_days: int,
    window_minutes: int,
    cap: int,
    skip_private: bool,
) -> int:
    if cap <= 0:
        return 0
    candidates = _fetch_threat_geo_candidates(window_minutes, max(cap * 6, cap))
    enriched = 0
    for ip in candidates:
        if enriched >= cap:
            break
        if skip_private and not classify_ip(ip)["is_public"]:
            continue
        try:
            if _enrich_ip_into_cache(ip, provider_name, cfg, timeout_s, cache_ttl_days):
                enriched += 1
        except Exception:
            continue
    return enriched


setup_logging("worker-lupe")
logger = logging.getLogger("seagull.worker.lupe")


def main() -> None:
    settings.validate_for_service("worker-ip-intel")

    every_s = _env_float(1.0, "SEAGULL_IP_INTEL_EVERY_SECONDS", "SEAGULL_LUPE_EVERY_SECONDS")
    idle_sleep_s = _env_float(2.0, "SEAGULL_IP_INTEL_IDLE_SLEEP_SECONDS", "SEAGULL_LUPE_IDLE_SLEEP_SECONDS")
    max_rows = _env_int(2000, "SEAGULL_IP_INTEL_MAX_ROWS", "SEAGULL_LUPE_MAX_ROWS")
    batch_size = _env_int(200, "SEAGULL_IP_INTEL_BATCH_SIZE", "SEAGULL_LUPE_BATCH_SIZE")
    timeout_s = _env_float(8.0, "SEAGULL_IP_INTEL_HTTP_TIMEOUT_SECONDS", "SEAGULL_LUPE_HTTP_TIMEOUT_SECONDS")
    cache_ttl_days = _env_int(7, "SEAGULL_IP_INTEL_CACHE_TTL_DAYS", "SEAGULL_LUPE_CACHE_TTL_DAYS")
    skip_private = (
        _env_str("true", "SEAGULL_IP_INTEL_SKIP_PRIVATE", "SEAGULL_LUPE_SKIP_PRIVATE").strip().lower() != "false"
    )
    threat_geo_every_s = _env_float(20.0, "SEAGULL_IP_INTEL_THREAT_GEO_EVERY_SECONDS")
    threat_geo_window_min = _env_int(60 * 24, "SEAGULL_IP_INTEL_THREAT_GEO_WINDOW_MINUTES")
    threat_geo_cap_local = _env_int(2000, "SEAGULL_IP_INTEL_THREAT_GEO_MAX_IPS_LOCAL")
    threat_geo_cap_remote = _env_int(48, "SEAGULL_IP_INTEL_THREAT_GEO_MAX_IPS_REMOTE")

    _ensure_bootstrap(cache_ttl_days)

    backoff = 1.0
    last_provider_state: Optional[tuple[str, str]] = None
    last_threat_geo_at = 0.0

    while True:
        try:

            cfg = _provider_config()
            provider_name, provider_reason = _resolve_provider(cfg)
            provider_state = (provider_name, provider_reason)
            if provider_state != last_provider_state:
                level = "info" if provider_name != GEOIP_PROVIDER_NONE else "warning"
                log_event(
                    logger,
                    level,
                    "ip_intel_provider_selected",
                    provider=provider_name,
                    reason=provider_reason,
                    requested=cfg["requested"],
                    fallback=cfg["fallback"],
                )
                last_provider_state = provider_state

            if provider_name == GEOIP_PROVIDER_NONE:
                time.sleep(max(idle_sleep_s, 2.0))
                continue

            now_ts = time.time()
            if now_ts - last_threat_geo_at >= threat_geo_every_s:
                cap = threat_geo_cap_local if provider_name == GEOIP_PROVIDER_MAXMIND else threat_geo_cap_remote
                try:
                    geo_enriched = _run_threat_geo_pass(
                        provider_name,
                        cfg,
                        timeout_s,
                        cache_ttl_days,
                        threat_geo_window_min,
                        cap,
                        skip_private,
                    )
                    if geo_enriched:
                        log_event(logger, "info", "threat_geo_enriched", count=geo_enriched, provider=provider_name)
                except Exception as e:
                    log_event(logger, "warning", "threat_geo_pass_error", error=repr(e))
                last_threat_geo_at = now_ts

            last_id = _get_last_id()
            max_id = _pick_batch_max_id(last_id, max_rows)

            if max_id is None or max_id <= last_id:
                time.sleep(idle_sleep_s)
                backoff = 1.0
                continue

            rows = _fetch_batch(last_id, max_id, batch_size)
            if not rows:
                _set_last_id(max_id)
                time.sleep(max(every_s, 0.1))
                backoff = 1.0
                continue

            last_done_id = last_id
            t0 = time.time()

            for r in rows:
                eid = int(r["id"])
                ip = (r.get("src_ip") or "").strip()

                base_patch = {
                    "lupe_enriched_at": _utc_now().isoformat().replace("+00:00", "Z"),
                }

                if not ip:
                    _patch_event(eid, {**base_patch, "lupe_skipped": True, "lupe_reason": "missing_src_ip"})
                    last_done_id = eid
                    continue

                if skip_private:
                    cls = classify_ip(ip)
                    if not cls["is_public"]:
                        _patch_event(eid, {
                            **base_patch,
                            "lupe_skipped": True,
                            "lupe_reason": "non_public_ip",
                            "src_ip_scope": cls["scope"],
                            "src_ip_label": cls["label"],
                            "src_is_internal": cls["is_internal"],
                            "src_is_public": cls["is_public"],
                        })
                        last_done_id = eid
                        continue

                cached = _get_cached_ip(ip)
                if cached is None:
                    rec = _lookup_ip(ip, provider_name, cfg, timeout_s)
                    _upsert_cache(ip, rec, cache_ttl_days)
                    cached = rec

                patch = _compact(
                    {
                        **base_patch,
                        "geo_country": cached.get("country"),
                        "geo_region": cached.get("region"),
                        "geo_city": cached.get("city"),
                        "geo_loc": cached.get("loc"),
                        "geo_org": cached.get("org"),
                        "asn": cached.get("asn"),
                        "asn_org": cached.get("asn_org"),
                        "ip_intel_provider": cached.get("provider") or provider_name,
                    }
                )

                _patch_event(eid, patch)
                last_done_id = eid

            _set_last_id(last_done_id)
            took_ms = int((time.time() - t0) * 1000)
            log_event(
                logger,
                "info",
                "lupe_ok",
                last_id=last_id,
                max_id=max_id,
                processed=len(rows),
                provider=provider_name,
                took_ms=took_ms,
            )

            backoff = 1.0
            time.sleep(max(every_s, 0.1))

        except OperationalError as e:
            wait_s = min(backoff, 15.0)
            log_event(logger, "warning", "lupe_db_not_ready", wait_s=wait_s, error=str(e).splitlines()[0])
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 15.0)
        except Exception as e:
            wait_s = min(backoff, 30.0)
            log_event(logger, "error", "lupe_loop_error", wait_s=wait_s, error=repr(e))
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 30.0)


if __name__ == "__main__":
    main()
