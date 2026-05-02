"""IP intelligence worker."""

from __future__ import annotations

import logging
import time
from typing import Optional

from sqlalchemy.exc import OperationalError

from app.core.config import settings
from app.core.observability import log_event, setup_logging
from .cache import _ensure_bootstrap, _fetch_batch, _get_cached_ip, _get_last_id, _patch_event, _pick_batch_max_id, _set_last_id, _upsert_cache
from .normalization import GEOIP_PROVIDER_NONE, _compact, _env_float, _env_int, _env_str, _is_public_ip, _utc_now
from .providers import _provider_config, _resolve_provider, _lookup_ip

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

    backoff = 1.0
    last_provider_state: Optional[tuple[str, str]] = None

    while True:
        try:
            _ensure_bootstrap(cache_ttl_days)

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

                if skip_private and not _is_public_ip(ip):
                    _patch_event(eid, {**base_patch, "lupe_skipped": True, "lupe_reason": "non_public_ip"})
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
