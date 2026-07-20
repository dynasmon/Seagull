from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional

from app.core.cache.client import get_redis
from app.core.config import settings
from app.core.observability import incr_counter, log_event, observe_hist

ParamsT = Dict[str, Any]
ComputeFn = Callable[[ParamsT], Awaitable[dict]]
KeyBuilder = Callable[[ParamsT], str]
ScopeProvider = Callable[[], List[ParamsT]]

logger = logging.getLogger("seagull.analytics.snapshots")

_SEEN_KEY_PREFIX = "seagull:snapshots:seen:"
_SEEN_MAX_MEMBERS = 64
_SEEN_TTL_SECONDS = 7 * 86400


def snapshot_tick_seconds() -> float:
    return max(5.0, float(getattr(settings, "SEAGULL_SNAPSHOTS_EVERY_SECONDS", 30.0) or 30.0))


def default_max_age_seconds() -> float:
    multiplier = float(getattr(settings, "SEAGULL_SNAPSHOTS_MAX_AGE_MULTIPLIER", 6.0) or 6.0)
    tick = snapshot_tick_seconds()
    return max(tick * multiplier, tick + 5.0)


def canonical_scope_params(params: ParamsT) -> str:
    return json.dumps(params, ensure_ascii=True, separators=(",", ":"), sort_keys=True, default=str)


def _always_snapshotable(params: ParamsT) -> bool:
    return True


def _global_scope_label(params: ParamsT) -> str:
    return "global"


@dataclass(frozen=True)
class SnapshotPage:
    page: str
    flag_env: str
    schema_version: int
    raw_compute: ComputeFn
    scope_key_builder: KeyBuilder
    static_scopes: ScopeProvider
    snapshotable: Callable[[ParamsT], bool] = field(default=_always_snapshotable)
    track_params: Optional[Callable[[ParamsT], Optional[ParamsT]]] = None
    scope_label: Callable[[ParamsT], str] = field(default=_global_scope_label)
    freshness_probe: Optional[Callable[[dict, ParamsT], bool]] = None
    refresh_interval_s: Optional[Callable[[ParamsT], float]] = None
    volatile_keys: frozenset[str] = frozenset()

    def enabled(self) -> bool:
        return bool(getattr(settings, self.flag_env, False))

    def scope_key(self, params: ParamsT) -> str:
        return self.scope_key_builder(params)

    def scope_refresh_interval_seconds(self, params: ParamsT) -> float:
        if self.refresh_interval_s is None:
            return 0.0
        try:
            return max(0.0, float(self.refresh_interval_s(params)))
        except Exception:
            return 0.0

    def max_age_seconds(self, params: Optional[ParamsT] = None) -> float:
        if params is not None:
            interval = self.scope_refresh_interval_seconds(params)
            if interval > 0.0:
                multiplier = float(getattr(settings, "SEAGULL_SNAPSHOTS_MAX_AGE_MULTIPLIER", 6.0) or 6.0)
                return max(interval * multiplier, interval + 5.0)
        return default_max_age_seconds()

    async def compute(self, params: ParamsT) -> dict:
        if not self.enabled():
            return await self.raw_compute(params)
        if not self.snapshotable(params):
            incr_counter("snapshot_lookup_total", page=self.page, outcome="bypass")
            return await self.raw_compute(params)
        self._record_seen(params)
        payload = await self._read_store(params)
        if payload is not None:
            return payload
        return await self.raw_compute(params)

    async def read(self, params: ParamsT) -> Optional[dict]:
        if not self.enabled():
            return None
        if not self.snapshotable(params):
            incr_counter("snapshot_lookup_total", page=self.page, outcome="bypass")
            return None
        self._record_seen(params)
        return await self._read_store(params)

    async def _read_store(self, params: ParamsT) -> Optional[dict]:
        from app.shared.analytics import snapshot_store

        scope_key = self.scope_key(params)
        started = time.perf_counter()
        try:
            row = await asyncio.to_thread(snapshot_store.read_snapshot, self.page, scope_key)
        except Exception as exc:
            observe_hist("snapshot_store_read_seconds", time.perf_counter() - started, page=self.page)
            self._fallback("error", scope_key, error_type=type(exc).__name__)
            return None
        observe_hist("snapshot_store_read_seconds", time.perf_counter() - started, page=self.page)
        if row is None:
            self._fallback("missing", scope_key)
            return None
        if int(row.schema_version) != int(self.schema_version):
            self._fallback("schema", scope_key)
            return None
        age_s = max(0.0, time.time() - row.computed_at.timestamp())
        if age_s > self.max_age_seconds(params):
            self._fallback("stale", scope_key, age_s=round(age_s, 1))
            return None
        if self.freshness_probe is not None:
            try:
                outdated = bool(self.freshness_probe(row.payload, params))
            except Exception:
                outdated = False
            if outdated:
                self._fallback("outdated", scope_key, age_s=round(age_s, 1))
                return None
        degraded = age_s > max(snapshot_tick_seconds(), self.scope_refresh_interval_seconds(params)) * 2.0
        incr_counter("snapshot_lookup_total", page=self.page, outcome="degraded" if degraded else "hit")
        payload = dict(row.payload)
        meta = dict(payload.get("meta") or {})
        meta["snapshot"] = {
            "computed_at": row.computed_at.isoformat(),
            "computed_ms": round(float(row.computed_ms), 2),
            "age_s": round(age_s, 1),
            "degraded": degraded,
        }
        payload["meta"] = meta
        return payload

    def _fallback(self, reason: str, scope_key: str, **extra: Any) -> None:
        incr_counter("snapshot_lookup_total", page=self.page, outcome=reason)
        incr_counter("snapshot_fallback_total", page=self.page, reason=reason)
        log_event(
            logger,
            "warning",
            "snapshot_fallback_inline_compute",
            page=self.page,
            reason=reason,
            scope_key=scope_key,
            **extra,
        )

    def _record_seen(self, params: ParamsT) -> None:
        if self.track_params is None:
            return
        try:
            tracked = self.track_params(params)
        except Exception:
            return
        if tracked is None:
            return
        r = get_redis()
        if r is None:
            return
        key = _SEEN_KEY_PREFIX + self.page
        try:
            r.zadd(key, {canonical_scope_params(tracked): time.time()})
            r.zremrangebyrank(key, 0, -(_SEEN_MAX_MEMBERS + 1))
            r.expire(key, _SEEN_TTL_SECONDS)
        except Exception:
            return


def snapshot_content_version(page: SnapshotPage, payload: dict) -> str:
    from app.shared.analytics.swr import payload_etag

    if not page.volatile_keys:
        return payload_etag(payload, schema_version=page.schema_version)
    stable = {key: value for key, value in payload.items() if key not in page.volatile_keys}
    return payload_etag(stable, schema_version=page.schema_version)


_PAGES: Dict[str, SnapshotPage] = {}


def register_snapshot_page(page: SnapshotPage) -> SnapshotPage:
    _PAGES[page.page] = page
    return page


def get_snapshot_page(name: str) -> Optional[SnapshotPage]:
    return _PAGES.get(name)


def iter_snapshot_pages() -> List[SnapshotPage]:
    return list(_PAGES.values())


def recent_dynamic_scopes(page: SnapshotPage) -> List[ParamsT]:
    if page.track_params is None:
        return []
    r = get_redis()
    if r is None:
        return []
    window_hours = int(getattr(settings, "SEAGULL_SNAPSHOTS_DYNAMIC_WINDOW_HOURS", 6) or 6)
    cap = int(getattr(settings, "SEAGULL_SNAPSHOTS_DYNAMIC_MAX_SCOPES", 20) or 20)
    cutoff = time.time() - max(1, window_hours) * 3600.0
    try:
        members = r.zrevrangebyscore(_SEEN_KEY_PREFIX + page.page, "+inf", cutoff, start=0, num=max(1, cap))
    except Exception:
        return []
    out: List[ParamsT] = []
    for member in members or []:
        try:
            obj = json.loads(member)
        except Exception:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def collect_scopes(page: SnapshotPage) -> List[ParamsT]:
    scopes: List[ParamsT] = []
    seen: set[str] = set()
    for params in list(page.static_scopes()) + recent_dynamic_scopes(page):
        try:
            key = page.scope_key(params)
        except Exception:
            continue
        if key in seen:
            continue
        seen.add(key)
        scopes.append(params)
    return scopes
