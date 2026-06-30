from __future__ import annotations

import asyncio
import secrets
import time
from typing import Any, Awaitable, Callable, Optional

from app.core.cache.client import get_redis

_RELEASE_LUA = (
    "if redis.call('get', KEYS[1]) == ARGV[1] then "
    "return redis.call('del', KEYS[1]) else return 0 end"
)


async def acquire_lock(key: str, *, ttl_s: float) -> Optional[str]:
    r = get_redis()
    if r is None:
        return None
    token = secrets.token_hex(16)
    try:
        ok = await asyncio.to_thread(r.set, key, token, nx=True, px=int(max(1.0, ttl_s) * 1000))
    except Exception:
        return None
    return token if ok else None


async def release_lock(key: str, token: str) -> None:
    r = get_redis()
    if r is None or not token:
        return
    try:
        await asyncio.to_thread(r.eval, _RELEASE_LUA, 1, key, token)
    except Exception:
        return


class _InProcessFlights:
    def __init__(self) -> None:
        self._inflight: dict[str, "asyncio.Future[Any]"] = {}

    def existing(self, key: str) -> "Optional[asyncio.Future[Any]]":
        return self._inflight.get(key)

    def begin(self, key: str) -> "asyncio.Future[Any]":
        loop = asyncio.get_event_loop()
        fut: "asyncio.Future[Any]" = loop.create_future()
        self._inflight[key] = fut
        return fut

    def finish(self, key: str, fut: "asyncio.Future[Any]", result: Any, exc: Optional[BaseException]) -> None:
        if not fut.done():
            if exc is not None:
                fut.set_exception(exc)
            else:
                fut.set_result(result)
        if self._inflight.get(key) is fut:
            self._inflight.pop(key, None)


_flights = _InProcessFlights()


async def single_flight(
    key: str,
    factory: Callable[[], Awaitable[Any]],
    *,
    lock_ttl_s: float,
    wait_timeout_s: float,
    poll: Optional[Callable[[], Optional[Any]]] = None,
    poll_interval_s: float = 0.05,
    on_role: Optional[Callable[[str], None]] = None,
) -> tuple[Any, str]:
    waiting = _flights.existing(key)
    if waiting is not None:
        if on_role:
            on_role("waiter")
        return await waiting, "waiter_local"

    fut = _flights.begin(key)
    result: Any = None
    exc: Optional[BaseException] = None
    role = "leader"
    try:
        token = await acquire_lock(key, ttl_s=lock_ttl_s)
        if token is not None:
            if on_role:
                on_role("leader")
            try:
                result = await factory()
            finally:
                await release_lock(key, token)
        else:
            role = "waiter"
            if on_role:
                on_role("waiter")
            result = await _wait_for_leader(
                factory, poll=poll, wait_timeout_s=wait_timeout_s, poll_interval_s=poll_interval_s
            )
    except BaseException as e:  # noqa: BLE001
        exc = e
    finally:
        _flights.finish(key, fut, result, exc)
    if exc is not None:
        raise exc
    return result, role


async def _wait_for_leader(
    factory: Callable[[], Awaitable[Any]],
    *,
    poll: Optional[Callable[[], Optional[Any]]],
    wait_timeout_s: float,
    poll_interval_s: float,
) -> Any:
    if poll is not None:
        deadline = time.monotonic() + max(0.0, wait_timeout_s)
        while time.monotonic() < deadline:
            found = poll()
            if found is not None:
                return found
            await asyncio.sleep(poll_interval_s)
    return await factory()
