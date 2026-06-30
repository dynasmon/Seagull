from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable, Iterable, List, TypeVar

T = TypeVar("T")


async def run_offloaded(fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    return await asyncio.to_thread(fn, *args, **kwargs)


async def gather_bounded(coros: Iterable[Awaitable[T]], *, limit: int) -> List[T]:
    sem = asyncio.Semaphore(max(1, int(limit)))

    async def _wrap(coro: Awaitable[T]) -> T:
        async with sem:
            return await coro

    return await asyncio.gather(*[_wrap(c) for c in coros])
