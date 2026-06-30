from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional

from app.shared.analytics.swr import get_or_compute

ParamsT = Dict[str, Any]
ComputeFn = Callable[[ParamsT], Awaitable[dict]]
KeyBuilder = Callable[[ParamsT], str]


@dataclass(frozen=True)
class AnalyticalReadModel:
    name: str
    schema_version: int
    fresh_s: int
    stale_s: int
    key_builder: KeyBuilder
    compute: ComputeFn

    def cache_key(self, params: ParamsT) -> str:
        return self.key_builder(params)


_REGISTRY: Dict[str, AnalyticalReadModel] = {}


def register_read_model(model: AnalyticalReadModel) -> AnalyticalReadModel:
    _REGISTRY[model.name] = model
    return model


def get_read_model(name: str) -> Optional[AnalyticalReadModel]:
    return _REGISTRY.get(name)


def iter_read_models() -> List[AnalyticalReadModel]:
    return list(_REGISTRY.values())


async def serve_read_model(
    model: AnalyticalReadModel,
    params: ParamsT,
    *,
    allow_stale: bool = True,
    background: bool = True,
) -> tuple[dict, str, str]:
    async def _compute() -> dict:
        return await model.compute(params)

    return await get_or_compute(
        feature=model.name,
        key=model.cache_key(params),
        compute=_compute,
        fresh_s=model.fresh_s,
        stale_s=model.stale_s,
        schema_version=model.schema_version,
        allow_stale=allow_stale,
        background=background,
    )
