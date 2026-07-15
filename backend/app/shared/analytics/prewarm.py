from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List

WarmProvider = Callable[[], Iterable["WarmSpec"]]


@dataclass(frozen=True)
class WarmSpec:
    feature: str
    params: Dict[str, Any] = field(default_factory=dict)


_PROVIDERS: List[WarmProvider] = []


def register_warm_set(provider: WarmProvider) -> WarmProvider:
    _PROVIDERS.append(provider)
    return provider


def iter_warm_specs() -> List[WarmSpec]:
    out: List[WarmSpec] = []
    for provider in _PROVIDERS:
        try:
            out.extend(list(provider()))
        except Exception:
            continue
    return out
