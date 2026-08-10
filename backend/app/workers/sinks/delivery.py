from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Protocol, Sequence


@dataclass(frozen=True)
class DeliveryResult:
    delivered: int = 0
    retry: List[Dict[str, Any]] = field(default_factory=list)
    dead: List[Dict[str, Any]] = field(default_factory=list)
    error: str = ""

    @property
    def complete(self) -> bool:
        return not self.retry and not self.dead


def delivered(count: int) -> DeliveryResult:
    return DeliveryResult(delivered=int(count))


def retry_all(events: Sequence[Dict[str, Any]], *, error: str) -> DeliveryResult:
    return DeliveryResult(retry=list(events), error=error)


class SinkDelivery(Protocol):
    sink: str

    def deliver(self, events: List[Dict[str, Any]], *, batch_id: int) -> DeliveryResult: ...
