from __future__ import annotations

from collections.abc import Sequence

from app.features.events.models import NetEventModel


def net_event_extra_jsonb_accessor(path: Sequence[str]):
    accessor = NetEventModel.extra
    for segment in path:
        accessor = accessor[segment]
    return accessor.astext
