from __future__ import annotations

from typing import Any, List, Mapping, Sequence, Tuple

from app.features.events.domain.hunt_dialects import HuntQueryError
from app.features.events.domain.normalizers import _hit_to_event
from app.features.events.schemas import EqlSequence, NetEventDB

EQL_MAX_QUERY_LENGTH = 2048


def normalize_eql_query(query: str) -> str:
    text = str(query or "").strip()
    if not text:
        raise HuntQueryError("EQL query must contain non-whitespace characters", reason="syntax")
    if len(text) > EQL_MAX_QUERY_LENGTH:
        raise HuntQueryError(
            f"EQL query exceeds the maximum length of {EQL_MAX_QUERY_LENGTH} characters",
            reason="too_long",
        )
    return text


def eql_response_is_incomplete(data: Mapping[str, Any]) -> bool:
    return bool(data.get("is_running") or data.get("is_partial") or data.get("timed_out"))


def _events_from_hits(raw_events: Sequence[Any]) -> List[NetEventDB]:
    events: List[NetEventDB] = []
    for raw in raw_events:
        if not isinstance(raw, Mapping):
            continue
        try:
            events.append(_hit_to_event(dict(raw)))
        except Exception:
            continue
    return events


def eql_sequences_from_response(data: Mapping[str, Any]) -> Tuple[List[EqlSequence], int]:
    hits = data.get("hits") or {}
    sequences: List[EqlSequence] = []
    for raw in hits.get("sequences") or []:
        if not isinstance(raw, Mapping):
            continue
        events = _events_from_hits(raw.get("events") or [])
        if not events:
            continue
        sequences.append(EqlSequence(join_keys=list(raw.get("join_keys") or []), events=events))
    if not sequences:
        for event in _events_from_hits(hits.get("events") or []):
            sequences.append(EqlSequence(join_keys=[], events=[event]))
    total_raw = hits.get("total")
    if isinstance(total_raw, Mapping):
        total = int(total_raw.get("value") or 0)
    else:
        total = int(total_raw or 0)
    return sequences, max(total, len(sequences))
