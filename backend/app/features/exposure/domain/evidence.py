from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.features.exposure.domain.normalization import (
    clamp_confidence,
    normalize_evidence_source_type,
    parse_dt,
)
from app.features.exposure.domain.types import EvidenceRef

_MAX_EVIDENCE_REFS = 32

# Evidence quality weights used when deriving aggregate confidence
_SOURCE_RELIABILITY: dict[str, int] = {
    "vulnerability": 88,
    "alert": 82,
    "attack_chain_step": 80,
    "attack_chain_case": 76,
    "event": 70,
    "fim": 74,
    "process_exec": 72,
    "inventory": 60,
    "response_action": 65,
    "investigation": 68,
}


def build_evidence_ref(
    *,
    source_type: str,
    source_id: str | int,
    observed_at: datetime | None,
    title: str,
    summary: str = "",
    metadata: dict[str, Any] | None = None,
) -> EvidenceRef:
    if observed_at is None:
        observed_at = datetime.now(tz=timezone.utc)
    elif observed_at.tzinfo is None:
        observed_at = observed_at.replace(tzinfo=timezone.utc)
    return EvidenceRef(
        source_type=normalize_evidence_source_type(source_type),
        source_id=str(source_id),
        observed_at=observed_at,
        title=str(title)[:256],
        summary=str(summary)[:1024],
        metadata=metadata or {},
    )


def evidence_refs_from_list(raw: list[Any]) -> list[EvidenceRef]:
    out: list[EvidenceRef] = []
    for item in raw[:_MAX_EVIDENCE_REFS]:
        if not isinstance(item, dict):
            continue
        source_type = normalize_evidence_source_type(item.get("source_type"))
        source_id = str(item.get("source_id") or "").strip()
        if not source_id:
            continue
        observed_at = parse_dt(item.get("observed_at")) or datetime.now(tz=timezone.utc)
        out.append(
            EvidenceRef(
                source_type=source_type,
                source_id=source_id,
                observed_at=observed_at,
                title=str(item.get("title") or "")[:256],
                summary=str(item.get("summary") or "")[:1024],
                metadata=item.get("metadata") if isinstance(item.get("metadata"), dict) else {},
            )
        )
    return out


def evidence_refs_to_list(refs: list[EvidenceRef]) -> list[dict[str, Any]]:
    return [r.to_dict() for r in refs[:_MAX_EVIDENCE_REFS]]


def derive_aggregate_confidence(refs: list[EvidenceRef], *, base_confidence: int = 50) -> int:
    if not refs:
        return clamp_confidence(base_confidence)

    seen_sources: set[str] = set()
    total_weight = 0.0
    weighted_sum = 0.0

    for ref in refs[:_MAX_EVIDENCE_REFS]:
        reliability = _SOURCE_RELIABILITY.get(ref.source_type, 60)
        weight = 1.0 if ref.source_type not in seen_sources else 0.4
        seen_sources.add(ref.source_type)
        total_weight += weight
        weighted_sum += reliability * weight

    if total_weight <= 0:
        return clamp_confidence(base_confidence)

    blended = (weighted_sum / total_weight) * 0.65 + float(base_confidence) * 0.35
    return clamp_confidence(blended)


def count_evidence_by_source(refs: list[EvidenceRef]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for ref in refs:
        counts[ref.source_type] = counts.get(ref.source_type, 0) + 1
    return counts


def merge_evidence_refs(existing: list[EvidenceRef], incoming: list[EvidenceRef]) -> list[EvidenceRef]:
    seen: dict[tuple[str, str], EvidenceRef] = {}
    for ref in existing + incoming:
        key = (ref.source_type, ref.source_id)
        prev = seen.get(key)
        if prev is None or ref.observed_at > prev.observed_at:
            seen[key] = ref
    ordered = sorted(seen.values(), key=lambda r: r.observed_at, reverse=True)
    return ordered[:_MAX_EVIDENCE_REFS]
