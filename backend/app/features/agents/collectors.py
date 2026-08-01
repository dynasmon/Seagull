from __future__ import annotations

from typing import Iterable, Optional, Sequence

from fastapi import HTTPException, status

CATALOG: tuple[str, ...] = (
    "authlog",
    "proc",
    "proc_exec",
    "fim",
    "scan",
    "ddos",
    "l7",
    "lateral",
    "syscollector",
    "vuln",
)

_CATALOG_SET = frozenset(CATALOG)


def normalize(values: Optional[Iterable[str]], *, field: str = "sources") -> list[str]:
    seen: set[str] = set()
    for value in values or ():
        item = str(value or "").strip().lower()
        if not item:
            continue
        if item not in _CATALOG_SET:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"unsupported agent collector in {field}: {item}",
            )
        seen.add(item)
    return [name for name in CATALOG if name in seen]


def resolve(requested: Optional[Sequence[str]], *, default: Sequence[str]) -> list[str]:
    selected = normalize(requested)
    if selected:
        return selected
    resolved = normalize(default, field="SEAGULL_AGENT_DEFAULT_SOURCES")
    if not resolved:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="SEAGULL_AGENT_DEFAULT_SOURCES does not select any collector",
        )
    return resolved
