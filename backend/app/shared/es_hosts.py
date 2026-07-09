from __future__ import annotations

_DEFAULT_URL = "http://elasticsearch:9200"


def es_hosts(url: str | None, default: str = _DEFAULT_URL) -> list[str]:
    raw = (url or "").strip() or default
    return [h.strip() for h in raw.split(",") if h.strip()]
