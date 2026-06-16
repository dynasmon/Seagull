from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from app.core.config import settings


@dataclass(frozen=True)
class HeuristicPatternList:
    id: str
    enabled: bool
    regex: re.Pattern


class HeuristicRegistry:
    def __init__(self, pattern_lists: dict[str, HeuristicPatternList]) -> None:
        self._pattern_lists = dict(pattern_lists)

    def get(self, list_id: str) -> re.Pattern | None:
        entry = self._pattern_lists.get(str(list_id or "").strip())
        if entry is None or not entry.enabled:
            return None
        return entry.regex

    @classmethod
    def load(cls, path: Path) -> "HeuristicRegistry":
        pattern_lists: dict[str, HeuristicPatternList] = {}
        try:
            raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        except FileNotFoundError:
            return cls(pattern_lists)
        for entry in raw.get("pattern_lists") or []:
            if not isinstance(entry, dict):
                continue
            list_id = str(entry.get("id") or "").strip()
            patterns = [str(item) for item in (entry.get("patterns") or []) if str(item or "").strip()]
            if not list_id or not patterns:
                continue
            regex = re.compile(r"\b(" + "|".join(re.escape(item) for item in patterns) + r")\b", re.IGNORECASE)
            pattern_lists[list_id] = HeuristicPatternList(
                id=list_id,
                enabled=bool(entry.get("enabled", True)),
                regex=regex,
            )
        return cls(pattern_lists)


_registry: HeuristicRegistry | None = None


def _patterns_path() -> Path:
    primary = Path(getattr(settings, "SEAGULL_RULES_DIR", "/app/rules") or "/app/rules") / "heuristics" / "patterns.yml"
    if primary.exists():
        return primary
    fallback = Path(__file__).resolve().parents[4] / "rules" / "heuristics" / "patterns.yml"
    return fallback if fallback.exists() else primary


def get_registry() -> HeuristicRegistry:
    global _registry
    if _registry is None:
        _registry = HeuristicRegistry.load(_patterns_path())
    return _registry
