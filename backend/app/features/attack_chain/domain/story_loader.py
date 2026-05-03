from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from app.core.config import settings

from .story_schemas import AttackStoryReport, AttackStoryTemplate


def _rules_root_path(rules_dir: str | Path | None = None) -> Path:
    if rules_dir is not None:
        raw = Path(rules_dir).resolve()
    else:
        raw = Path(getattr(settings, "SEAGULL_RULES_DIR", "/app/rules") or "/app/rules").resolve()
    if raw.name == "attack_stories":
        return raw.parent.resolve()
    return raw


def attack_story_dir_path(rules_dir: str | Path | None = None) -> Path:
    base = _rules_root_path(rules_dir)
    candidate = base if base.name == "attack_stories" else (base / "attack_stories")
    return candidate.resolve()


def _discover_story_files(story_dir: Path) -> list[Path]:
    files: list[Path] = []
    for suffix in (".yml", ".yaml"):
        files.extend(path for path in story_dir.rglob(f"*{suffix}") if path.is_file())
    return [Path(path) for path in sorted({path.resolve() for path in files})]


def _load_story_file(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Attack story file must contain a mapping: {path}")
    return data


def _build_error(*, source_file: str, message: str, story_id: str | None = None) -> dict[str, Any]:
    return {
        "source_file": source_file,
        "story_id": story_id,
        "message": message,
    }


def load_and_validate_attack_stories(
    *,
    include_disabled: bool = True,
    with_source: bool = True,
    rules_dir: str | Path | None = None,
    strict: bool = False,
) -> AttackStoryReport:
    rules_root = _rules_root_path(rules_dir)
    story_dir = attack_story_dir_path(rules_dir)
    if not story_dir.exists():
        return AttackStoryReport(stories=[], errors=[])

    stories: list[AttackStoryTemplate] = []
    errors: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for path in _discover_story_files(story_dir):
        source_file = str(path.relative_to(rules_root))
        try:
            raw = _load_story_file(path)
            candidate = dict(raw)
            if with_source:
                candidate["source_file"] = source_file
            story = AttackStoryTemplate.model_validate(candidate)
        except Exception as exc:
            error = _build_error(source_file=source_file, message=str(exc))
            if strict:
                raise
            errors.append(error)
            continue

        if story.id in seen_ids:
            error = _build_error(
                source_file=str(story.source_file or source_file),
                story_id=story.id,
                message=f"Duplicate attack story id detected: {story.id}",
            )
            if strict:
                raise RuntimeError(error["message"])
            errors.append(error)
            continue

        seen_ids.add(story.id)
        if not include_disabled and story.enabled is False:
            continue

        if not with_source:
            story = story.model_copy(update={"source_file": None})
        stories.append(story)

    stories.sort(key=lambda item: (str(item.maturity or ""), item.id))
    return AttackStoryReport(stories=stories, errors=errors)


def load_attack_stories(
    *,
    include_disabled: bool = False,
    with_source: bool = False,
    rules_dir: str | Path | None = None,
) -> list[AttackStoryTemplate]:
    report = load_and_validate_attack_stories(
        include_disabled=include_disabled,
        with_source=with_source,
        rules_dir=rules_dir,
        strict=True,
    )
    return list(report.stories)
