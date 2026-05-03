from __future__ import annotations

import hashlib
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from sqlalchemy import select

from app.core.db import engine
from app.features.attack_chain.worker_runtime import AttackChainAllowlistModel, load_and_validate_attack_stories

_allowlist_cache: dict[str, Any] = {"loaded_at": 0.0, "rules": []}
_story_cache: dict[str, Any] = {"loaded_at": 0.0, "stories": [], "errors": []}


def _load_allowlist_rules(*, ttl_seconds: float = 10.0) -> List[Dict[str, Any]]:
    now_t = time.time()
    loaded_at = float(_allowlist_cache.get("loaded_at") or 0.0)
    if ttl_seconds > 0 and (now_t - loaded_at) < ttl_seconds:
        return list(_allowlist_cache.get("rules") or [])

    try:
        with engine.begin() as conn:
            rows = conn.execute(
                select(
                    AttackChainAllowlistModel.id,
                    AttackChainAllowlistModel.rule_type,
                    AttackChainAllowlistModel.enabled,
                    AttackChainAllowlistModel.match_mode,
                    AttackChainAllowlistModel.pattern,
                    AttackChainAllowlistModel.agent_id,
                    AttackChainAllowlistModel.username,
                    AttackChainAllowlistModel.target_user,
                )
                .where(
                    AttackChainAllowlistModel.rule_type == "sudo_cmd",
                    AttackChainAllowlistModel.enabled.is_(True),
                )
                .order_by(AttackChainAllowlistModel.updated_at.desc(), AttackChainAllowlistModel.id.desc())
            ).mappings().all()
            rules = [dict(r) for r in rows]
    except Exception:
        rules = []

    _allowlist_cache["loaded_at"] = now_t
    _allowlist_cache["rules"] = rules
    return list(rules)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _fingerprint(stage: str, raw: str) -> str:
    base = f"{stage}:{raw}".encode("utf-8", errors="ignore")
    return hashlib.sha1(base).hexdigest()[:40]


def _load_attack_story_templates(*, ttl_seconds: float = 60.0) -> Tuple[List[Any], List[Dict[str, Any]]]:
    now_t = time.time()
    loaded_at = float(_story_cache.get("loaded_at") or 0.0)
    if ttl_seconds > 0 and (now_t - loaded_at) < ttl_seconds:
        return list(_story_cache.get("stories") or []), [dict(item) for item in (_story_cache.get("errors") or [])]

    try:
        report = load_and_validate_attack_stories(
            include_disabled=False,
            with_source=True,
            strict=False,
        )
        stories = list(report.stories)
        errors = [dict(item) for item in list(report.errors or [])]
    except Exception as exc:
        stories = []
        errors = [{"source_file": "attack_stories", "story_id": None, "message": str(exc)}]

    _story_cache["loaded_at"] = now_t
    _story_cache["stories"] = stories
    _story_cache["errors"] = errors
    return list(stories), [dict(item) for item in errors]
