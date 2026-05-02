from __future__ import annotations

import re
from pathlib import Path

from app.mitre.catalog import TACTIC_LABELS
from app.workers.intelligence.rules.loader import load_rules


_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_SEVERITIES = {"low", "medium", "high", "critical"}
_RULE_TYPES = {"aggregate_count", "distinct_count", "multi_distinct"}


def _repo_rules_dir() -> Path:
    # backend/tests -> repo root -> rules
    return Path(__file__).resolve().parents[2] / "rules"


def test_detection_catalog_schema_and_attack_mapping() -> None:
    rules = load_rules(
        include_disabled=True,
        with_source=True,
        rules_dir=_repo_rules_dir(),
        apply_env_filters=False,
    )
    assert len(rules) >= 30

    seen_ids: set[str] = set()
    for r in rules:
        rid = str(r.get("id") or "").strip()
        assert rid
        assert rid not in seen_ids
        seen_ids.add(rid)

        assert str(r.get("name") or "").strip()
        assert str(r.get("description") or "").strip()
        assert str(r.get("pack") or "").strip()
        assert str(r.get("category") or "").strip()
        assert str(r.get("severity") or "").strip().lower() in _SEVERITIES
        assert str(r.get("type") or "").strip() in _RULE_TYPES

        match = r.get("match")
        assert isinstance(match, dict)

        group_by = r.get("group_by")
        assert isinstance(group_by, (str, list))

        mitre = r.get("mitre")
        assert isinstance(mitre, dict)
        tactic = str(mitre.get("tactic") or "").strip().lower()
        technique_id = str(mitre.get("technique_id") or "").strip()
        confidence = int(mitre.get("confidence", 0))

        assert tactic in TACTIC_LABELS
        assert _TECHNIQUE_ID_RE.match(technique_id)
        assert 0 <= confidence <= 100


def test_detection_catalog_pack_environment_filtering() -> None:
    rules = load_rules(
        include_disabled=True,
        with_source=True,
        rules_dir=_repo_rules_dir(),
        apply_env_filters=True,
    )
    assert rules
    # At least one core/network stable rule must always be present.
    packs = {str(r.get("pack") or "").strip() for r in rules}
    assert "core" in packs or "network" in packs
