from __future__ import annotations

from pathlib import Path

from app.features.attack_chain.domain.story_loader import load_and_validate_attack_stories


def _repo_rules_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "rules"


def test_repo_attack_story_templates_load() -> None:
    report = load_and_validate_attack_stories(
        include_disabled=False,
        with_source=True,
        rules_dir=_repo_rules_dir(),
        strict=False,
    )

    assert not report.errors
    assert len(report.stories) >= 6
    assert {story.id for story in report.stories} >= {
        "ssh_compromise_story",
        "recon_to_bruteforce_story",
        "privileged_access_after_ssh_story",
        "persistence_after_execution_story",
        "beaconing_after_persistence_story",
        "exposure_to_exploitation_story",
    }
    assert all(str(story.source_file or "").startswith("attack_stories/") for story in report.stories)


def test_invalid_attack_story_validation_returns_error(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules" / "attack_stories"
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / "invalid_story.yml").write_text(
        """
schema_version: 1
id: invalid_story
name: Invalid Story
description: Missing selectors should fail validation.
enabled: true
maturity: stable
entity:
  type: suspect_ip
  field: suspect_ip
maxspan_seconds: 600
stages:
  - id: stage_one
    name: Empty Match
    tactic: discovery
    technique_id: null
    required: true
    min_signals: 1
    after: null
    within_seconds: null
    match:
      rule_ids: []
      correlation_rule_ids: []
      attack_step_kinds: []
      event_types: []
    score_delta: 2
    confidence_weight: 1.0
scoring:
  story_match_bonus: 4
  max_story_score: 8
attack:
  summary: Invalid
  techniques: []
  tags: []
response:
  summary: Invalid
  recommendations: []
""".strip(),
        encoding="utf-8",
    )

    report = load_and_validate_attack_stories(
        include_disabled=False,
        with_source=True,
        rules_dir=tmp_path / "rules",
        strict=False,
    )

    assert not report.stories
    assert len(report.errors) == 1
    assert report.errors[0]["source_file"] == "attack_stories/invalid_story.yml"
    assert "match selector" in report.errors[0]["message"].lower()
