# Attack Stories

Attack stories are kill-chain templates that identify multi-stage attack progressions within durable attack-chain cases. They are evaluated continuously as new evidence arrives for a case.

## How attack stories work

The attack-chain worker processes events into `AttackChainStepModel` records attached to `AttackChainCaseModel` cases (keyed by suspect entity). After each batch, `evaluate_attack_stories()` is called for each case. The evaluator:

1. Builds a unified evidence record list from existing steps, recent alerts, and correlation incidents for the entity.
2. Iterates enabled story templates.
3. For each story, iterates stages in order. A stage matches if evidence records satisfy the stage's `match` selectors within the stage's temporal constraints.
4. Matched stages contribute `score_delta` to the case's risk score.
5. When all required stages of a story match, the story is marked complete and a `story_match_bonus` is applied.
6. The case's `context` JSONB is updated with `story_stage_hits`, `matched_story_ids`, `story_confidence`, and `story_reasoning`.

## Story file location

```
rules/attack_stories/<story_id>.yml
```

Files are loaded by `features.attack_chain.domain.story_loader.load_attack_stories()`. The loader validates each file with `AttackStoryTemplate.model_validate()` and raises on schema errors.

## Story schema

```yaml
schema_version: 1
id: ssh_compromise_story              # unique, matches filename
name: SSH Compromise After Brute Force
description: "..."
enabled: true
maturity: stable                      # stable or experimental

entity:
  type: suspect_ip                    # entity type label
  field: suspect_ip                   # field to match on evidence records

maxspan_seconds: 1800                 # overall story time limit (0 = no limit)

stages:
  - id: brute_force
    name: SSH Brute Force
    tactic: credential_access
    technique_id: T1110.001
    required: true                    # all required stages must match for story completion
    min_signals: 1                    # minimum matching evidence records
    after: null                       # no ordering constraint for the first stage
    within_seconds: null              # relative time constraint (from the "after" stage)
    match:
      rule_ids:
        - ssh_bruteforce_authlog_v2   # alert rule IDs
        - ssh_bruteforce_v1
      attack_step_kinds:
        - ssh_bruteforce              # attack chain step kinds
      correlation_rule_ids: []        # correlation rule integer IDs
      event_types: []                 # raw event types
    score_delta: 4
    confidence_weight: 1.0

  - id: accepted_ssh
    name: Accepted SSH Session
    tactic: initial_access
    technique_id: T1078
    required: true
    min_signals: 1
    after: brute_force                # must appear after the brute_force stage
    within_seconds: 1800              # within 30 minutes of brute_force
    match:
      attack_step_kinds:
        - ssh_bruteforce_success
      event_types:
        - ssh_auth
    score_delta: 6
    confidence_weight: 1.2

scoring:
  story_match_bonus: 8               # added when all required stages match
  max_story_score: 18                # cap on total score contribution from this story

attack:
  summary: "..."
  techniques:
    - T1110.001
    - T1078
  tags:
    - ssh
    - credential_access

response:
  summary: "..."
  recommendations:
    - "Rotate credentials."
    - "Review host activity."
```

## Stage match selectors

A stage can match on any combination of:

| Selector | Type | Description |
|---|---|---|
| `rule_ids` | `list[str]` | Alert `rule_id` values (exact match) |
| `attack_step_kinds` | `list[str]` | `AttackChainStepModel.label` or step kind from detector |
| `correlation_rule_ids` | `list[int]` | Correlation rule integer PKs |
| `event_types` | `list[str]` | Raw `event_type` values from net events |

At least one selector must be non-empty. Evidence must match any selector in the stage (OR across selector types).

## Temporal constraints

- `maxspan_seconds` on the story limits how far the last stage can be from the first stage's `first_seen_at`.
- `after: <stage_id>` requires the current stage to appear after the referenced stage's `matched_at`.
- `within_seconds` (requires `after`) limits how long after the `after` stage this stage can appear.

Stages without `after` are evaluated against all evidence within the overall `maxspan_seconds`.

## Scoring

Each matched stage contributes `score_delta` to the case risk score. The story caps total contribution at `max_story_score` (if set). When all required stages match, `story_match_bonus` is added once. The confidence score for each stage is the average of the evidence record confidence values, weighted by `confidence_weight` during story-level confidence calculation.

## Writing a new story

1. Create `rules/attack_stories/<story_id>.yml`.
2. Define the entity field that links evidence (usually `suspect_ip` or `agent_id`).
3. Order stages from earliest to latest in the attack progression.
4. Set `required: true` only for stages that are definitively diagnostic. Optional stages (`required: false`) contribute score but don't block story completion.
5. Start with `maturity: experimental` and `enabled: false`.
6. Validate: `python -m app.features.attack_chain.domain.story_loader` (or via `load_and_validate_attack_stories(strict=True)`).
7. Test by replaying case data.
8. Set `enabled: true` and `maturity: stable` when confirmed accurate.

## Validation

```python
from app.features.attack_chain.domain.story_loader import load_and_validate_attack_stories

report = load_and_validate_attack_stories(strict=True)
for error in report.errors:
    print(error)
```

`strict=True` raises on the first error rather than collecting them.

## What not to do

- Do not add a story that requires every stage to match. Use `required: false` for supporting signals that are indicative but not always present.
- Do not set `maxspan_seconds` to 0 on a multi-day investigation story — it disables the time constraint entirely, which can produce false positives.
- Do not match on alert `rule_id` values that are not stable. If a rule is renamed, update the story.
- Do not add `min_signals: 1` to stages where a single event is insufficient evidence — raise the threshold.
