# Detection Engineering Architecture

## Module boundaries

Detection engineering spans three layers. Each layer has a single responsibility.

```
rules/packs/**/*.yml          ← detection content (YAML)
rules/attack_stories/**/*.yml ← attack story content (YAML)

backend/app/features/detections/   ← owns rule loading, validation, compilation, backtesting
backend/app/features/alerts/       ← owns alert models, rule execution, governance overlays
backend/app/features/correlations/ ← owns correlation rules, incidents, engines
backend/app/features/attack_chain/ ← owns attack chain cases, steps, story evaluation
backend/app/features/ueba/         ← owns behavioral baselines, findings, detector runtime

backend/app/workers/intelligence/rules/      ← schedules rule execution (no logic)
backend/app/workers/intelligence/attack_chain/ ← schedules attack chain processing (no logic)
backend/app/workers/intelligence/correlations/ ← schedules correlation cycles (no logic)
backend/app/workers/intelligence/ueba/         ← schedules UEBA detector cycles (no logic)
```

## Data flow

```
net_events
    │
    ▼
rules.runner (every N seconds)
    │  app.features.alerts.rule_runtime.run_all_rules()
    ▼
alerts table
    │
    ├──► correlations worker (every 60s)
    │        app.features.correlations.service.run_correlations()
    │        → CorrelationIncidentModel (durable)
    │
    ├──► ueba worker (every 60s)
    │        app.features.ueba.worker_runtime.run_ueba_cycle()
    │        → UebaBaselineModel / UebaFindingModel (durable)
    │        → shared alert persistence path for promoted findings
    │
    └──► attack_chain worker (continuous batch)
             app.features.attack_chain domain
             → AttackChainCaseModel / AttackChainStepModel (durable)
             → AttackStoryEvaluation applied to case context
```

## Feature stable import surfaces

Workers call features through `worker_runtime` modules. This keeps worker entrypoints thin and prevents feature internals from leaking into the worker layer.

| Worker | Imports from |
|---|---|
| `intelligence.rules.runner` | `features.alerts.rule_runtime` |
| `intelligence.attack_chain.main` | `features.attack_chain.worker_runtime` |
| `intelligence.correlations.main` | `features.correlations.worker_runtime` |
| `intelligence.ueba.main` | `features.ueba.worker_runtime` |

The `worker_runtime` modules are the stable API contract between workers and features. They may call `features.*.service` and `features.*.repository` internally. Workers must not bypass them.

## Rule lifecycle

```
YAML file
  └─ loader.py discovers and normalizes to dict
       └─ compatibility.py applies env_overrides, parses version
            └─ registry.py applies DB overrides / tuning / suppressions
                 └─ engine.py (v1) or compiler.py (v2) executes query
                      └─ AlertModel created and committed
```

## Governance overlay

Rule YAML is the baseline definition. Portal-managed governance records can patch behaviour at runtime without editing files:

- `AlertRuleOverrideModel` — enable/disable, change severity, window, cooldown, condition
- `AlertRuleTuningModel` — context-scoped adjustments (by `agent_id`, `src_ip`, `dst_ip`, etc.)
- `AlertRuleSuppressionModel` — scheduled or conditional silence windows

The overlay is applied by `features.alerts.rule_registry_runtime` before the engine runs each cycle.

## Schema versions

Two rule schema versions coexist at runtime.

| Version | Field | Aggregation names | Execution path |
|---|---|---|---|
| v1 | `schema_version: 1` (default) | `aggregate_count`, `distinct_count`, `multi_distinct` | `engine.py` direct SQL |
| v2 | `schema_version: 2` | `threshold`, `cardinality`, `multi_cardinality` | `compiler.py` AST → SQL |

v1 rules use runtime field names (`src_ip`, `dst_ip`). v2 rules use canonical field names (`source.ip`, `destination.ip`). The `compatibility.py` module converts between the two representations and can translate a v1 rule dict into v2 form for migration tooling.

## Canonical field model

All v2 rules and the Sigma importer reference fields by canonical name (e.g. `source.ip`). The canonical field map lives in:

```
backend/app/features/detections/domain/canonical_fields.py
```

See [canonical_fields.md](canonical_fields.md) for the full field reference.

## Correlation engine

Correlations run independently of the rules engine. They read existing alerts and produce `CorrelationIncidentModel` records using pluggable strategy engines (sequence, threshold, cardinality, burst, entity state). See [correlation_engine.md](correlation_engine.md).

## Attack chain and attack stories

The attack chain worker maintains durable `AttackChainCaseModel` records per suspect entity. Cases accumulate `AttackChainStepModel` evidence over time. After each batch, `evaluate_attack_stories()` applies story templates to the case evidence to identify multi-stage kill-chain progressions. See [attack_stories.md](attack_stories.md).

## What belongs where

| Layer | Owns |
|---|---|
| `workers/` | Scheduling loops, backoff, process lifecycle |
| `features/*/worker_runtime.py` | Stable import surface, config loading |
| `features/*/service.py` | Use cases (orchestration) |
| `features/*/repository.py` | Database access |
| `features/*/domain/` | Pure logic — no I/O, no ORM |
| `features/*/api.py` | HTTP contracts only |
| `frontend/src/features/*/page.tsx` | Thin page shells |
| `frontend/src/features/*/components/` | Focused reusable UI |
| `frontend/src/shared/components/` | Generic reusable components |

## What not to do

- Do not add a new container for a new worker. Add a child spec to `app.workers.manager.GROUPS`.
- Do not import `features.*.repository` directly from a worker entrypoint.
- Do not put SQL queries in a worker module.
- Do not duplicate canonical field definitions. `canonical_fields.py` is the single source of truth.
- Do not bypass the governance overlay by constructing rule dicts by hand in the engine.
- Do not enable rules in production without first running validation and a backtest.
