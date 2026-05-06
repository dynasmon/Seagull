# Correlation Engine

Correlations group existing alerts into higher-level incidents using configurable strategy engines. They run independently of the rules engine and produce durable `CorrelationIncidentModel` records.

## How correlations work

The correlations worker (`app.workers.intelligence.correlations.main`) calls `features.correlations.service.run_correlations()` on a configurable interval (default 60s). Each cycle:

1. Fetch recent alerts (up to `SEAGULL_CORRELATIONS_MAX_ALERTS`, default 5000) within the configured age window (`SEAGULL_CORRELATIONS_MAX_AGE_MINUTES`, default 60 min).
2. For each enabled correlation rule, evaluate the alert dataset against the rule's strategy engine.
3. Create or update `CorrelationIncidentModel` records for matches.
4. Attach `CorrelationIncidentEvidenceModel` records linking incidents to their constituent alerts.

## Durable incidents

`CorrelationIncidentModel` is persistent — incidents survive across worker restarts and can be updated as new alerts arrive. An incident has:

- `status`: `open`, `triaged`, `closed`, `suppressed`
- `risk_score`: computed by the engine
- `stage_hits`: which stages of a multi-stage rule were matched
- `unique_rules`: alert rule IDs that contributed evidence
- `started_at` / `last_seen_at`: temporal span of matched evidence

Status transitions are managed by analysts in the portal (admin-only) or automatically when the engine marks an incident `closed`.

## Strategy engines

The engine facade (`features.correlations.engine`) dispatches to strategy-specific engine classes.

### sequence / chain

`SequenceEngine` evaluates ordered stage progressions. Each stage has match criteria (alert `rule_id` patterns, field filters). The engine checks that stages appear in order within the configured `window_seconds`.

Use when you need to assert that event A happened before event B.

### threshold

`ThresholdEngine` fires when the alert count meeting the filter criteria exceeds a threshold.

### cardinality

`CardinalityEngine` fires when the number of distinct values for a field exceeds a threshold within a group.

### entity_state

`EntityStateEngine` tracks per-entity state transitions. Use when detection depends on accumulated state rather than a single window.

### risk_aggregation

`RiskAggregationEngine` aggregates weighted risk scores across multiple rule hits and fires when the total exceeds a threshold.

### temporal_join

`TemporalJoinEngine` joins two or more alert streams by entity and time proximity.

## Writing a correlation rule

Correlation rules are stored in the database and managed via the portal (admin-only). The rule schema:

```json
{
  "name": "SSH brute force to success",
  "description": "Brute-force attempt followed by successful SSH session.",
  "strategy": "sequence",
  "group_by": "src_ip",
  "window_seconds": 1800,
  "min_alerts": 2,
  "enabled": true,
  "stages": [
    {
      "id": "brute_force",
      "name": "SSH Brute Force",
      "patterns": ["ssh_bruteforce_*"],
      "required": true
    },
    {
      "id": "success",
      "name": "Successful SSH",
      "patterns": ["ssh_accepted_*"],
      "required": true,
      "after": "brute_force"
    }
  ]
}
```

Fields:

| Field | Notes |
|---|---|
| `strategy` | Engine to use: `sequence`, `chain`, `threshold`, `cardinality`, `entity_state`, `risk_aggregation`, `temporal_join` |
| `group_by` | Alert field to group incidents by (e.g. `src_ip`, `dst_ip`, `agent_id`) |
| `window_seconds` | Maximum time span for a correlation match |
| `min_alerts` | Minimum number of matching alerts required |
| `stages` | Ordered list of stage definitions (required for sequence/chain) |
| `patterns` | Glob patterns matched against alert `rule_id` |
| `configs` | Engine-specific extra configuration |

## The stable import surface

Worker code for correlations imports only from `features.correlations.worker_runtime`:

```python
from app.features.correlations.worker_runtime import (
    CorrelationsWorkerConfig,
    load_worker_config,
    load_enabled_rules,
    run_correlation_cycle,
)
```

The `run_correlation_cycle(cfg)` call manages its own `SessionLocal` context.

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `SEAGULL_CORRELATIONS_INTERVAL_SECONDS` | 60 | Seconds between correlation cycles |
| `SEAGULL_CORRELATIONS_MAX_ALERTS` | 5000 | Max alerts per cycle |
| `SEAGULL_CORRELATIONS_MAX_AGE_MINUTES` | 60 | Alert age horizon |
| `SEAGULL_CORRELATIONS_LOG_EVERY_SECONDS` | 60 | Logging interval |
| `SEAGULL_CORRELATIONS_WORKER_ENABLED` | true | Enable the correlations child in the intelligence group |

## Frontend

The portal exposes durable correlation incidents under the Correlations tab (admin-only). Incidents can be viewed, triaged, and closed. The frontend uses `CorrelationIncidentTable`, `CorrelationIncidentDrawer`, and `CorrelationIncidentTimeline` components.

## What not to do

- Do not query the alerts table directly in worker code. Use `run_correlation_cycle()`.
- Do not create incidents by inserting `CorrelationIncidentModel` rows outside the engine — the engine handles deduplication.
- Do not enable a correlation rule that has no tested patterns. Use the portal's dry-run option first.
