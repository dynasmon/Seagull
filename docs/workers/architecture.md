# Worker Architecture

## Overview

Workers are long-running background processes separate from the FastAPI backend. They own no database schema and call feature-layer code through stable import surfaces. The backend never imports worker internals.

```
                         ┌──────────────────────────┐
                         │  app.workers.manager      │
                         │  WorkerGroupManager       │
                         └──────────┬───────────────┘
             ┌──────────────────────┼──────────────────────┐
             │                      │                       │
      ┌──────▼──────┐       ┌───────▼──────┐       ┌───────▼──────┐
      │   ingest    │       │ intelligence │       │ maintenance  │
      └──────┬──────┘       └───────┬──────┘       └───────┬──────┘
             │                      │                       │
    3 children             6 children               2 children
```

## Worker groups

Three groups are defined in `app.workers.manager.GROUPS`.

### ingest

| Child name    | Module                                    |
|---------------|-------------------------------------------|
| ingest-worker | `app.workers.ingest.main`                 |
| es-indexer    | `app.workers.indexing.elasticsearch`      |
| rollup-1m     | `app.workers.analytics.rollup_1m`         |

Drain the ingest queue, index events into Elasticsearch, and pre-aggregate 1-minute rollups.

### intelligence

| Child name     | Module                                               | Env gate                           |
|----------------|------------------------------------------------------|------------------------------------|
| rules-runner   | `app.workers.intelligence.rules.runner`              | always on                          |
| ip-intel       | `app.workers.intelligence.ip_intel.main`             | always on                          |
| proto-intel    | `app.workers.intelligence.protocol.main`             | always on                          |
| attack-chain   | `app.workers.intelligence.attack_chain.main`         | always on                          |
| exposure-graph | `app.workers.intelligence.exposure.main`             | `SEAGULL_EXPOSURE_ENABLED` (default on)  |
| correlations   | `app.workers.intelligence.correlations.main`         | `SEAGULL_CORRELATIONS_WORKER_ENABLED` (default on) |
| ueba           | `app.workers.intelligence.ueba.main`                 | `SEAGULL_UEBA_ENABLED` (default on) |

### maintenance

| Child name        | Module / command                             | Env gate                                    |
|-------------------|----------------------------------------------|---------------------------------------------|
| audit-retention   | `app.workers.maintenance.audit_retention`    | always on                                   |
| bootstrap-rotator | `/scripts/agent_bootstrap_token_rotator.py` | `SEAGULL_MAINTENANCE_ENABLE_BOOTSTRAP_ROTATOR` |

## Running a group

```bash
python -m app.workers.manager run intelligence
# shortcut form
python -m app.workers.manager intelligence
```

Healthcheck:

```bash
python -m app.workers.manager health intelligence
# exits 0 if healthy, 1 otherwise
```

State is written to `$SEAGULL_WORKER_GROUP_STATE_DIR/<group>.json` (default `/tmp/seagull-worker-groups/`).

## WorkerGroupManager behaviour

`WorkerGroupManager` supervises child processes via `subprocess.Popen`. On each tick (0.5s poll):

1. Dead children are detected via `process.poll()`.
2. Quick failures (runtime < `SEAGULL_WORKER_GROUP_QUICK_FAIL_SECONDS`, default 15s) are counted in a sliding window (`SEAGULL_WORKER_GROUP_RESTART_WINDOW_SECONDS`, default 300s).
3. If quick failures exceed `SEAGULL_WORKER_GROUP_MAX_QUICK_FAILURES` (default 5), the group is marked non-viable and the manager exits with code 1.
4. Otherwise the child is restarted after an exponential backoff (initial `SEAGULL_WORKER_GROUP_RESTART_BACKOFF_INITIAL_SECONDS` default 1s, max `SEAGULL_WORKER_GROUP_RESTART_BACKOFF_MAX_SECONDS` default 30s).
5. `SIGTERM` / `SIGINT` to the manager forwards termination to all children and waits up to `SEAGULL_WORKER_GROUP_STOP_TIMEOUT_SECONDS` (default 20s) before force-killing.

The groups run as systemd services. Use `journalctl` to inspect logs, not docker logs.

## Intelligence worker entrypoints

### rules.runner

`app.workers.intelligence.rules.runner`

Polls `run_all_rules()` on a configurable interval (default 5s, minimum 0.25s, env `SEAGULL_RULES_EVERY_SECONDS`). On `OperationalError` the worker backs off up to 15s and retries — it never exits on transient DB errors.

Delegates entirely to `app.features.alerts.rule_runtime.run_all_rules`. The worker module contains no rule logic.

### attack_chain.main

`app.workers.intelligence.attack_chain.main`

Fetches events in batches, detects suspicious steps, attaches them to durable attack-chain cases, closes stale cases, and evaluates attack stories. Idle sleep interval is separate from active processing interval. Backs off up to 30s on errors.

Key env vars: `SEAGULL_ATTACK_CHAIN_BATCH_SIZE`, `SEAGULL_ATTACK_CHAIN_EVERY_SECONDS`, `SEAGULL_ATTACK_CHAIN_IDLE_SLEEP_SECONDS`.

### correlations.main

`app.workers.intelligence.correlations.main`

Runs correlation cycles on a configurable interval (default 60s, env `SEAGULL_CORRELATIONS_INTERVAL_SECONDS`). Delegates to `app.features.correlations.worker_runtime.run_correlation_cycle`.

### ueba.main

`app.workers.intelligence.ueba.main`

Runs bounded behavioral detector cycles on a configurable interval (default 60s, env `SEAGULL_UEBA_INTERVAL_SECONDS`). Delegates to `app.features.ueba.worker_runtime.run_ueba_cycle`; individual detector failures are recorded and isolated so one detector does not stop the rest of the cycle.

### ip_intel.main

`app.workers.intelligence.ip_intel.main`

Enriches unprocessed events with GeoIP / ASN data. Provider is selected via env vars (ipinfo or maxmind). Results are cached to avoid redundant lookups.

### protocol.main

`app.workers.intelligence.protocol.main`

Classifies application-layer protocols for events that did not have a protocol identified at ingest time.

### exposure.main

`app.workers.intelligence.exposure.main`

Computes and persists exposure risk posture per agent/asset using the exposure projector.

## Import rules

```
workers → features.*worker_runtime (stable surface)
workers → domain modules (pure logic, no DB)
workers MUST NOT → features.*.service, features.*.repository, features.*.api
features.*.worker_runtime → features.*.service (OK)
features.*.worker_runtime → features.*.repository (OK)
```

A worker that needs database access gets a `SessionLocal()` from `app.core.db` and passes it into feature-layer functions. The worker never builds ORM queries directly.

## What not to do

- Do not add DB migrations to a worker module. Migrations live in `alembic/`.
- Do not import `features.*.api` from a worker.
- Do not add business logic inside a worker entrypoint. The entrypoint schedules and loops; features own logic.
- Do not add a new container. Add a child spec to an existing group.
- Do not share state between children using in-process globals — children are separate processes.
