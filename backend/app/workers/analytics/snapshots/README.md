# Dashboard snapshots worker

Materializes the aggregated payload of the hottest dashboard pages into Postgres
(CQRS pattern: background compute, O(1) read in the handler). The HTTP handler
never calls this worker — all communication happens through the
`dashboard_snapshots` table.

## Topology

```
worker (this process)                  API (uvicorn)
  fixed tick (30s)                       GET /overview, /vuln/..., ...
  for each enabled page                    SWR (Redis) --------- fresh? serve
    for each registered scope               | miss/revalidate
      Redis lock per scope                  v
      raw_compute(params)              SnapshotPage.compute
      UPSERT dashboard_snapshots  -->    SELECT by (page, scope_key)
                                          fresh? serve : fallback raw_compute
```

Converted pages (one feature flag per page, rollback = turn the flag off):

| page | flag | scopes |
| --- | --- | --- |
| `overview` | `SEAGULL_SNAPSHOT_OVERVIEW_ENABLED` | static (global `SEAGULL_SNAPSHOT_OVERVIEW_WINDOWS` windows + lite) + dynamic |
| `exposure_summary` | `SEAGULL_SNAPSHOT_EXPOSURE_SUMMARY_ENABLED` | single (global) |
| `network_topology_summary` | `SEAGULL_SNAPSHOT_TOPOLOGY_SUMMARY_ENABLED` | single (global) |
| `vuln_summary` | `SEAGULL_SNAPSHOT_VULN_SUMMARY_ENABLED` | router defaults |
| `vuln_posture` | `SEAGULL_SNAPSHOT_VULN_POSTURE_ENABLED` | router defaults |

## Store: why Postgres (and not ClickHouse)

- Low cardinality: scopes = global pages + agents actually being queried
  (capped by `SEAGULL_SNAPSHOTS_DYNAMIC_MAX_SCOPES`, default 20). ClickHouse's
  strengths (cheap bulk writes, native TTL) carry no weight at ~1 row/s.
- Real atomicity: `INSERT ... ON CONFLICT DO UPDATE` swaps the whole row in one
  transaction — partial state is never visible. In ClickHouse
  (ReplacingMergeTree) convergence depends on merges and would require
  `FINAL`/`argMax` on the read path.
- Availability: the dashboard read path cannot depend on ClickHouse, which is
  optional (`SEAGULL_CLICKHOUSE_REQUIRED=false` in the workers) and enters
  degraded mode under ingest storms — exactly the scenario where the dashboard
  most needs to respond.
- One generic table (`page` + `scope_key` as PK, JSONB payload) instead of a
  table per page: every reader does the same PK point-read, no per-page
  indexing is needed, and new pages require no migration. Payload versioning is
  per page via `schema_version`.

## Scope registry

- **Static (code)**: each page registers `static_scopes()` alongside
  `register_snapshot_page(...)` in the feature's service (guarantees worker and
  handler derive the same `scope_key` from the same read-model `key_builder`).
- **Dynamic (actual queries)**: pages with `track_params` (today only
  `overview`) record every queried scope in a Redis ZSET
  (`seagull:snapshots:seen:<page>`, score = last access). The worker recomputes
  only the scopes seen within the last `SEAGULL_SNAPSHOTS_DYNAMIC_WINDOW_HOURS`
  hours (capped by `SEAGULL_SNAPSHOTS_DYNAMIC_MAX_SCOPES`). Per-agent overview
  is therefore only materialized for agents someone actually queried; the first
  access falls back to inline compute and from the next tick onward it is
  served from the snapshot.
- Highly combinatorial scopes (fixed `start_ts`/`end_ts` ranges, windows
  outside the preset, non-default params) are `bypass`: they never consult the
  store and go straight through SWR with inline compute.

## Freshness contract

Each row carries `computed_at` and `computed_ms`; the handler exposes both in
`meta.snapshot` (with `age_s` and `degraded`) for debugging. Handler rules:

- `age <= 2 × tick` → serve normally (`snapshot_lookup_total{outcome="hit"}`).
- `2 × tick < age <= SEAGULL_SNAPSHOTS_MAX_AGE_MULTIPLIER × tick` → serve with
  `meta.snapshot.degraded=true` (`outcome="degraded"`).
- `age` above the ceiling, missing row, `schema_version` mismatch, or read
  error → fallback to the old inline compute, with a structured warning
  (`snapshot_fallback_inline_compute`) and `snapshot_fallback_total{reason}`.
- A page may register an optional `freshness_probe(payload, params)`: when the
  probe detects that the stored payload has fallen behind reality, the read
  falls back to inline compute (`reason="outdated"`). Snapshot age cannot catch
  this case: while the stream is idle the worker keeps recomputing on every
  tick (`computed_at` stays fresh) but the content remains frozen at the last
  activity. The overview probe compares the payload's `meta.window_end` against
  the newest live bucket in Redis, with a margin of 2 × tick — the margin must
  exceed one worker tick plus compute time, otherwise steady traffic would
  bypass the store on every read — and applies to global scopes only, since the
  live peek carries no agent dimension. Probe errors never break the read —
  when in doubt, the snapshot is served.

The endpoints' response contract does not change: the SWR/ETag layer stays
above this one, and `meta` is excluded from the ETag hash.

## Concurrency

Multiple worker instances can coexist: each scope is protected by a distributed
lock (`acquire_lock`/`release_lock` from `app/core/cache/locks.py`, the same
primitive as the `single_flight` used on the SWR path). Whoever misses the lock
skips the scope (`outcome="locked"`). Without Redis, a single instance is
assumed and the compute proceeds anyway.

## Invalidation

v1 is fixed-tick only (`SEAGULL_SNAPSHOTS_EVERY_SECONDS`, default 30s) — cheap,
predictable, and sufficient given that the SWR layer above already absorbs
bursts. Event-driven invalidation (e.g. a critical alert publishing a wake-up
via Redis pub/sub to advance the tick) is left for a later iteration; the
current design accommodates it without a schema change. Retention: rows not
rewritten for `SEAGULL_SNAPSHOTS_RETENTION_HOURS` (24h) are pruned — this
removes dynamic scopes that stopped being queried.

## Metrics (Prometheus)

- `snapshot_compute_seconds{page,scope}` — compute latency per page+scope
  (the `scope` label is the compact form `w60:global:lite`, not the full
  scope_key, to keep cardinality bounded).
- `snapshot_oldest_age_seconds{page}` — age of the oldest snapshot per page.
- `snapshot_fallback_total{page,reason}` — inline fallbacks (missing/stale/schema/error/outdated).
- `snapshot_compute_errors_total{page}` — worker compute errors.
- `snapshot_lookup_total{page,outcome}` — hit/degraded/bypass/misses in the handler.
- `snapshot_writes_total{page,outcome}` / `snapshot_cycle_seconds` /
  `snapshot_store_read_seconds{page}` — cycle health and point-read cost.

## Operations

Runs as the `dashboard-snapshots` child of the `intelligence` group
(`python -m app.workers.manager intelligence`), gated by
`SEAGULL_SNAPSHOTS_WORKER_ENABLED`. Automatic backoff while ClickHouse is in
`degraded` state (the same signal used by the prewarm). If the worker is down,
the handlers keep working through the inline fallback — the cost returns to the
pre-snapshot SWR-only path.
