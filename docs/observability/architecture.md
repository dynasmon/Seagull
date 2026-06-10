# Observability Architecture

Prometheus-native instrumentation for the Seagull backend and workers, scraped by
an **internal** Prometheus, queried **server-side** through a **typed allowlist**,
and surfaced through Seagull's own authenticated API.

There is no Grafana, no browser→Prometheus path, and no PromQL in the frontend.

## Architecture

```
workers / backend  ──/metrics (exposition)──►  Prometheus (internal :9090)
                                                     ▲
                                                     │ server-side PromQL (typed allowlist)
EUI observability  ──auth'd JSON──►  backend observability API ──┘
```

- **Emission** — application code calls `incr_counter` / `observe_hist` /
  `set_gauge` (`app/core/observability/metrics.py`). Every metric is declared
  once, with a bounded label set, in `app/core/observability/registry.py`.
- **Exposition** — the backend serves `GET /metrics` as Prometheus text
  exposition; each worker group manager serves the same on `:9100`. Both
  aggregate across child processes via multiprocess mode.
- **Scrape** — the internal `prometheus` service
  (`infra/prometheus/prometheus.yml`) scrapes the backend and the three worker
  groups every 15s. It has no published host port.
- **Query layer** — `app/core/integrations/prometheus.py` is the read transport;
  `app/core/observability/queries.py` is the typed allowlist that turns a *named*
  query + bounded parameters into server-built PromQL.
- **API** — `app/features/observability/` exposes the allowlist over an
  admin-gated, cached, degradation-tolerant HTTP API.

## Security model

- **Prometheus is internal-only.** No host port is published; only services on
  the `seagull` docker network reach it. Caddy proxies `/api/*` (portal
  listener) and `/agent/*` (dedicated mTLS listener, port 8444) to the backend,
  never `/metrics`.
- **No arbitrary PromQL.** The browser asks for a named query from the allowlist;
  the backend builds the PromQL. Range requests are capped (min step 15s, max
  span 7d, max 1500 points) so a client cannot request an enormous matrix.
- **Bounded cardinality.** Labels are a fixed, low-cardinality set per metric;
  raw IPs, IDs, hostnames, paths, and user identifiers are never label values
  (HTTP uses `route` templates and `status_class`, not raw path/code).
- **RBAC.** Every observability API route requires an admin principal
  (`require_admin`).

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `SEAGULL_METRICS_ENABLED` | `true` | Serve `/metrics`; emission is always on. |
| `SEAGULL_PROMETHEUS_ENABLED` | `true` | Enable the server-side query layer. |
| `SEAGULL_PROMETHEUS_URL` | `http://prometheus:9090` | Internal Prometheus base URL. |
| `SEAGULL_PROMETHEUS_TIMEOUT_SECONDS` | `5` | Per-request query timeout. |
| `SEAGULL_OBSERVABILITY_CACHE_TTL_SECONDS` | `10` | API result cache TTL (per worker). |
| `SEAGULL_WORKER_METRICS_PORT` | `9100` | Port each worker group manager exposes. |
| `SEAGULL_PROMETHEUS_RETENTION` | `15d` | Prometheus TSDB retention. |
| `PROMETHEUS_MULTIPROC_DIR` | `/tmp/seagull-metrics` | Multiprocess aggregation dir (tmpfs). |

When the query layer is disabled or Prometheus is unreachable the API degrades
gracefully (returns `available:false`) rather than erroring.

## Metric catalogue

Declared in `app/core/observability/registry.py` (source of truth). Counters end
`_total`; histograms carry `_bucket`/`_sum`/`_count`; all labels are bounded.

| Domain | Metrics |
|---|---|
| HTTP | `http_requests_total`, `http_request_duration_ms` |
| API | `api_cache_hit_total`, `api_route_latency_seconds` |
| Agent auth/identity | `agent_auth_requests_total`, `agent_bootstrap_token_*`, `agent_identity_enroll_total`, `agent_credential_rotate_total`, `agent_cert_renew_total`, `agent_identity_reissue_total`, `agent_disable_total`, `agent_enable_total` |
| Realtime | `realtime_publish_topic_total`, `realtime_publish_dropped_total`, `realtime_stream_connections_total`, `realtime_stream_reconnect_total`, `realtime_stream_disconnect_total`, `realtime_cursor_gap_total`, `realtime_unauthorized_topic_total`, `realtime_delivery_coalesced_total` |
| Ingest (receive) | `ingest_batches_received_total`, `ingest_events_received_total`, `ingest_events_sampled_total` |
| Ingest (worker) | `ingest_batches_processed_total`, `ingest_events_processed_total`, `ingest_loop_errors_total`, `ingest_hot_path_latency_seconds`, `ingest_optional_sink_latency_seconds`, `ingest_optional_sink_queue_depth`, `ingest_optional_sink_dropped_total`, `ingest_queue_depth`, `ingest_backpressure_active`, `ingest_storm_active` |
| Detection | `detection_cycles_total`, `detection_cycle_duration_seconds`, `detection_rule_evaluations_total`, `detection_rule_matches_total`, `detection_rule_errors_total`, `detection_rule_eval_latency_seconds` |
| Alerts | `alert_created_total` |
| Overview | `overview_live_write_failed_total` |
| Workers | `worker_up`, `worker_starts_total`, `worker_exits_total`, `worker_child_runtime_seconds` |

## Query allowlist

Declared in `app/core/observability/queries.py`. Each query is self-describing
(`unit`, `kinds`) so the UI renders panels without embedding query knowledge.

| Key | Title | Unit |
|---|---|---|
| `http_request_rate` | HTTP request rate | ops |
| `http_error_ratio` | HTTP 5xx ratio | ratio |
| `http_latency_p95_ms` | HTTP latency p95 | ms |
| `http_latency_p99_ms` | HTTP latency p99 | ms |
| `ingest_events_received_rate` | Events received/s | ops |
| `ingest_events_processed_rate` | Events processed/s | ops |
| `ingest_events_sampled_rate` | Events shed/s | ops |
| `ingest_hot_path_p95_seconds` | Ingest hot-path p95 | seconds |
| `ingest_queue_depth` | Ingest queue depth | count |
| `ingest_backpressure_active` | Backpressure active | bool |
| `ingest_storm_active` | Storm active | bool |
| `detection_cycle_rate` | Detection cycles/s | ops |
| `detection_cycle_p95_seconds` | Detection cycle p95 | seconds |
| `detection_rule_eval_rate` | Rule evaluations/s | ops |
| `detection_rule_match_rate` | Rule matches/s | ops |
| `detection_rule_error_rate` | Rule errors/s | ops |
| `alert_created_rate` | Alerts created/s | ops |
| `alert_created_rate_by_severity` | Alerts created/s by severity | ops |
| `workers_up` | Workers up | count |
| `workers_up_by_group` | Workers up by group | count |
| `worker_start_rate` | Worker starts/s | ops |
| `worker_exit_rate_by_outcome` | Worker exits/s by outcome | ops |

## HTTP API

All routes are under `/observability`, require an admin token, and return either
a typed shape (status/catalogue) or the query envelope.

| Method | Path | Returns |
|---|---|---|
| GET | `/observability/status` | `{enabled, available}` |
| GET | `/observability/catalogue` | `{queries: [...]}` |
| GET | `/observability/query/{key}?window=` | instant envelope |
| GET | `/observability/query/{key}/range?start&end&step&window` | range envelope |

Query envelope:

```json
{ "available": true, "error": null,
  "result": { "key": "...", "title": "...", "unit": "ops", "kind": "instant",
              "result_type": "vector",
              "samples": [{ "metric": {}, "value": 1.5, "timestamp": 1700000000.0 }] } }
```

- `window` ∈ `{1m, 5m, 15m, 1h}` (rate queries only).
- `start`/`end` are epoch seconds; `step` is seconds. Omitted range params default
  to the last hour. Out-of-bounds requests return `400`.
- Validation errors → `400`; a disabled/unreachable Prometheus →
  `200 {available:false}`; an upstream query failure → `200 {available:true,
  result:null, error}` (logged server-side).

## Operations

**Validate the scrape config** (uses the pinned image, matches prod):

```bash
./infra/prometheus/validate.sh        # promtool check config
docker compose config -q              # compose validity
```

**How scraping works.** Prometheus scrapes `seagull-backend:8000/metrics` and
each worker group at `:9100/metrics` every 15s, tagging series with `component`
and `worker_group`. Backend and workers run multiple processes; multiprocess mode
(`PROMETHEUS_MULTIPROC_DIR` on a fresh tmpfs per container) aggregates series
correctly and avoids stale per-pid carryover across restarts.

**Troubleshooting.**

- *API panels show "metrics unavailable".* Check `/observability/status`. If
  `available:false`, Prometheus is down/unreachable or `SEAGULL_PROMETHEUS_ENABLED`
  is off. Confirm the `prometheus` service is healthy and on the `seagull` network.
- *Internal debug page (`features/internal/views/debug.tsx`) shows "No HTTP
  counters".* That panel reads the legacy JSON shape from `/metrics`, which now
  serves Prometheus text exposition. The supported interface is the authenticated
  observability API and portal view.
- *A worker target is down in Prometheus.* The group manager binds `:9100`
  best-effort; a bind failure is logged and never takes the group down. Check the
  worker logs (`journalctl`/container logs) for `metrics` bind errors.

## Extension contracts

- **Add a metric** — declare it in `registry.py` (name + kind + bounded labels +
  buckets), then emit via the facade. Undeclared names are a warn-once no-op.
- **Add a panel** — add a `QuerySpec` to the catalogue in `queries.py`. It must
  reference only declared metrics (enforced by tests) and use bounded labels in
  `by(...)`.

## Tests

- `backend/tests/test_prometheus_query_layer.py` — transport + allowlist unit tests.
- `backend/tests/test_observability_api.py` — service + router (RBAC, caching, degradation).
- `backend/tests/test_observability_infra_consistency.py` — scrape-config ↔ compose
  ↔ worker-port consistency, allowlist ↔ registry grounding, metric naming, the
  emission→exposition contract, and `docker compose config` validity.
- `backend/tests/test_observability.py` — emission facade + snapshot.
