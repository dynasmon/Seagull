# Analytical sink delivery

ClickHouse and the Elasticsearch warm index are projections of the ingest path.
They used to be fed by two in-memory `queue.Queue` instances inside the ingest
worker: a full queue dropped the batch, exhausted retries dropped the batch, a
restart dropped everything still in memory, and partial `bulk` failures were
counted as success. Events acknowledged as durable by the API could therefore be
absent from hunt and the analytics pages with no record that they were ever lost.

Delivery is now a transactional outbox with a reconciler on top.

## Write path

```
ingest worker (single transaction)
  ├─ INSERT net_events
  ├─ UPSERT rollups
  └─ INSERT event_outbox   (sink='clickhouse', sink='warm')

sink-dispatcher (one thread per sink)
  claim (lease) → deliver → settle
                            ├─ delivered      → DELETE the row
                            ├─ transient fail → shrink the row to the failed events, back off
                            └─ permanent fail → event_outbox_dead_letter

projection-reconciler
  per settled minute: count(net_events) vs count(projection)
                      → projection_divergence_ratio
                      → re-enqueue the missing ids into event_outbox
```

Because the outbox row and the events land in the same commit, there is no window
where an event is durable in PostgreSQL and unknown to the sinks. A batch leaves
`event_outbox` only after the sink confirms it.

## At-least-once, and why duplicates are harmless

A dispatcher that dies mid-delivery leaves the row leased; the lease expires
after `SEAGULL_SINK_LEASE_SECONDS` and another pass redelivers it. Both sinks
absorb the repeat:

- ClickHouse receives `insert_deduplication_token = outbox:<batch id>`, so the
  same batch inserted twice collapses to one block. `net_events_raw` is also a
  `ReplacingMergeTree` keyed on `pg_event_id`.
- Elasticsearch receives a deterministic `_id`: the hot-store event id when the
  event was persisted, otherwise a SHA-1 of the event fingerprint. Re-indexing
  the same document overwrites it instead of duplicating it.

## Failure classification

`bulk` responses are parsed item by item. A 4xx other than 429 is permanent —
retrying a mapping conflict never succeeds — and those documents go straight to
`event_outbox_dead_letter` while the rest of the batch continues. Everything else
is transient: the row is rewritten with only the failed events and rescheduled
with exponential backoff up to `SEAGULL_SINK_MAX_ATTEMPTS`, after which the
remainder is dead-lettered. The same classification backs the three ES indexers
(`app/shared/indexing/bulk.py`).

## Reconciler

The dispatcher guarantees that nothing is dropped after the outbox row exists.
The reconciler answers the wider question — *is the projection actually complete?*
— and repairs history that predates this design or was lost by a path outside it.

Each pass compares, minute by minute, the count of `net_events` against:

- ClickHouse rows with `pg_event_id > 0`;
- Elasticsearch documents in `SEAGULL_PROJECTION_SEARCH_INDEX_PATTERN` that have
  an `id` field. Warm-index documents have no `id`, so they never mask a missing
  hot event.

Only minutes where the projection is short are drilled into ids, so a healthy
system costs two aggregate queries per pass. Missing ids are re-enqueued into the
outbox — for ClickHouse under the `clickhouse` sink, for Elasticsearch under the
`search` sink, which indexes into the write alias — bounded by
`SEAGULL_PROJECTION_REPAIR_MAX_EVENTS` per pass.

Two boundaries keep the comparison honest:

- **Settle horizon.** Minutes younger than
  `SEAGULL_PROJECTION_RECONCILE_SETTLE_SECONDS` are not judged. Sequence values
  are handed out before commit, so a very recent minute is legitimately still
  filling in.
- **Backpressure.** Under an ingest storm the platform samples the hot and
  analytics paths at different rates, so divergence is deliberate. Passes are
  skipped entirely while backpressure is active, which also keeps the repair
  budget from adding load during an incident.

## Operating it

| Signal | Meaning |
|---|---|
| `sink_outbox_pending_events{sink}` | events waiting for a sink; normal steady state is near zero |
| `sink_outbox_oldest_age_seconds{sink}` | how long the oldest batch has been stuck |
| `sink_outbox_dead_letter_events{sink}` | events delivery gave up on; always worth a look |
| `projection_divergence_ratio{sink}` | fraction of the reconciled window missing from the projection |
| `projection_repair_enqueued_total{sink}` | events the reconciler pushed back through delivery |
| `projection_reconcile_errors_total{sink}` | passes that could not read the projection at all |

A store that cannot be read fails only its own sink: the pass keeps reconciling
the others and the loop keeps its normal interval, so one unreachable backend
never turns the reconciler into a retry loop against the healthy ones. The cost
is that the divergence gauge for that sink freezes at its last value, which is
what `projection_reconcile_errors_total` exists to make visible.

Alerts live in `infra/prometheus/rules/seagull-projections.yml`.

Dead letters keep the full payload, so a replay after fixing the root cause is a
copy back into `event_outbox`:

```sql
INSERT INTO event_outbox (sink, payload, event_count)
SELECT sink, payload, event_count FROM event_outbox_dead_letter WHERE id = :id;
```

Rows are purged after `SEAGULL_SINK_DEAD_LETTER_RETENTION_DAYS`.

To backfill a long history — a fresh ClickHouse, or a projection rebuilt from
scratch — raise `SEAGULL_PROJECTION_RECONCILE_LOOKBACK_MINUTES` and
`SEAGULL_PROJECTION_REPAIR_MAX_EVENTS`, and let successive passes walk it. The
work always flows through the same delivery path, so it retries and dead-letters
like any other batch.
