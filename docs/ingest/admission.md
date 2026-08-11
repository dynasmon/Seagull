# Ingest admission control

`POST /ingest/events` answers `durable: true` and returns before the events are
written. Everything that decides whether a batch can actually be stored has to
happen before that answer, or the platform promises durability it cannot keep.

Two defects made that promise unsafe. The event schema accepted values the hot
store columns could not hold, so a single oversized string aborted the worker
transaction that carried up to 50 messages of up to `SEAGULL_INGEST_MAX_BATCH`
events each — and the retry counter was then bumped for every message in that
transaction, not just the offending one. And the body guard only read
`Content-Length`, so a chunked upload, or a request without the header, was
never measured at all.

Admission is now a contract with two layers: the edge rejects what it cannot
store, and the worker repairs anything that reaches it anyway.

## The storage contract

`app/features/events/storage_contract.py` declares what the hot store accepts.
The limits are not chosen numbers; they are the `net_events` column widths, and
`tests/test_event_storage_contract.py` asserts every one of them against
`NetEventModel.__table__` so a column change cannot silently outgrow the
contract.

| Field | Limit | Source |
|---|---|---|
| `agent_id` | 1..64 chars, `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` | `net_events.agent_id`, agent enrollment |
| `event_type` | 1..32 chars, `^[A-Za-z0-9][A-Za-z0-9._:-]{0,31}$` | `net_events.event_type` |
| `src_ip`, `dst_ip` | a parseable IPv4/IPv6 address, ≤ 45 chars | `net_events.src_ip` |
| `src_port`, `dst_port` | 0..65535 | port semantics |
| `proto` | ≤ 16 chars | `net_events.proto` |
| `bytes` | 0..2⁶³-1 | `net_events.bytes` (bigint) |
| `extra` keys | ≤ 128 chars | JSONB key sanity |
| `extra` strings | ≤ 4096 chars | measured against real traffic (observed max 844) |
| `extra` values | ≤ 512 nodes, ≤ 8 levels deep | bounds worker memory per event |
| `extra` payload | ≤ 32 KiB serialized | measured against real traffic (observed max 3352 B) |
| derived columns | `dns_qname` 512, `proc_exe` 512, `fim_path` 1024, … | `HOT_TEXT_COLUMN_MAX_CHARS` |

The same file holds both halves of the contract:

- `extra_violation()` and the `NetEvent` field constraints **detect**. They run
  at the API boundary and answer `422` naming the event index and the field.
- `fit_*()` **repair**. They run in the worker and coerce any value into
  something the column can hold.

## Strict at the edge, tolerant in the worker

The API is the trust boundary, so it fails loudly: a batch containing one
out-of-contract event is refused whole, before enqueue, before `durable: true`.
The agent gets a `422` that names the offending index and field instead of a
silent loss four retries later.

The worker is the interior, so it never fails on data. `app/workers/ingest/parser.py`
runs every column-bound field through the contract: strings are truncated to
their column width, addresses that do not parse become `NULL`, ports outside
0..65535 become `NULL`, `bytes` is clamped, and `extra` is trimmed to the
structural limits. A message queued before the contract existed, or replayed
from the dead letter list, can no longer poison the transaction that carries the
other 499,999 events.

Repair is not free of consequence, so it is counted:
`ingest_event_fields_normalized_total{field}` should sit at zero once the API is
enforcing the contract. A sustained rate means something is enqueuing events
that never passed the boundary check, and `IngestEventFieldsNormalized` fires.

`NetEventDB`, the read model, deliberately shares none of this. Rows written
before the contract existed still have to render in hunt, so the read path stays
permissive; only the write path is strict.

## Body ceilings

Two enforcement points, both counting bytes actually received:

- **Caddy** rejects at the edge with `request_body max_size`, before a byte
  reaches the backend: `SEAGULL_EDGE_MAX_BODY` for `/api/*`,
  `SEAGULL_EDGE_AGENT_MAX_BODY` for the agent listener on `:8444`, and
  `SEAGULL_EDGE_ENROLL_MAX_BODY` for enrollment on `:8445`.
- **The backend** enforces it again in `app/core/api/body_limit.py`, an ASGI
  middleware that wraps `receive` and adds up the bytes it hands to the route.
  A `Content-Length` that is absent, invalid, or lying about the payload changes
  nothing: the count is what was actually delivered. An oversized declared
  length is answered before the body is read at all.

The limit is per route class, because the routes are not comparable:
`SEAGULL_MAX_REQUEST_BODY_BYTES` (2 MiB) covers everything, and
`SEAGULL_INGEST_MAX_REQUEST_BODY_BYTES` (8 MiB) covers `/ingest/events`, which
has to hold a full `SEAGULL_INGEST_MAX_BATCH`. Startup refuses a configuration
where the ingest ceiling is below the default. Rejections are counted by
`http_request_body_rejected_total{policy}`; keep the Caddy values in step with
the backend values, or the edge becomes the effective limit without saying so.

## Dead letter operations

A batch that cannot commit after `SEAGULL_INGEST_WORKER_MAX_MESSAGE_RETRIES`
attempts is parked in `<queue>:deadletter` (200 most recent messages, seven day
TTL). Until now nothing could read or replay that list. Three admin routes now
can:

| Route | Effect |
|---|---|
| `GET /ingest/deadletter` | Batch summaries: agent, event counts, retries, age, size. Never the payloads. |
| `POST /ingest/deadletter/redrive?limit=N` | Moves the oldest N batches back to the ingest queue with a fresh retry budget and restores the backlog counter. |
| `POST /ingest/deadletter/purge?limit=N` | Drops the oldest N batches, or all of them when `limit` is omitted. |

Redrive is safe precisely because of the parser repair above: a batch that was
parked for a value the columns could not hold now commits with that value
truncated instead of aborting the transaction again. A message whose JSON cannot
be decoded is put back rather than dropped, and reported as `skipped_messages`.

When Redis is unreachable these routes answer `503`. They never answer "the
dead letter list is empty" for an outage — an empty answer means empty.

`ingest_queue_depth{queue="deadletter"}` carries the depth, and
`IngestDeadLetterNotEmpty` fires after ten minutes with anything parked: the
list is capped and expires, so an unattended alert eventually becomes real data
loss.
