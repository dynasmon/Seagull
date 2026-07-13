# Redpanda — distributed event log

Redpanda is the Kafka-compatible distributed log that will replace Redis Streams in the
Seagull ingest pipeline. This introduces it in coexistence
mode: Redis Streams remains the primary transport, producers dual-write to both, and a
single pilot consumer reads from Redpanda behind a feature flag. Nothing is removed.

## Why Redpanda

- Kafka wire protocol: any Kafka client and the whole Kafka ecosystem (Connect, sinks)
  work unchanged.
- Single binary, no JVM, no ZooKeeper/KRaft; one container per node.
- Disk-backed retention: days or weeks of replay instead of RAM-bound Redis Streams.
- Horizontal scale by partitions across brokers, with per-partition replication.

## Topology

| Environment | File               | Brokers | Replication |
|-------------|--------------------|---------|-------------|
| dev         | `compose.yml`      | 1 (`redpanda`, dev-container mode) | 1 |
| production  | `compose.prod.yml` | 3 (`redpanda-1..3`, seeds fixed, `empty_seed_starts_cluster=false`) | 3 |

Ports per broker: Kafka internal `9092`, Kafka external `19092` (host-published,
localhost-bound in prod), Admin API `9644` (metrics + rpk). Pandaproxy (REST, `8082`)
listens on the internal network only and is not published.

Each node has a dedicated volume (`redpanda-data`, `redpanda-N-data`). The container
healthcheck is the native `rpk cluster health`.

## Topics

Provisioning is declarative and idempotent: `app/core/messaging/topics.py` is the
single source of truth and `python -m app.core.messaging.provision` (the
`redpanda-provision` one-shot compose service) creates missing topics and reconciles
retention on existing ones. Run it after every settings change.

| Topic                      | Partitions | Retention | Producer                          | Payload |
|----------------------------|------------|-----------|-----------------------------------|---------|
| `seagull.events.raw`       | 12         | 7d        | backend API (`ingest_events`)     | every accepted event, pre-sampling |
| `seagull.events.index`     | 12         | 7d        | ingest-worker (`es_stream_producer`) | hot events with `pg_event_id`, mirror of the `seagull:events:index` Redis Stream |
| `seagull.events.index.dlq` | 3          | 30d       | `es-indexer-redpanda`             | undecodable / permanently failed index events, with a `_dlq` block (reason, error, source partition/offset) |
| `seagull.alerts.raw`       | 3          | 30d       | none yet (reserved for the alerts wave) | alert lifecycle |

There is no `seagull.enrichment.jobs` topic: the audit showed the enrichment worker
(ip-intel) polls Postgres/ClickHouse and consumes no queue, so there is nothing to
mirror. A topic will be added when that worker gains a real job stream.

Environment overrides (read by the provisioner): `SEAGULL_REDPANDA_EVENTS_PARTITIONS`
(12), `SEAGULL_REDPANDA_EVENTS_RETENTION_HOURS` (168), `SEAGULL_REDPANDA_ALERTS_RETENTION_HOURS`
(720), `SEAGULL_REDPANDA_DLQ_RETENTION_HOURS` (720), `SEAGULL_REDPANDA_TOPIC_REPLICATION`
(1 in dev, 3 in `compose.prod.yml`).

## Partition key

All event topics are keyed by `agent_id`. Events from one agent always land in the
same partition, preserving per-agent ordering for every consumer — the same guarantee
detection logic gets from the single Redis Stream today. The trade-off is accepted and
intentional: a single very hot agent cannot spread across partitions. Changing the key
later requires re-partitioning through a new topic; treat this decision as irreversible
for `seagull.events.*`.

## Message envelope

Every message is JSON (`zstd`-compressed at the producer batch level):

```json
{
  "schema_version": 1,
  "produced_at": "2026-07-13T16:28:59.200056+00:00",
  "event": { "id": 1303910, "agent_id": "agent-core-1", "event_type": "ssh_auth", "...": "..." }
}
```

`schema_version` versions the envelope contract. Consumers must ignore unknown fields
and reject messages whose `event` is not an object (`es-indexer-redpanda` routes those
to the DLQ topic with reason `decode_error`).

## Client

`confluent-kafka` (librdkafka) is the single Kafka client for the whole backend —
async aiokafka was rejected because the entire ingest path (API endpoint, ingest
worker, pilot consumer) is synchronous code. Producer settings that matter:

- `enable.idempotence=true` — retries cannot duplicate messages.
- `compression.type=zstd`, `linger.ms=5` — batched, compressed produce.
- Fire-and-forget: `produce()` only appends to the client buffer; a dedicated poll
  thread drains delivery callbacks, so the ingest hot path never waits on the broker.

Consumer settings: `enable.auto.commit=false` on every consumer; offsets are committed
synchronously only after the batch is fully resolved (indexed or dead-lettered).

## Runtime configuration

| Setting | Default | Meaning |
|---------|---------|---------|
| `SEAGULL_REDPANDA_ENABLED` | `false` | master switch; enables the producer singleton and the `/health/ready` broker check |
| `SEAGULL_REDPANDA_BROKERS` | `redpanda:9092` | bootstrap servers (comma-separated in prod) |
| `SEAGULL_REDPANDA_DUAL_WRITE_ENABLED` | `false` | producers write to Redpanda in addition to Redis |
| `SEAGULL_ES_INDEXER_SOURCE` | `redis` | selects `es-indexer-stream` (Redis) or `es-indexer-redpanda` as the active pilot consumer |

Turning the pilot on locally:

```sh
SEAGULL_REDPANDA_ENABLED=true \
SEAGULL_REDPANDA_DUAL_WRITE_ENABLED=true \
SEAGULL_ES_STREAM_PRODUCER_ENABLED=true \
SEAGULL_ES_INDEXER_STREAM_ENABLED=true \
SEAGULL_ES_INDEXER_SOURCE=redpanda \
docker compose up -d --force-recreate seagull-backend seagull-ingest-pipeline
```

Reverting the pilot to Redis Streams is `SEAGULL_ES_INDEXER_SOURCE=redis` plus the same
recreate — the worker manager enables exactly one of the two consumers.

## Observability

Application metrics (Prometheus, exported by backend `:8000/metrics` and workers `:9100/metrics`):

- `redpanda_producer_msgs_total{topic}` / `redpanda_producer_error_total{topic,reason}`
- `redpanda_producer_delivery_seconds{topic}` — produce-to-ack latency
- `redpanda_consumer_msgs_total{topic,group}` / `redpanda_consumer_batch_seconds{topic,group}`
- `redpanda_consumer_lag{topic,group}` — end-offset minus position, summed per topic
- `ingest_dual_write_discrepancy_total{stream,reason}` — one side succeeded and the
  other failed (`redis_write_failed`, `redpanda_write_failed`, `producer_unavailable`)

Broker metrics: Prometheus scrapes `redpanda:9644/public_metrics` (job `redpanda` in
`infra/prometheus/prometheus.yml`). `/health/ready` reports a `redpanda` component
(status, broker count, latency) whenever `SEAGULL_REDPANDA_ENABLED=true`; it degrades
but never blocks readiness while Redpanda is in coexistence mode.

## Useful commands

```sh
docker exec seagull-redpanda rpk cluster health
docker exec seagull-redpanda rpk topic list
docker exec seagull-redpanda rpk topic describe seagull.events.index -c
docker exec seagull-redpanda rpk group describe es-indexer
docker exec seagull-redpanda rpk topic consume seagull.events.index -n 5 --offset end
docker exec seagull-redpanda rpk topic consume seagull.events.index.dlq -n 10 --offset start
docker exec seagull-redpanda rpk cluster logdirs describe --topics seagull.events.index
docker compose up redpanda-provision
```
