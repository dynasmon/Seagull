# Elasticsearch index setup (`es-indexer`)

The `es-indexer` worker (`backend/app/workers/indexing/elasticsearch.py`, part of the
`ingest` worker group) reads rows from Postgres `net_events` and indexes them into
Elasticsearch. On startup it applies an index template and an ILM policy from the
JSON files in this directory. This document describes what it creates and how to
operate it.

The files are loaded at bootstrap rather than embedded in Python:

| File | Contents |
| --- | --- |
| `index-template.json` | Composable index template: `dynamic: strict` mapping, the `extra`/`extra_search` fields, runtime fields, and the settings skeleton. |
| `ilm-policy.json` | ILM policy with `hot` / `warm` / `cold` / `delete` phases. |

The `properties` in `index-template.json` are the same field catalog as
`event_index_mapping_properties()` in
`backend/app/shared/indexing/es_mapping.py` (also used by the ingest/warm template
and by mapping reconcile). A test (`backend/tests/test_es_indexer_bootstrap.py`)
asserts the two stay identical, so they cannot drift apart.

## Index topology

```
seagull-events-write            write alias, points at the current hot index
   └── seagull-events-ilm-000001, -000002, ...   ILM-managed rollover series

seagull-events-YYYY.MM.DD       legacy daily indices (created before rollover; no ILM)
seagull-events-warm-*           separate ingest/warm tier (not managed here)

reads: seagull-events-*         matches managed + legacy indices; used by the backend
```

- **Writes** target the `seagull-events-write` alias. The worker never computes an
  index name; ILM rolls the hot index over and moves the `is_write_index` flag to
  the new index on its own.
- **Reads** use the `seagull-events-*` pattern (unchanged in the backend), which
  covers managed, legacy, and warm indices. When a search matches an index both
  directly and through the write alias, Elasticsearch resolves the duplicate, so
  documents are not counted twice.
- The managed series uses the `-ilm-` infix, giving the template the pattern
  `seagull-events-ilm-*`. This does not overlap the legacy dated indices or the
  `seagull-events-warm-*` tier, so neither of them picks up the strict mapping or the
  rollover alias from this template.

## ILM phases

Defaults:

| Phase | Enters | Actions |
| --- | --- | --- |
| hot | immediately | `rollover` at `max_primary_shard_size=50gb` or `max_age=1d`, whichever comes first; priority 100 |
| warm | 3 days after rollover | `forcemerge` to 1 segment; optional `shrink`; priority 50 |
| cold | 14 days | `readonly`; priority 0 |
| delete | 90 days | `delete` |

`min_age` is counted from the point an index rolls over, so `delete` at `90d` means
roughly 90 days after an index stops being the write index. The ages must increase
across phases (`warm ≤ cold ≤ delete`); Elasticsearch rejects a non-monotonic policy
when it is submitted. If the policy fails to apply, the worker logs it and applies
the template without ILM so indexing still works.

Two deliberate omissions:

- **Cold does not use the ILM `freeze` action.** It is deprecated and inert on
  Elasticsearch 8.x. Cold instead makes the index read-only and drops its priority.
  `migrate` is disabled by default because a single-node cluster has nowhere to move
  shards to; set `SEAGULL_ES_ILM_MIGRATE_ENABLED=true` on a cluster with tiered
  `node.roles` and ILM will move indices to `data_warm` / `data_cold` nodes as they
  age (the production compose enables this).
- **Warm `shrink` is off by default** (`SEAGULL_ES_ILM_WARM_SHRINK_SHARDS=0`).
  Shrinking a 1-shard index is invalid, so enable it only where the index has more
  than one primary shard (for example, set it to `1` in a 3-shard production setup).

## Settings

All configuration is through `SEAGULL_ES_*` environment variables. The values below
are the code defaults.

| Setting | Default | Meaning |
| --- | --- | --- |
| `SEAGULL_ES_BOOTSTRAP` | `false`* | Whether the worker provisions anything. |
| `SEAGULL_ES_ARTIFACTS_DIR` | auto | Directory holding the JSON files; resolves to `/etc/seagull/elasticsearch` in the container or `infra/elasticsearch` in the repo. |
| `SEAGULL_ES_INDEX_PREFIX` | `seagull-events` | Read prefix and the base for the derived names below. |
| `SEAGULL_ES_WRITE_ALIAS` | `<prefix>-write` | Rollover write alias. |
| `SEAGULL_ES_ROLLOVER_INDEX_PREFIX` | `<prefix>-ilm` | Managed index series and the template pattern (`<...>-*`). |
| `SEAGULL_ES_TEMPLATE_PRIORITY` | `200` | Composable template priority. |
| `SEAGULL_ES_NUMBER_OF_SHARDS` | `1` | Primary shards (use 3 in production). |
| `SEAGULL_ES_NUMBER_OF_REPLICAS` | `0` | Replicas (use 1 in production). |
| `SEAGULL_ES_REFRESH_INTERVAL` | `10s` | Refresh interval. The dashboard reads from an SWR cache, so a longer interval is fine. |
| `SEAGULL_ES_TIER_PREFERENCE` | `data_hot` | `index.routing.allocation.include._tier_preference` for new managed indices; `none` disables the setting. |
| `SEAGULL_ES_ILM_MIGRATE_ENABLED` | `false` | Let ILM migrate indices across data tiers in warm/cold. Enable on clusters with tiered `node.roles`. |
| `SEAGULL_ES_ILM_ENABLED` | `true` | Whether to create and attach the policy. |
| `SEAGULL_ES_ILM_POLICY_NAME` | `<prefix>-ilm` | Policy name. |
| `SEAGULL_ES_ILM_ROLLOVER_MAX_PRIMARY_SHARD_SIZE` | `50gb` | Hot rollover size trigger. |
| `SEAGULL_ES_ILM_ROLLOVER_MAX_AGE` | `1d` | Hot rollover age trigger. |
| `SEAGULL_ES_ILM_WARM_AFTER` | `3d` | Warm entry age. |
| `SEAGULL_ES_ILM_COLD_AFTER` | `14d` | Cold entry age. |
| `SEAGULL_ES_ILM_DELETE_AFTER_DAYS` | `90` | Delete entry age, in days. |
| `SEAGULL_ES_ILM_FORCEMERGE_SEGMENTS` | `1` | Warm forcemerge target segments. |
| `SEAGULL_ES_ILM_WARM_SHRINK_SHARDS` | `0` | Warm shrink target shards; `0` disables it. |

\* The bundled `compose.yml` sets `SEAGULL_ES_BOOTSTRAP=true` for the dev stack.

## Bootstrap

When `SEAGULL_ES_BOOTSTRAP=true`, the worker runs the following once at startup:

1. **ILM policy** — `PUT _ilm/policy/<name>`. Overwrites; a re-PUT with the same body
   is a no-op.
2. **Index template** — `PUT _index_template/<prefix>-template`, carrying
   `_meta.version`. If step 1 failed, the template is applied without the lifecycle
   settings so index creation still works.
3. **Write index and alias** — if the `<prefix>-write` alias does not exist, create
   `<prefix>-ilm-000001` with `is_write_index: true` (or attach the alias to that
   index if it already exists).
4. **Reconcile** — `put_mapping` of the field catalog onto existing `<prefix>-*`
   indices. This adds newly declared fields to older indices; a field whose type
   conflicts is skipped rather than treated as an error.

Every step is safe to repeat, so the worker can bootstrap on every restart.

With `SEAGULL_ES_BOOTSTRAP=false`, the worker does none of the above and assumes the
cluster was provisioned by hand. In that case you must create the `<prefix>-write`
alias yourself; otherwise the first write auto-creates a plain index with that name
that never rolls over.

## Adding a new field

`dynamic: strict` makes Elasticsearch reject any document that contains a top-level
field not present in the mapping (HTTP 400, `strict_dynamic_mapping_exception`). This
prevents mapping explosion and stops unmapped fields from being silently typed as
`text`. The cost is that a genuinely new top-level field has to be declared before it
can be indexed.

You can add data without changing the mapping in two ways:

- **Exact filtering:** put the value inside the agent `extra` object. `extra` is
  `flattened`, so arbitrary sub-keys are stored and exact-matchable with no mapping
  change.
- **Full-text search:** the value flows into `extra_search` if the `_to_doc` builder
  copies it there.

To promote a value to its own typed top-level field (needed for aggregations,
ranges, or the `ip` type):

1. Add it to `event_index_mapping_properties()` in `es_mapping.py` **and** to
   `properties` in `index-template.json`, with the same type. The drift test fails if
   they disagree.
2. Bump `_meta.version` in `index-template.json` (and `mappings._meta.mapping_version`).
3. Emit the field from the relevant `_to_doc` builder.
4. Deploy. New indices get the field on the next rollover; reconcile adds it to
   existing indices where the type does not conflict.
5. Reindex old data only if you need the field populated retroactively.

Runtime fields (`dst_port_class`, `proto_category`) are computed at query time and
cost nothing to store — use them for derived classifications instead of a stored
field.

## Applying ILM to legacy indices

Bootstrap does not modify the legacy `seagull-events-YYYY.MM.DD` indices; they are
not part of the write alias and stay readable through the `seagull-events-*` pattern.
To bring them under the policy manually, set `index.lifecycle.name` on them. Do not
set a `rollover_alias` — they are not write indices, so ILM manages them by age only
(no rollover step).

```bash
# One index:
curl -XPUT "$ES/seagull-events-2026.06.15/_settings" -H 'content-type: application/json' -d '{
  "index.lifecycle.name": "seagull-events-ilm"
}'

# All legacy dated indices at once:
curl -XPUT "$ES/seagull-events-2026.*/_settings" -H 'content-type: application/json' -d '{
  "index.lifecycle.name": "seagull-events-ilm"
}'
```

Check `_ilm/explain` on a single index before applying this broadly.

## Diagnostics

```bash
ES=http://localhost:9200

curl -s "$ES/_index_template/seagull-events-template?pretty"
curl -s "$ES/_ilm/policy/seagull-events-ilm?pretty"
curl -s "$ES/_cat/indices/seagull-events-*?v&s=index"
curl -s "$ES/_cat/aliases/seagull-events-*?v"
curl -s "$ES/seagull-events-write/_ilm/explain?pretty"     # phase/step/age of the write index
curl -s "$ES/_cat/shards/seagull-events-ilm-*?v"
```

## Failure modes

- **A new top-level field breaks indexing under strict mapping.** It shows up right
  away as a bulk error logged by the worker (`es_bulk_partial_success`, with
  `strict_dynamic_mapping_exception` in the sample), and on the read side as missing
  recent documents. Only the documents carrying that field fail; everything already
  mapped keeps indexing, and the read offset is not advanced past a batch until it is
  handled, so nothing is dropped. Fix it with the "Adding a new field" procedure.
- **The warm tier must stay on its own prefix.** The template is scoped to
  `seagull-events-ilm-*`, so a warm index named outside that pattern is fine; a warm
  index placed under `seagull-events-ilm-*` would incorrectly inherit this template.
- **`SEAGULL_ES_BOOTSTRAP=false` without a pre-created alias** makes writes
  auto-create a plain `<prefix>-write` index that never rolls over. Create the alias,
  or leave bootstrap on.

---

# Production cluster

Everything above applies unchanged to a multi-node cluster; this section covers the
cluster itself: topology, sharding, snapshots, scaling, and operations.

The stack ships one Elasticsearch node in `compose.yml`, which is what
`./seagull up` runs in every environment. A cluster is operated separately from
the application stack: run the nodes wherever they belong (dedicated hosts, a
managed service, an operator-owned compose file) and point the platform at them.
Nothing else changes — the same env knobs drive shard counts, ILM, and the
expected health status.

| Setting | Cluster value |
| --- | --- |
| `SEAGULL_ES_URL` | Comma-separated node list, e.g. `http://es01:9200,http://es02:9200,http://es03:9200`. |
| `SEAGULL_ES_NUMBER_OF_SHARDS` / `SEAGULL_ES_NUMBER_OF_REPLICAS` | `3` / `1` (see Sharding and replication). |
| `SEAGULL_ES_EXPECTED_STATUS` | `green` — yellow means lost redundancy on a cluster. |
| `SEAGULL_ES_ILM_MIGRATE_ENABLED` | `true` once nodes carry tiered `node.roles`. |
| `SEAGULL_ES_ILM_WARM_SHRINK_SHARDS` | `1` with 3 primary shards. |
| `SEAGULL_ES_SECURITY_ENABLED` and credentials | Required beyond a trusted network (see Security). |

Per-node sizing is a property of the nodes themselves: heap at 50% of node RAM
capped at 30 GB, a container memory limit around 2× heap, `bootstrap.memory_lock`
on, and `vm.max_map_count >= 262144` on the host.

`SEAGULL_ES_URL` accepts a comma-separated host list; all ES clients (backend and
workers) round-robin across the listed nodes and fail over when one goes down. The
compose sets all three nodes, so losing any single node never takes the application
offline.

Cluster formation settings, per node:

- `discovery.seed_hosts: es01,es02,es03` — static seed list.
- `cluster.initial_master_nodes: es01,es02,es03` — consulted only on the very
  first formation; in a real deployment remove it after the cluster has formed
  (leaving it set is harmless but logs a warning and can mask a mis-join).
- `node.roles: master,data_hot,data_content,data_warm,data_cold,ingest` — explicit,
  never default. All three nodes carry all roles here; a larger deployment splits
  them (see "Scaling" below). The tier roles are per-tier on purpose (no generic
  `data` role) so `_tier_preference` and ILM `migrate` behave exactly as they will
  when tiers become dedicated nodes.
- `bootstrap.memory_lock: true` + `memlock` ulimits — the heap never swaps.
- Host prerequisite: `vm.max_map_count >= 262144` (`sysctl -w vm.max_map_count=262144`).

## Sharding and replication

Defaults, driven exclusively by backend settings (the JSON template carries
inspectable placeholders; bootstrap always overwrites them):

| Environment | Shards | Replicas | Where |
| --- | --- | --- | --- |
| dev / single-node compose | 1 | 0 | code defaults (`SEAGULL_ES_NUMBER_OF_SHARDS/REPLICAS`) |
| production / cluster | 3 | 1 | `SEAGULL_ES_NUMBER_OF_SHARDS/REPLICAS` on the stack |

Why 3 shards / 1 replica:

- **Shard size target: 10–50 GB.** The ILM hot phase already rolls over at
  `max_primary_shard_size=50gb` (or 1 day), so shard size is capped by rollover no
  matter what. The shard *count* is therefore about write/query parallelism, not
  about keeping shards small.
- **3 shards = 1 primary per node.** Ingest bulk requests fan out to all three
  nodes instead of hammering one; searches over the hot index run three shard
  queries in parallel. With the daily volume this SIEM targets (single-digit GB/day
  in the lab, tens of GB/day in production), 3×50 GB of primary capacity per
  rollover generation is comfortable headroom; more shards would just multiply
  per-shard overhead (each shard is a Lucene index with its own segments, memory
  and merge activity — oversharding is the most common ES scaling mistake).
- **1 replica = survive exactly one node.** Full copy of every shard elsewhere:
  any single node can die with zero data loss and the cluster stays writable
  (quorum 2/3 holds). Storage cost is 2× vs 3× for 2 replicas; replicas also double
  indexing work, so more replicas buy read throughput and tolerance for a second
  simultaneous failure, at real write cost. For an events store where the source of
  truth also lives in Postgres/ClickHouse, 1 replica is the right trade.
- With 3 shards × (1+1) copies = 6 shards over 3 nodes, allocation balances at 2
  per node and a primary never shares a node with its own replica.
- **Recalibrate by measuring:** `GET _cat/indices/seagull-events-ilm-*?v&h=index,pri,rep,store.size`.
  If indices roll over daily far below 10 GB per primary, drop to 1–2 shards; if
  rollover triggers on size several times a day, add nodes and shards together
  (shards ≈ data nodes, or a small multiple).
- `SEAGULL_ES_ILM_WARM_SHRINK_SHARDS=1` in production: once an index leaves the
  write path, 3 shards no longer help and the warm phase shrinks it to 1, cutting
  per-shard overhead for the long tail of older indices.

New managed indices are pinned to the hot tier
(`index.routing.allocation.include._tier_preference: data_hot`) and
`SEAGULL_ES_ILM_MIGRATE_ENABLED=true` lets ILM rewrite that preference to
`data_warm`/`data_cold` as indices age. With all roles on all nodes this is a
no-op today — but the day warm data moves to cheaper nodes, it is a `node.roles`
change, not a reindex.

## Snapshots

Infrastructure the cluster must provide: a shared volume mounted at
`/usr/share/elasticsearch/snapshots` on **every** node, declared via `path.repo`.
A snapshot repository must be visible to all nodes — on a single host a shared
volume works; across hosts use NFS or a cloud repository plugin (S3/GCS/Azure).

Register and verify the repository (one-time, after the cluster is up):

```bash
ES=http://localhost:9201

curl -XPUT "$ES/_snapshot/local" -H 'content-type: application/json' -d '{
  "type": "fs",
  "settings": {"location": "/usr/share/elasticsearch/snapshots", "compress": true}
}'
curl -XPOST "$ES/_snapshot/local/_verify"    # must list every node
```

Schedule daily snapshots with SLM (managed by the cluster itself, survives
restarts, applies retention):

```bash
curl -XPUT "$ES/_slm/policy/seagull-daily" -H 'content-type: application/json' -d '{
  "schedule": "0 30 2 * * ?",
  "name": "<seagull-daily-{now/d}>",
  "repository": "local",
  "config": {"indices": ["seagull-events-*"], "include_global_state": false},
  "retention": {"expire_after": "7d", "min_count": 3, "max_count": 30}
}'

curl -XPOST "$ES/_slm/policy/seagull-daily/_execute"   # run one now
curl "$ES/_slm/policy/seagull-daily?human"              # last success/failure
```

Snapshots are incremental at the segment level: unchanged segments are reused, so
daily snapshots of mostly-immutable rolled-over indices are cheap.

## Backup and restore playbook

List what exists:

```bash
curl "$ES/_cat/snapshots/local?v&h=id,status,start_time,duration,indices,successful_shards,failed_shards"
```

Restore one index. Restoring over a live index is not allowed; restore under a new
name, then swap or reindex:

```bash
curl -XPOST "$ES/_snapshot/local/<snapshot-id>/_restore?wait_for_completion=true" \
  -H 'content-type: application/json' -d '{
  "indices": "seagull-events-ilm-000042",
  "rename_pattern": "(.+)",
  "rename_replacement": "restored-$1",
  "include_aliases": false,
  "index_settings": {"index.lifecycle.name": null, "index.lifecycle.rollover_alias": null}
}'
```

`include_aliases: false` plus the cleared lifecycle settings keep the restored copy
out of the write alias and out of ILM — it will not start rolling over or
double-receiving writes. Verify with a search/count, then either point reads at it
or `_reindex` into the live series, and delete the `restored-*` index.

**Test recovery periodically** (monthly, or after any topology change): pick the
latest snapshot, restore it under `restored-*` as above, assert doc counts match
(`GET restored-<index>/_count` vs the snapshot's source), delete the restored
index. The playbook was validated end-to-end on this cluster (restore of a 3-shard
index: 3/3 shards successful). A backup that has never been restored is a hope, not
a backup.

Disaster recovery (all nodes lost, volumes gone): bring up a fresh cluster, mount
the snapshot volume (or point at the shared repo), register the repository, then
restore `seagull-events-*` without renames and re-run the worker bootstrap to
recreate the template/alias before enabling ingest.

## Scaling from 3 to N nodes

1. Add the new node with the same `cluster.name`, `discovery.seed_hosts` pointing
   at existing nodes, explicit `node.roles`, and **no**
   `cluster.initial_master_nodes` (the cluster already exists; that setting is
   only for first formation — setting it on a joining node risks it bootstrapping
   a *separate* cluster).
2. The node joins and shard rebalancing starts automatically. Watch it:
   ```bash
   curl "$ES/_cat/recovery?v&active_only=true"
   curl "$ES/_cat/shards/seagull-events-*?v&h=index,shard,prirep,state,node"
   curl "$ES/_cat/allocation?v"
   ```
3. Throttle if rebalance competes with ingest:
   `cluster.routing.allocation.cluster_concurrent_rebalance` (default 2) and
   `indices.recovery.max_bytes_per_sec` (default 40mb) via
   `PUT _cluster/settings {"persistent": {...}}`.
4. Raise `SEAGULL_ES_NUMBER_OF_SHARDS` only when node count grows enough that a
   hot index no longer spans the data-hot nodes (target: shards ≈ hot data nodes).
   It applies from the next rollover; existing indices keep their count.
5. Past ~5–6 nodes, split roles: 3 dedicated master-eligible nodes
   (`node.roles: master`), the rest data/ingest by tier. Keep the number of
   master-eligible nodes **odd** (3 is almost always right); voting quorum is
   managed automatically, but an even count adds failure modes without adding
   tolerance.
6. Removing a node: for data nodes, drain first —
   `PUT _cluster/settings {"persistent": {"cluster.routing.allocation.exclude._name": "es04"}}`,
   wait for its shards to reach 0, then stop it. For master-eligible nodes, also
   use `POST /_cluster/voting_config_exclusions?node_names=es04` before shutdown
   when downsizing below the current voting configuration.

## Emergency runbook

**Cluster yellow.** Replicas unassigned. One node down (fix the node — the compose
healthchecks and `restart: unless-stopped` handle the local case) or allocation
rules can't place replicas (e.g. replicas > available nodes - 1). Diagnose:

```bash
curl "$ES/_cluster/health?pretty"
curl "$ES/_cat/shards?v" | grep -v STARTED
curl -XPOST "$ES/_cluster/allocation/explain?pretty"   # explains the first unassigned shard
```

Note: after a node leaves, replicas stay `delayed_unassigned` for
`index.unassigned.node_left.delayed_timeout` (default 1m) before re-replicating
elsewhere — a restarting node recovers from local data, which is much cheaper.
Yellow that self-heals within minutes after a restart is normal.

**Cluster red.** Primaries unassigned — some data is unsearchable and writes to
affected indices fail. Same diagnosis as yellow; common causes and fixes:

- Disk watermarks exceeded (`flood-stage` also makes indices read-only):
  `curl "$ES/_cat/allocation?v"`, free space or add nodes, then
  `PUT <index>/_settings {"index.blocks.read_only_allow_delete": null}`.
- Allocation retries exhausted after a transient failure:
  `POST /_cluster/reroute?retry_failed=true`.
- The only copy was on a dead node: bring the node (or its volume) back, or accept
  loss and restore that index from the last snapshot.

**Node won't join.** Check the joining node's log first:

- `cluster UUID mismatch` — the node bootstrapped its own cluster in the past
  (usually `cluster.initial_master_nodes` left set on a fresh volume). Wipe its
  data dir and rejoin, never reuse it as-is.
- `master not discovered` — `discovery.seed_hosts` wrong/unresolvable, or the
  transport port (9300) blocked between containers/hosts.
- Version incompatibility — a node more than one minor behind the master is
  rejected; upgrade the node.

**Split-brain.** Not possible on Elasticsearch ≥7 with a correctly bootstrapped
cluster: master election is quorum-based over the voting configuration, and a
partition holding fewer than a majority of master-eligible nodes refuses to elect
(the old `minimum_master_nodes` foot-gun was removed). What you can still get
wrong: bootstrapping twice (the UUID mismatch above — two clusters that will never
merge) and even master-eligible counts. Verify a single master with
`curl "$ES/_cat/master"` from several nodes.

**Backend view during incidents.** `/health/ready` →
`components.elasticsearch.cluster` reports `status`, `expected`,
`below_expected_seconds` and `alert`. `SEAGULL_ES_EXPECTED_STATUS` defaults to
`auto` (green expected for multi-node, yellow for single-node);
`SEAGULL_ES_YELLOW_ALERT_MINUTES` (default 15) sets how long the cluster may sit
below expectation before `alert: true` + a warning log (red alerts immediately).
Readiness never flips on yellow/red — ES still serves traffic and search has a
Postgres fallback; only ES-unreachable-and-required does.

## Security

Elasticsearch authentication off is acceptable only while the cluster is confined
to a trusted network (local validation, isolated staging); `./seagull up` refuses
to start a production stack with `SEAGULL_ES_SECURITY_ENABLED=false` while the
search backend uses Elasticsearch. Any deployment reachable beyond that **must** enable security, and
multi-node clusters with security on additionally require transport TLS with
certificates provisioned before boot:

1. **Transport TLS (mandatory with security on):** generate a CA and per-node certs
   with `elasticsearch-certutil ca` + `elasticsearch-certutil cert`, mount them,
   set `xpack.security.transport.ssl.enabled=true`,
   `verification_mode=certificate`, keystore/truststore paths.
2. **HTTP TLS:** same tooling (`xpack.security.http.ssl.*`); backend/workers then
   use `https://` in `SEAGULL_ES_URL` with `SEAGULL_ES_CA_CERTS` pointing at the CA
   bundle (`SEAGULL_ES_VERIFY_CERTS=true`).
3. **`elastic` password from a secret** (`ELASTIC_PASSWORD_FILE` or an orchestrator
   secret), used only for administration — never by the application.
4. **Least-privilege application users** instead of `elastic` everywhere:
   ```bash
   # role for the indexer worker (writes + bootstrap)
   curl -XPUT "$ES/_security/role/seagull_indexer" -H 'content-type: application/json' -d '{
     "cluster": ["monitor", "manage_ilm", "manage_index_templates", "manage_slm"],
     "indices": [{"names": ["seagull-events-*"],
                  "privileges": ["create_index", "write", "manage", "view_index_metadata"]}]
   }'
   # role for the backend (read-only + health)
   curl -XPUT "$ES/_security/role/seagull_backend" -H 'content-type: application/json' -d '{
     "cluster": ["monitor"],
     "indices": [{"names": ["seagull-events-*"], "privileges": ["read", "view_index_metadata"]}]
   }'
   ```
   Create one user per role (`PUT _security/user/...`) and wire them through
   `SEAGULL_ES_USERNAME`/`SEAGULL_ES_PASSWORD(_FILE)` per service — the backend and
   the indexer already read credentials independently, so they can differ today.

## Heap and memory

- Rule: **heap = 50% of the node's available RAM, capped at ~30 GB** (above ~32 GB
  the JVM loses compressed object pointers and 40 GB of heap performs worse than
  30). The other 50% is not waste — Lucene depends on the OS page cache for
  segment reads.
- Always set `-Xms` = `-Xmx` (the single node in `compose.yml` stays at 512 MB;
  cluster nodes typically run 2 GB or more). A container memory limit at ~2× heap
  leaves the other half to the OS page cache Lucene depends on.
- `bootstrap.memory_lock=true` + memlock ulimits prevent the heap from swapping;
  keep host swap usage for ES nodes at effectively zero.
- Rough sizing for this workload: a 2 GB-heap node handles the lab comfortably; at
  tens of GB/day of events plan 8 GB heap / 16 GB RAM per data node and scale on
  heap pressure (`_nodes/stats/jvm`, old-GC frequency), not CPU.

## Circuit breakers and limits

Defaults are sane; do not tune preemptively. Knobs that matter when query volume
or aggregation cardinality grows (all dynamic via `PUT _cluster/settings` or env):

| Setting | Default | When to touch |
| --- | --- | --- |
| `indices.breaker.total.limit` | 95% of heap | Trips as `circuit_breaking_exception [parent]` under memory pressure. Lowering it (e.g. 85%) trades failed requests for node stability. Prefer adding heap/nodes. |
| `indices.breaker.fielddata.limit` | 40% of heap | Only relevant if something aggregates on `text` fielddata — this schema uses `keyword`/runtime fields, so growth here signals a mapping mistake. |
| `indices.breaker.request.limit` | 60% of heap | Per-request structures (big aggs). Lower it to kill pathological dashboards earlier. |
| `search.max_buckets` | 65,536 | Hard cap per response. Raise only for a specific legitimate aggregation; prefer `composite` aggs for pagination. |

Breaker trips are visible in `GET _nodes/stats/breaker` (`tripped` counters) and
should page before users notice — see monitoring below.

## Monitoring

Two complementary sources:

1. **Backend-exported gauges** (already scraped by the dev Prometheus from
   `/metrics`): `es_cluster_status` (0 green / 1 yellow / 2 red / -1 unreachable),
   `es_cluster_below_expected`, `es_cluster_unassigned_shards`. Alert rules live in
   `infra/prometheus/rules/seagull-elasticsearch.yml` (below-expected sustained
   15m → warning; red 5m / unreachable 10m → critical). Keep the rule durations
   aligned with `SEAGULL_ES_YELLOW_ALERT_MINUTES`.
2. **A dedicated exporter** for node-level detail in real production:
   [`prometheus-community/elasticsearch_exporter`](https://github.com/prometheus-community/elasticsearch_exporter)
   (run one instance pointed at the cluster; not bundled here to keep the stack
   ES-only). Collect at minimum:
   - `elasticsearch_cluster_health_status` / `..._unassigned_shards` /
     `..._number_of_pending_tasks`
   - `elasticsearch_jvm_memory_used_bytes` vs `_max_bytes` (heap %), GC time
     (`elasticsearch_jvm_gc_collection_seconds_*`)
   - `elasticsearch_thread_pool_rejected_count` (`write`/`search` pools — the
     earliest overload signal)
   - `elasticsearch_breakers_tripped`
   - `elasticsearch_filesystem_data_available_bytes` vs watermarks
   - `elasticsearch_indices_indexing_index_total` and
     `..._search_query_total` rates (throughput baselines)

## Dev vs prod defaults

| Knob | single node (`compose.yml`) | production cluster | Why they differ |
| --- | --- | --- | --- |
| Nodes | 1 (`discovery.type: single-node`) | 3, quorum election | HA needs a majority; 2 nodes cannot lose either one. |
| Shards / replicas | 1 / 0 | 3 / 1 | Single node can't host replicas (they'd just turn the cluster yellow); a cluster wants parallelism + redundancy. |
| Expected health | yellow acceptable | green (`SEAGULL_ES_EXPECTED_STATUS=green`) | 0-replica indices make yellow benign in dev; in a cluster yellow means lost redundancy. |
| Heap | 512 MB | 2 GB/node (env) | Dev optimizes for coexisting with the whole stack on one laptop. |
| `node.roles` | image default | explicit, all tiers | Explicit roles make tier separation a config change later. |
| ILM `migrate` | disabled | enabled | Meaningless without tiered roles; ready for dedicated warm/cold nodes. |
| Warm shrink | 0 (off) | 1 | Shrinking a 1-shard index is invalid; 3→1 cuts old-index overhead. |
| Snapshots | none | shared `path.repo` volume + SLM | Dev data is disposable. |
| Security | off | off by default, **required beyond trusted networks** | Enabling needs transport TLS certs provisioned first (see Security). |
