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
  Elasticsearch 8.x. Cold instead makes the index read-only and drops its priority,
  and disables `migrate` because there are no dedicated cold nodes to move shards to.
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
