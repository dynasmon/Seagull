# The agent authentication path

Every request an agent makes — ingest, heartbeat, config poll, action poll —
carries `X-Agent-ID` and `X-Agent-Credential` and goes through
`get_current_agent`. That function ran on the hot path of the busiest endpoint
in the platform and treated authentication as a write.

Two things were wrong with it, and one of them took agents off the network.

## A credential that spent itself

`SEAGULL_AGENT_CREDENTIAL_MAX_USES` defaults to `100000`, and authentication
consumed one use per HTTP request. The counter had nothing to do with how many
credentials had been handed out; it counted traffic. An agent that talks to the
platform once a second burns the quota in a little over 27 hours and then gets
`401 Agent credential exhausted` on everything, while its credential is still
weeks from expiring.

Nothing fails loudly when that happens. The agent stops being able to ship
telemetry and simply goes quiet in the fleet view, which is the worst shape a
failure can take in a security product: absence of data looks like absence of
activity.

Authentication no longer reads or writes that counter. A credential is valid
while it is unrevoked and unexpired, which is what `revoked_at` and `expires_at`
already say. The counter went back to meaning what its name says — how many
times the credential may be redeemed — and is spent in
`POST /agents/credential/rotate`, where the agent actually exchanges one
credential for another.

## Authentication that wrote on every request

The same function then wrote `used_uses`, `last_used_at` and
`agents.last_seen_at`, and committed, before the route did any of its own work.
For a fleet of *n* agents polling every second that is `3n` row updates per
second on two hot rows per agent, with the WAL traffic and index churn that
follows, spent entirely on bookkeeping.

Two of those three writes are gone: the counter is not authentication's business
and `last_used_at` now records redemption alongside it. The third is real —
the fleet view needs to know an agent is alive — but it does not need
per-request resolution, and the heartbeat already refreshes it on its own timer.

`agents.last_seen_at` is now written at most once per
`SEAGULL_AGENT_LAST_SEEN_THROTTLE_SECONDS` (default 60) per agent. The window is
claimed with a Redis `SET NX EX`, so concurrent requests across replicas settle
on one writer without coordinating. When nothing is claimed the request performs
no write and no commit at all.

| Redis | Behaviour |
|---|---|
| Reachable, window free | write `last_seen_at`, commit, count `written` |
| Reachable, window taken | no write, no commit, count `throttled` |
| Unreachable or failing | no write, no commit — the heartbeat still updates it |

Setting the window to `0` restores a write on every request.

Losing Redis therefore degrades `last_seen_at` to heartbeat cadence rather than
degrading availability, which is the right direction: the value is a liveness
hint, and the heartbeat is its authoritative source.

## What did not change

The credential is still matched by hashing the presented string against the
salted hash of each unrevoked credential for that agent. The review proposed
embedding a non-secret credential id in the credential string for an O(1)
lookup, and the measurement did not support the change: an agent holds one
active credential outside the rotation overlap window and two inside it, so the
loop runs once, at 0.46 µs per hash. That is noise next to the two SELECTs
around it, and buying it would cost a schema column, a credential format change,
and a parsing fallback for credentials issued under the old format.

Certificate identity binding (`SEAGULL_AGENT_MTLS_IDENTITY_BINDING`) is
unchanged and still runs before any state is touched.

## What it emits

| Metric | Labels | Meaning |
|---|---|---|
| `agent_auth_requests_total` | `outcome`, `reason`, `method` | authentication attempts; `reason="exhausted"` is now unreachable |
| `agent_last_seen_write_total` | `outcome` | `written` or `throttled` |

The ratio between the two `agent_last_seen_write_total` outcomes is the write
reduction the throttle is buying. If `written` tracks the request rate, either
the window is `0` or Redis is not being reached.
