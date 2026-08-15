# Container networks and host exposure

Two properties decide how far a compromise travels in a container stack: which
containers can talk to each other, and which ports the host offers to the
network. Seagull got both wrong in the same direction — one flat network for
everything, and a publishing pattern that looked restrictive and was not.

## One network was every network

Every service shared a single bridge called `seagull`. Caddy could open a
connection to PostgreSQL. The portal could reach Redis. A compromise of the edge
container — the one process deliberately exposed to the internet — started with
network reach to every datastore in the product, and from there needed only
credentials, which several stores do not require by default in the dev profile.

The stack is now split by what each hop legitimately needs.

| Network | Members | Carries |
|---|---|---|
| `edge` | caddy, portal | browser traffic arriving at the edge and static assets |
| `app` | caddy, portal, backend | API requests to the backend |
| `data` | backend, the three workers, postgres, redis, elasticsearch, clickhouse, redpanda, kibana | queries and writes to the stores |
| `observability` | prometheus, backend, workers, redpanda | scrapes and the observability API |
| `pki` | backend, seagull-pki | certificate signing requests |

Read as reachability:

| From | Can reach |
|---|---|
| caddy | portal, backend |
| portal | backend |
| backend | everything it depends on |
| workers | the stores and prometheus |
| postgres, redis, elasticsearch, clickhouse | whatever connects to them; they initiate nothing |
| seagull-pki | nothing — the backend connects to it |

The backend is the only container that crosses into `data` and `pki`. That is
not an accident of the layout, it is the point: it is the one service that has
business in every tier, and it is now the only path between them.

`backend/tests/test_container_topology.py` asserts this from `compose.yml`
rather than from a diagram — that edge-facing services share no network with any
store or with the authority, that only `seagull-pki` mounts the CA key, and that
every Prometheus scrape target is on a network Prometheus is actually attached
to. Adding a scrape target without adding the network fails the suite instead of
producing a silently dead job.

## An empty variable published to the world

Ports were written as `"${ELASTICSEARCH_PORT:-}:9200"`, with a comment in
`.env.example` stating that leaving the variable empty would not publish the
port at all. That is not what Docker does. `-p :9200` publishes container port
9200 on a *random* host port, on every interface. The running dev stack was
proof: Redpanda, whose variables nobody had ever set, was listening on
`0.0.0.0:32768` and `0.0.0.0:32769`.

Every internal service now carries a loopback default:

```yaml
ports:
  - "${ELASTICSEARCH_PORT:-127.0.0.1:9200}:9200"
```

`:-` treats an empty value as absent, so the three states are now the ones an
operator expects: unset or empty binds to loopback, an explicit
`127.0.0.1:9200` binds to loopback, and a bare `9200` or `0.0.0.0:9200` is a
deliberate choice to expose the port.

Caddy is the exception and stays published on all interfaces on `8081`, `8443`,
`8444` and `8445`. It is the edge; that is its job.

Redpanda's advertised address stopped sharing a variable with its published
port. The two say different things — one is where a client should connect, the
other is how the port reaches the host — and a value carrying a bind address
(`127.0.0.1:19092`) is valid for publishing and nonsense inside an advertised
listener. `SEAGULL_REDPANDA_ADVERTISED_KAFKA_PORT` (default 19092) is now
separate from `SEAGULL_REDPANDA_KAFKA_PORT`.

## Production refuses to expose itself

`./seagull up` runs preflight, and preflight now checks the publish address of
every internal port variable: backend, portal, Elasticsearch, Kibana, both
ClickHouse listeners and both Redpanda listeners.

| Environment | Published beyond loopback |
|---|---|
| dev | prints a warning naming each variable |
| prod | refuses to start, naming each variable and the fix |

A development machine that wants the portal reachable from a phone on the same
LAN is a legitimate choice, and the warning states what is happening. A
production host publishing the backend next to the edge that fronts it is not a
choice anyone makes on purpose; it is what happens when a variable was copied
from a dev `.env`. The edge listeners are excluded from the check, because they
are the ports that are supposed to face the network.

## What is still open

Marking `data`, `observability` and `pki` as `internal: true` would also cut
those containers off from outbound internet access, which none of them need. It
changes how Docker picks a container's default route when it is attached to
several networks, so it needs the endpoint priorities set explicitly and a
verification pass of its own; it is not in this change.

Beyond the network, each store still authenticates every Seagull service with
the same credentials. Per-service database roles — a worker that can write
events but not read the audit trail — are the next reduction, and they are
schema and deployment work rather than topology.
