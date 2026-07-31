# Seagull

[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)
[![Backend](https://img.shields.io/badge/backend-Python%203.12-3776AB.svg)](backend)
[![Portal](https://img.shields.io/badge/portal-React%20%2B%20Vite-61DAFB.svg)](frontend)
[![Runtime](https://img.shields.io/badge/runtime-Docker%20Compose-2496ED.svg)](compose.yml)
[![Agent](https://img.shields.io/badge/agent-seagull--agent-00A6A6.svg)](https://github.com/dynasmon/seagull-agent)

Seagull is an open security operations platform. It collects endpoint and network
telemetry, correlates it into alerts and incidents, and gives analysts a focused
portal for triage, hunting, and investigation.

The platform is a FastAPI control plane, a set of detection and enrichment
workers, PostgreSQL/ClickHouse/Elasticsearch storage, and a React portal.
Endpoint collection is performed by [Seagull Agent](https://github.com/dynasmon/seagull-agent),
released independently: the platform runs with no agent installed, and an agent
installs with no access to this repository.

## Seagull capabilities

### Endpoint and network telemetry

Agents collect process execution, network flows, SSH authentication events, and
file integrity changes, plus PCAP-derived port scan, DDoS, and L7 protocol
signals. Host inventory and package data feed vulnerability correlation.

### Detection engineering

Detections are YAML rule packs with a versioned schema, evaluated continuously
by the intelligence workers. Sigma rules can be imported and reviewed. Rules
support backtesting against historical events, and carry health and governance
state so noisy or stale content is visible.

### Correlation and attack chains

Correlation rules group related detections into durable incidents. Attack-chain
stories assemble multi-stage activity into scored timelines, so an analyst sees a
progression rather than isolated alerts.

### Alert triage and investigation

The alert queue supports severity and status filtering, evidence pivoting, and
rule tuning from the same workflow. Investigation workspaces track evidence
across alerts, events, hosts, and findings.

### Network topology and exposure

Observed flows are projected into a topology graph grouped by subnet and
location. The exposure graph scores assets, surfaces attack paths, and explains
each score through reason codes.

### Vulnerability detection

Agent inventory is matched against OSV, scored with CVSS, and correlated with
host exposure so remediation can be prioritized by reachability rather than
severity alone.

### Behavioral analytics

UEBA detectors build per-entity baselines and report explainable anomalies with
the window and contributing signals that produced them.

### Fleet and response management

Agents enroll with single-use tokens and receive a certificate bound to their
identity. Credentials and certificates rotate automatically. Response actions are
dispatched only when the agent has announced the matching capability, and the
endpoint enforces its own local policy regardless of server intent.

### Data pipeline

Ingestion is idempotent per batch and buffered through Redis under load.
PostgreSQL holds operational state, ClickHouse serves analytics rollups, and
Elasticsearch backs event hunting. Worker groups handle ingest, intelligence, and
maintenance independently.

### Security operations

Role-based access control, HttpOnly refresh cookies, hardened headers, rate
limiting, and a hashed audit trail for administrative and login activity.
Secrets can be supplied through `*_FILE` variables for Docker secrets.

## Portal

![Operational overview](docs/assets/seagull-overview.png)

![Alert queue and triage](docs/assets/seagull-alerts.png)

![Event hunting](docs/assets/seagull-events.png)

![Agent fleet](docs/assets/seagull-agents.png)

![Network topology](docs/assets/seagull-network-topology.png)

![Exposure graph](docs/assets/seagull-exposure.png)

## Architecture

```text
Seagull Agent (systemd, per host)
        │  HTTPS · mTLS :8444 · enrollment :8445
        ▼
   Caddy edge ──► FastAPI backend ──► PostgreSQL · ClickHouse · Elasticsearch
        │               │
        │               ├── Redis ingest queue and rate limiting
        │               └── ingest · intelligence · maintenance workers
        └──► React portal
```

Services are declared in [`compose.yml`](compose.yml):

| Service | Role |
|---|---|
| `seagull-portal` | React portal served by nginx. |
| `seagull-backend` | API for ingest, auth, agents, detections, triage, topology, exposure, and administration. |
| `seagull-ingest-pipeline` | Queue draining, indexing, rollups, and analytics sink writes. |
| `seagull-intelligence-worker` | Rules, correlations, protocol intelligence, enrichment, attack chains, exposure, topology, and UEBA. |
| `seagull-maintenance-worker` | Audit retention and recurring maintenance. |
| `caddy` | HTTPS edge for the portal, the API, and the agent mTLS listener. |
| `postgres`, `redis`, `clickhouse`, `elasticsearch`, `prometheus` | Data and observability infrastructure. |

## Deployment

Requires Docker with the Compose plugin, Git, curl, jq, and Python 3 with the
`cryptography` package. Node is only needed for frontend development outside
Docker.

```bash
git clone https://github.com/dynasmon/Seagull.git
cd Seagull
./seagull -d --install
./seagull env bootstrap
${EDITOR:-nano} .env
./seagull up
```

`./seagull -d --install` provisions host dependencies (Debian/Ubuntu supported,
Fedora/RHEL best-effort). `./seagull up` bootstraps `.env`, downloads and
validates the GeoLite2 databases, generates the internal PKI, builds the
containers, and waits for the core services. It never compiles or installs an
agent.

Set `MAXMIND_LICENSE_KEY` in `.env` before the first start to enable GeoIP
enrichment.

| Endpoint | Default |
|---|---|
| Portal | `http://localhost:8080` |
| HTTPS edge | `https://localhost:8443` |
| Backend readiness | `http://localhost:8000/health/ready` |
| OpenAPI (dev only) | `http://localhost:8000/docs` |

Log in with `SEAGULL_BOOTSTRAP_ADMIN_USERNAME` and
`SEAGULL_BOOTSTRAP_ADMIN_PASSWORD` from `.env`. Rotate both before exposing the
service.

Common operations:

```bash
./seagull status                     # service health
./seagull logs seagull-backend       # follow one service
./seagull doctor                     # preflight and configuration checks
./seagull db upgrade                 # run migrations
./seagull agent tokens --agent-id id # mint an enrollment token
./seagull ci                         # lint, tests, and image build
```

## Seagull Agent

Agents run as a native `systemd` service on each monitored host and are never
part of the platform deployment. Source, packaging, CI, and the install, upgrade,
rollback, and uninstall lifecycle live in
[`dynasmon/seagull-agent`](https://github.com/dynasmon/seagull-agent).

The platform pins a supported release through `SEAGULL_AGENT_RELEASE_VERSION` and
offers the matching Linux `amd64` and `arm64` artifacts in the onboarding flow.
Releases are signed; verification and installation are documented in the agent
repository.

Mint a single-use token in the Agents view, then run the command the portal
renders:

```bash
sudo ./install.sh \
  --agent-id web-01 \
  --api-url https://siem.example.com:8444/agent \
  --enroll-url https://siem.example.com:8445 \
  --profile sensor \
  --prompt-enroll-token
```

The endpoint generates its own private key and sends only a certificate signing
request. The `sensor` profile collects telemetry and cannot execute response
actions; `managed` additionally accepts server-dispatched actions permitted by
local policy. See [`secrets/README.md`](secrets/README.md) for the mTLS trust
model.

## Configuration

`./seagull up` creates and syncs `.env`. For production, run `./seagull env
wizard` then `./seagull env prepare` and review the result. Settings that matter
most:

| Variable | Purpose |
|---|---|
| `SEAGULL_JWT_SECRET` | Portal token signing secret. |
| `SEAGULL_BOOTSTRAP_ADMIN_PASSWORD` | Initial administrator password. |
| `SEAGULL_COOKIE_SECURE` | Required when serving over HTTPS. |
| `SEAGULL_ALLOWED_HOSTS` | Accepted hostnames outside local development. |
| `SEAGULL_CADDY_DOMAIN`, `SEAGULL_CADDY_EMAIL` | Public TLS and domain configuration. |
| `SEAGULL_AGENT_PUBLIC_HOST` | Hostname advertised to remote agents; defaults to the Caddy domain. |
| `SEAGULL_AGENT_RELEASE_VERSION` | Agent release offered by onboarding. |
| `MAXMIND_LICENSE_KEY` | Enables automatic GeoLite2 downloads. |
| `SEAGULL_CLICKHOUSE_ENABLED` | Analytics sink toggle. |
| `SEAGULL_SEARCH_BACKEND`, `SEAGULL_ES_URL` | Hunting and search backend. |

Every secret above accepts a `*_FILE` variant; prefer those with Docker secrets
in real deployments.

## Development

```bash
./seagull ci                          # full pipeline
./seagull up --mode dev --dev-reload  # fast portal and backend loop
cd backend && python3 -m pytest -q
cd frontend && npm test && npm run build
```

The portal targets Node 20+ and npm 10+; the backend runs Python 3.12.

## Documentation

| Document | Topic |
|---|---|
| [detections/architecture.md](docs/detections/architecture.md) | Detection module boundaries and runtime. |
| [detections/rule_format_v2.md](docs/detections/rule_format_v2.md) | Rule schema and supported blocks. |
| [detections/canonical_fields.md](docs/detections/canonical_fields.md) | Canonical event fields and operators. |
| [detections/correlation_engine.md](docs/detections/correlation_engine.md) | Correlation strategies and durable incidents. |
| [detections/attack_stories.md](docs/detections/attack_stories.md) | Attack-chain templates and scoring. |
| [detections/backtesting.md](docs/detections/backtesting.md) | Detection validation. |
| [detections/sigma_import.md](docs/detections/sigma_import.md) | Sigma import and review. |
| [workers/architecture.md](docs/workers/architecture.md) | Worker group manager behavior. |
| [observability/architecture.md](docs/observability/architecture.md) | Metrics and observability APIs. |

Detection content lives in [`rules/`](rules/). The API is documented at `/docs`
when the backend runs in development mode.

## License

Seagull is licensed under the [GNU General Public License v3.0](LICENSE).
