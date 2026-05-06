# Dynasmon Seagull

Dynasmon Seagull is a threat hunting platform designed as a lightweight, opinionated mini‑SIEM. It started as a network telemetry pipeline and is evolving toward an “XDR‑foundation” architecture inspired by Wazuh endpoint management.

At this stage, Seagull provides an end‑to‑end pipeline:

- Multiple Go agents that capture and ship telemetry (proc/authlog + PCAP‑based collectors + endpoint syscollector)
- A FastAPI backend that ingests and persists events into PostgreSQL
- A rules engine executed by the grouped intelligence worker container
- A **Seagull Portal** (React) with authentication and an operator‑friendly UI
- Optional search indexing into Elasticsearch (Postgres → ES) for fast hunting
- Grouped background worker services for ingest, intelligence, and maintenance domains

## Recent changes (already implemented)

These items used to be “future work” and are now part of the project:

- **Seagull Portal (React)** with login, RBAC (admin vs. user), and a consistent “SOC console” UI.
- **Cursor (keyset) pagination** for heavy timelines:
  - Events: `GET /events`
  - Alerts (admin‑only): `GET /alerts`
  - Inventory history paging: `GET /inventory/{agent_id}/history/page`
- **Lupe SSH Insights** (`GET /events/ssh/summary`) + optional `ip-intel` worker process (inside `seagull-intelligence-worker`) that adds Geo/ASN metadata, using my personal tool: https://github.com/dynasmon/lupe.
- **Correlation Rules / Incidents** (admin‑only): CRUD correlation rules + run correlation to produce incident‑like findings.
- **1-minute rollup worker logic** (now hosted in `seagull-ingest-pipeline`) that pre‑aggregates data to reduce dashboard query cost.
- **Redis is now actively used** for portal rate‑limiting (best‑effort fail‑open) instead of being “reserved”.
- **Administrative audit/governance**:
  - append-only admin audit timeline (`admin_audit_events`)
  - login/auth evidence with persistence and queryability
  - audit coverage for users, allowlists, rule governance, agent admin actions, and platform settings
  - dedicated retention worker logic (now hosted in `seagull-maintenance-worker`)

---

## High‑Level Architecture

Dynasmon Seagull is composed of multiple services, orchestrated with Docker Compose:

Backend modular-monolith boundaries and contribution guardrails are documented in
`backend/docs/architecture.md`.

- **seagull-agent-*** (Go)
  - Runs close to the network (host or segment).
  - Supports multiple telemetry sources (selected via `SEAGULL_SOURCES`), including:
    - `proc` (flows from `/proc/net/tcp*`)
    - `authlog` (SSH/auth log parsing)
    - `scan` (PCAP‑based scan detection)
    - `lateral` (PCAP + proc‑assisted lateral movement telemetry)
    - `ddos` (PCAP‑based DoS/DDoS heuristics)
    - `syscollector` (OS + package inventory snapshots)
  - Sends batched events to the backend over HTTPS with rotating agent credentials plus a persisted self-recovery token (both bound to `agent_id`).

- **seagull-backend** (FastAPI)
  - Ingestion API (agent‑auth): `POST /ingest/events`
  - Control plane (agent‑auth): `/agents/enroll`, `/agents/heartbeat`, `/agents/config`
  - Portal APIs (user/admin): `/events`, `/inventory`, `/overview`, `/auth/*`, `/account/*`, `/admin/*`
  - Normalizes and persists to PostgreSQL.
  - Adds baseline hardening headers + GZip for JSON.

- **seagull-portal** (React + Vite)
  - Operator UI: Overview, Agents, Events (with pagination), SSH Insights, Inventory, Alerts, Correlations, Settings.
  - Uses portal auth (`/auth/login`, `/auth/refresh`, `/auth/me`) and does not rely on localStorage roles.

- **caddy** (public reverse proxy with automatic HTTPS)
  - Terminates HTTPS for externally exposed entrypoints.
  - Routes `/` -> portal, `/api/*` -> backend, `/agent/*` -> backend.
  - Adds HSTS + security headers and forwards `X-Forwarded-*` headers to upstream services.

- **seagull-ingest-pipeline**
  - Runs ingest queue draining, Elasticsearch indexing, and 1-minute rollups in one supervised group.
  - Child modules: `app.workers.ingest.main`, `app.workers.indexing.elasticsearch`, `app.workers.analytics.rollup_1m`.

- **seagull-intelligence-worker**
  - Runs rule evaluation and enrichment/correlation workers in one supervised group.
  - Child modules: `app.workers.intelligence.rules.runner`, `app.workers.intelligence.ip_intel.main`, `app.workers.intelligence.protocol.main`, `app.workers.intelligence.attack_chain.main`, `app.workers.intelligence.exposure.main`.

- **seagull-maintenance-worker**
  - Runs administrative maintenance loops.
  - Child modules: `app.workers.maintenance.audit_retention` and (in production when enabled) the bootstrap token rotator.

- **PostgreSQL**
  - Stores raw events in `net_events`.
  - Stores alerts in `alerts`.
  - Stores portal users/sessions, agent inventory snapshots, correlation rules, and offsets for workers.

- **Redis**
  - Used for portal rate‑limiting (login/OTP) with short TTL keys.
  - Can be extended later for Streams/queues if needed.

- **Grafana (optional)**
  - Provisioned automatically (datasources + dashboards) via `infra/grafana/provisioning`.
  - Reads Postgres for rollups/events/alerts and Elasticsearch for indexed hunting (optional).

- **Elasticsearch (optional)**
  - Stores indexed events for fast hunting and flexible aggregations (index pattern `seagull-events-*`).
  - Fed asynchronously by the `es-indexer` child inside `seagull-ingest-pipeline` (Postgres → Elasticsearch).

Worker group manager entrypoints:

- `python -m app.workers.manager ingest`
- `python -m app.workers.manager intelligence`
- `python -m app.workers.manager maintenance`

---

## Detection Engineering

| Document | What it covers |
|---|---|
| [docs/detections/architecture.md](docs/detections/architecture.md) | Module boundaries, data flow, import rules, layer responsibilities |
| [docs/detections/rule_format_v2.md](docs/detections/rule_format_v2.md) | v2 rule schema, detection blocks, aggregation types, tuning, migration from v1 |
| [docs/detections/canonical_fields.md](docs/detections/canonical_fields.md) | Supported telemetry fields, operators, how to add a new field |
| [docs/detections/correlation_engine.md](docs/detections/correlation_engine.md) | Correlation strategies, durable incidents, how to write a correlation rule |
| [docs/detections/attack_stories.md](docs/detections/attack_stories.md) | Kill-chain story templates, stage matching, scoring, how to write a story |
| [docs/detections/backtesting.md](docs/detections/backtesting.md) | Backtesting via API and Python, YAML unit tests, tuning / suppression |
| [docs/detections/sigma_import.md](docs/detections/sigma_import.md) | Sigma → v2 importer, supported subset, field mapping, review process |
| [docs/workers/architecture.md](docs/workers/architecture.md) | Worker groups, manager behaviour, per-worker env vars, import rules |

---

## Technology Stack

### Agent

- **Language:** Go
- **Telemetry:** `/proc/net/tcp*`, authlog parsing, gopacket PCAP capture
- **Security:** HTTPS edge + rotating per-agent credential hashes with durable agent-side identity state (no client cert operation for agents).

### Backend

- **Language:** Python
- **Framework:** FastAPI (Pydantic + OpenAPI)
- **DB:** SQLAlchemy + PostgreSQL
- **Auth (Portal):** access/refresh tokens with HttpOnly cookies + Bearer access token
- **Auth (Agents):** one-time bootstrap enrollment, overlapping rotating credentials, and recovery-token self-healing (hash-only persistence, `agent_id` binding).
- **Perf:** bulk inserts for ingest, optional rollups for dashboard load reduction

### Portal

- **React + TypeScript**, Vite
- **Tailwind CSS** (UI tuned for “SOC console” layout)
- **Auth‑aware routing** (ProtectedLayout) + admin‑only sections

### Observability / Search

- **Grafana** (optional, provisioned dashboards)
- **Elasticsearch + Kibana** (optional)

---

## Getting Started

### Prerequisites

- Docker with Compose plugin (`docker compose version`)
- Python 3.9+
- Git

### 1. Clone the repository

```bash
git clone https://gitlab.com/nathanmblima/dynasmon-seagull.git
cd dynasmon-seagull
```

### 2. Start (single command)

```bash
./seagull up
```

This is the only command you need for first run and all subsequent reruns. It:

- Creates `.env` from `.env.example` when missing, and syncs new keys on reruns
- Runs preflight checks (Docker daemon, TLS files, compose config)
- Builds and starts the full stack
- Mints short-lived per-agent bootstrap tokens and starts agent containers

### 3. Common commands

```bash
./seagull up                        # start (dev mode by default)
./seagull up --mode dev             # explicit dev mode
./seagull up --mode prod            # production mode (Caddy HTTPS edge)
./seagull up --agent-mode systemd   # start platform only; host systemd agent handles collection
./seagull down                      # stop the stack
./seagull status                    # show running container status
./seagull logs                      # follow all service logs
./seagull logs seagull-backend      # follow a specific service
./seagull doctor                    # check deps, TLS, secrets, compose config
./seagull restart                   # rebuild and restart
./seagull restart --quick           # recreate containers without rebuild
./seagull reset --volumes           # stop and remove all containers and volumes (DANGEROUS)
```

### 4. Environment variables

No manual `.env` setup is required. `./seagull up` handles it automatically.

To pre-customize values before first startup:

```bash
cp .env.example .env
# edit .env
```

Minimum required for a secure bootstrap:

- `SEAGULL_JWT_SECRET` or `SEAGULL_JWT_SECRET_FILE` (auto-generated if weak/missing in prod mode)
- `SEAGULL_BOOTSTRAP_ADMIN_PASSWORD` or `SEAGULL_BOOTSTRAP_ADMIN_PASSWORD_FILE`
- In dev, `SEAGULL_BOOTSTRAP_ADMIN_RESET_ON_START=true` re-syncs the admin password on startup.

Recommended production hardening:

- Use `*_FILE` variants with Docker secrets for all credentials.
- Set `SEAGULL_COOKIE_SECURE=true` behind HTTPS.
- Configure Caddy domain: `SEAGULL_CADDY_DOMAIN`, `SEAGULL_CADDY_EMAIL`.
- Set `SEAGULL_AUDIT_HASH_PEPPER` / `SEAGULL_AUDIT_HASH_PEPPER_FILE`.

For production setup wizard (interactive):

```bash
./seagull env wizard
./seagull up --mode prod
```

### 5. Native Linux `systemd` agent deployment

Run the agent directly on a Linux host instead of in a container. The platform services (backend, portal, workers) still run in Docker; only the agent runs as a systemd service.

```bash
# Install (from repo root, as root):
./seagull agent install-systemd

# Start platform without Docker agent containers:
./seagull up --agent-mode systemd

# Agent management:
./seagull agent status-systemd
./seagull agent restart-systemd
./seagull agent validate-systemd
```

#### Installed paths

| Purpose | Path |
|---|---|
| Agent binary | `/usr/local/bin/seagull-agent` |
| Service unit | `/etc/systemd/system/seagull-agent.service` |
| Environment config | `/etc/seagull/agent.env` |
| CA file | `/etc/seagull/pki/root_ca.crt` |
| CA sync helper | `/usr/local/lib/seagull/seagull-agent-sync-ca.sh` |
| CA sync timer | `seagull-agent-ca-sync.timer` |
| State files | `/var/lib/seagull` (`agent.identity.json`, `agent.credential`, `agent.config.json`) |
| Runtime logs | `journalctl -u seagull-agent` |

After install, edit `/etc/seagull/agent.env` and set at minimum:

- `SEAGULL_AGENT_ID`
- `SEAGULL_API_URL`
- `SEAGULL_AGENT_BOOTSTRAP_TOKEN` or `SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE`
- `SEAGULL_TLS_CA_FILE` (default: `/etc/seagull/pki/root_ca.crt`)

Install modes:

```bash
# Default: build from source
./seagull agent install-systemd

# Use a pre-built binary:
BUILD_FROM_SOURCE=0 SOURCE_BINARY=/path/to/seagull-agent ./seagull agent install-systemd

# Auto-start when prerequisites are met:
AUTO_START_IF_READY=1 ./seagull agent install-systemd
```

The installer is idempotent: preserves existing `agent.env`, migrates legacy token paths, normalizes permissions, installs the CA sync timer.

### 6. Clean reset

```bash
./seagull nuke    # remove all containers and volumes
./seagull up      # fresh start
```

### 7. Open the Portal

- Dev: `https://localhost:${SEAGULL_EDGE_HTTPS_PORT:-8443}`
- Prod: `https://<SEAGULL_CADDY_DOMAIN>`
- Login: `SEAGULL_BOOTSTRAP_ADMIN_USERNAME` / `SEAGULL_BOOTSTRAP_ADMIN_PASSWORD`

If login gets out of sync with `.env`:

```bash
./seagull admin reset
```

### 8. Verify the backend

```bash
curl -k https://localhost:${SEAGULL_EDGE_HTTPS_PORT:-8443}/api/health
# {"status":"ok"}

curl -k https://localhost:${SEAGULL_EDGE_HTTPS_PORT:-8443}/api/health/ready
```

### 9. Optional profiles

```bash
# Observability (Grafana + Kibana):
./seagull observability

# Extra agent collectors (lateral movement):
./seagull dev --extra
```

Grafana: `http://localhost:${GRAFANA_PORT:-3000}` (auto-provisioned from `infra/grafana/provisioning`).

### 10. Redis modes

- **Dev (default)**: ephemeral — restarts are clean by default.
- **Dev persistent**: `./seagull up --mode dev --persist` — survives restarts.
- **Prod**: persistent, requires `SEAGULL_REDIS_PASSWORD`.

AOF recovery (stop Redis first):

```bash
./seagull redis repair-aof
```

### 11. Developer quality pipeline

```bash
./seagull lint          # ruff + eslint + gofmt + go vet
./seagull test          # pytest + go test + npm smoke
./seagull test --detections   # detection catalog + rule unit tests only
./seagull build         # build all service images
./seagull deps-check    # pip-audit + npm audit + govulncheck
./seagull ci            # lint + test + build
```

CI (`.gitlab-ci.yml`) runs lint/tests, image build, dependency audit, and secret scanning (`gitleaks`) on push and merge request pipelines.

### 12. Database migrations and lifecycle (Alembic)

The project now uses Alembic for schema versioning.

- Migration files live in `backend/alembic/versions/`
- Initial baseline migration: `20260308_0001`
- Rule governance migration: `20260309_0002`
- Admin audit/governance migration: `20260311_0003`
- Runtime no longer depends on `Base.metadata.create_all()` for schema evolution

Lifecycle flow:

- **Initial bootstrap (dev)**: `SEAGULL_DB_AUTO_UPGRADE=true` is set in dev mode, so services apply `alembic upgrade head` automatically.
- **Upgrade before prod deploy**: run migrations explicitly, then start services.

Useful commands:

```bash
./seagull db upgrade    # run alembic upgrade head via backend container
./seagull db current    # show current revision
```

In production mode, `SEAGULL_DB_AUTO_UPGRADE=false` by default.

### 13. Administrative Audit and Governance

Administrative evidence is persisted in Postgres with the same architecture in dev and prod:

- `admin_audit_events`: append-only administrative and auth timeline
- `portal_login_events`: login evidence (success/failure, method, source)
- `alert_rule_tuning_history` / `alert_rule_suppressions_history`: rule governance history

Administrative governance/query endpoints:

- `GET /admin/audit/events` (filters by time/user/action/resource/outcome)
- `GET /admin/login-history`
- `GET|POST|PUT|DELETE /users`
- `GET|PUT|DELETE /settings`

Frontend audit/governance console:

- Route: `/audit` (admin-only)
- Subroutes:
  - `/audit/admin-actions`
  - `/audit/logins`
  - `/audit/changes`
  - `/audit/timeline`
- UX capabilities:
  - URL-persisted filters (period, actor, action, category, resource, outcome, free text, origin)
  - server-side timeline paging through `until` cursor windows (same endpoint contract in dev/prod)
  - per-event investigation drawer (`before/after/context`, changed fields, request/correlation metadata, hash-chain references)
  - retention visibility from `GET /admin/runtime-config` security policy fields

Retention enforcement:

- worker group: `seagull-maintenance-worker` (child: `audit-retention`)
- same retention mechanism in dev/prod; only windows/volume change by config
- defaults:
  - dev: 30 days
  - prod: 365 days (compose prod defaults)

Config knobs:

- `SEAGULL_AUDIT_RETENTION_ENABLED`
- `SEAGULL_AUDIT_RETENTION_DAYS`
- `SEAGULL_LOGIN_AUDIT_RETENTION_DAYS`
- `SEAGULL_GOVERNANCE_RETENTION_DAYS`
- `SEAGULL_AUDIT_RETENTION_EVERY_SECONDS`
- `SEAGULL_AUDIT_RETENTION_DELETE_BATCH`

Troubleshooting (Postgres auth failed):

- If you see `password authentication failed for user "seagull"` after changing `POSTGRES_PASSWORD`, your existing `postgres-data` volume still has the old password.
- Option 1 (keep data): set `.env` `POSTGRES_PASSWORD` back to the password used when that volume was first created.
- Option 2 (reset disposable local state): run `./seagull nuke` and then `./seagull up`.

Other common first-run issues:

- `Bootstrap admin password rejected`: your `SEAGULL_BOOTSTRAP_ADMIN_PASSWORD` does not meet policy (12+ chars, upper/lower/digit/symbol, cannot include username).
- Portal loads but UI fails behind TLS edge: check `infra/caddy/Caddyfile.dev` (dev CSP/HMR policy) and restart with `./seagull restart`.
- Optional workers degraded while API is available: this is expected when optional services (for example Elasticsearch/ClickHouse) are unavailable and not required.

### 14. Development observability

Backend and workers now emit structured JSON logs with a common shape:

- `ts`, `level`, `service`, `logger`, `event`, and contextual fields
- request context on API logs (`request_id`, `trace_id`)

API runtime observability:

- `X-Request-Id`, `X-Trace-Id`, `X-Response-Time-Ms` response headers
- clearer error payloads with `request_id`
- in-memory debugging metrics at `GET /metrics`
- realtime counters in `GET /metrics` for stream opens/reconnects/disconnects, publish/drop paths, topic publishes, coalescing, cursor gaps, and replay overflow recovery

Hybrid realtime operations:

- portal realtime stays on the existing `/api/realtime/portal` (SSE) and `/api/realtime/portal/ws` (WebSocket) routes in both dev and prod
- Caddy dev and prod force non-buffered SSE delivery with `flush_interval -1`, `Cache-Control: no-cache, no-transform`, and `X-Accel-Buffering: no`
- websocket failures, invalid tokens, unauthorized topics, Redis unavailability, cursor gaps, and replay overflow now emit explicit logs/counters instead of silently degrading
- the frontend keeps bounded reconnect backoff and falls back to reconciliation/polling when live delivery is degraded; the internal debug view exposes the client-side fallback/reconnect counters

Tracing (local/simple):

- Send `X-Trace-Id` in requests to correlate logs across calls
- If missing, backend generates one automatically

---

## Packet Capture Requirements (PCAP Agents)

The `scan`, `lateral`, and `ddos` agents use packet capture and require elevated capabilities. In Docker Compose, those services run with `network_mode: host` and `cap_add: NET_RAW, NET_ADMIN`.

If you do not want to run PCAP‑based collectors, disable those services (or don’t start the `extra` profile).

---

## DoS/DDoS (Reducing False Positives)

The `seagull-agent-ddos` collector supports hard thresholds to avoid emitting low‑signal detections.

Key environment variables:

- `SEAGULL_DDOS_MIN_PACKETS`  
  Minimum packet count in the evaluation window required to emit a detection.

- `SEAGULL_DDOS_MIN_REQUESTS`  
  Minimum L7 “request‑like” count (e.g., HTTP indicators / TLS handshakes) in the evaluation window required to emit L7 detections.

- `SEAGULL_DDOS_MIN_CONFIDENCE`  
  Minimum confidence score required to emit a `dos_attack` event.

Noise control for lab environments:

- `SEAGULL_PROC_DROP_LIKELY_OUTBOUND=true`
- `SEAGULL_EPHEMERAL_PORT_MIN=49152`

These settings help drop traffic likely related to outbound connections where the local host is using ephemeral destination ports.

---

## SSH Insights (Lupe)

Seagull includes an SSH Insights endpoint:

- `GET /events/ssh/summary`

When enrichment is enabled (via the `ip-intel` child inside `seagull-intelligence-worker`), SSH auth events can be enriched with:

- Country/region/city (Geo)
- ASN and ASN org
- Organization

The worker maintains a small Postgres cache (`ip_enrichment_cache`) to respect rate limits.

---

## Cursor Pagination (recommended for UIs)

Timelines can grow fast. Prefer the cursor endpoints for UIs/infinite scroll:

- Events: `GET /events?page_size=50&cursor=<opaque>`
- Alerts (admin): `GET /alerts?page_size=50&cursor=<opaque>`
- Inventory history: `GET /inventory/{agent_id}/history/page?page_size=50&cursor=<opaque>`

Responses return:

- `items`: the page results
- `next_cursor`: pass this to fetch the next page
- `has_more`: whether more results exist

---

## Exposure & Attack Path Graph

The Exposure & Attack Path Graph feature computes per-asset risk posture by projecting evidence from agents, vulnerability scans, alerts, attack-chain cases, and response actions into a scored graph model.

### What it does

- Scores every monitored asset on a 0–100 risk scale with severity banding (informational / low / medium / high / critical).
- Projects asset telemetry into an attack-path graph: asset nodes link to vulnerability nodes, service/package nodes, alert nodes, attack-chain case nodes, investigation nodes, and response-action nodes.
- Generates findings with reason codes, evidence references, confidence levels, and prioritised remediation recommendations.
- Maintains per-asset score history so operators can track risk trend over time.
- Emits realtime SSE/WebSocket events when asset posture or findings change.

### Enabling the worker

The worker runs inside `seagull-intelligence-worker` as the `exposure-graph` child process. It is enabled by default:

```
SEAGULL_EXPOSURE_ENABLED=true
```

Set to `false` to disable it without affecting other intelligence workers.

### Key environment variables

| Variable | Default | Purpose |
|---|---|---|
| `SEAGULL_EXPOSURE_ENABLED` | `true` | Enable/disable the worker |
| `SEAGULL_EXPOSURE_EVERY_SECONDS` | `300` | Full refresh cycle interval |
| `SEAGULL_EXPOSURE_EVENT_BATCH_SIZE` | `500` | Events processed per incremental pass |
| `SEAGULL_EXPOSURE_LOOKBACK_HOURS` | `48` | Event window for bootstrap scan |
| `SEAGULL_EXPOSURE_MAX_FINDINGS_PER_ASSET` | `100` | Max open findings per asset |
| `SEAGULL_EXPOSURE_SCORE_HISTORY_EVERY_SECONDS` | `3600` | Score history snapshot interval |
| `SEAGULL_EXPOSURE_STALE_AGENT_MINUTES` | `60` | Agent staleness threshold |
| `SEAGULL_EXPOSURE_STALE_INVENTORY_HOURS` | `24` | Inventory staleness threshold |
| `SEAGULL_EXPOSURE_MAX_GRAPH_NODES_PER_ASSET` | `200` | Hard node limit per graph response |
| `SEAGULL_EXPOSURE_MAX_GRAPH_EDGES_PER_ASSET` | `300` | Hard edge limit per graph response |

### API routes

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/exposure/summary` | user | Fleet-wide risk summary and top reason codes |
| `GET` | `/exposure/assets` | user | Paginated asset posture list with filters |
| `GET` | `/exposure/assets/{key}` | user | Full asset detail with linked evidence |
| `GET` | `/exposure/assets/{key}/graph` | user | Attack-path graph for an asset |
| `GET` | `/exposure/paths` | user | Paginated attack path list |
| `GET` | `/exposure/findings` | user | Paginated findings list |
| `POST` | `/exposure/recalculate` | admin | Trigger a forced full refresh |
| `POST` | `/exposure/assets/{key}/investigation` | admin | Open an investigation from an asset |
| `POST` | `/exposure/assets/{key}/response-actions/triage` | admin | Create a triage response action |

Pagination follows the same cursor (keyset) contract as other list endpoints: `items`, `next_cursor`, `has_more`.

### Portal UI

Navigate to **Assets & Exposure → Exposure Graph** (`/exposure`) in the Seagull Portal.

The page provides:
- Summary cards (critical / high / medium / low asset counts, active findings, attack paths)
- Filterable asset table with risk score, severity, and reason-code columns
- Attack-path timeline tab
- Findings tab
- Per-asset drawer with score breakdown, recommendations, linked evidence, and score history
- Interactive attack-path graph canvas
- Realtime refresh on posture and finding updates
- Admin-only actions (recalculate, open investigation, create triage response action)

---

## Roadmap and Future Work

Planned enhancements (not yet implemented):

1. **Deeper Network Enrichment**
   - DNS metadata, HTTP host/method, TLS fingerprints (JA3/JA4), protocol‑aware parsing.

2. **Broader Endpoint Inventory**
   - Extend syscollector to include services, users, running processes, and persistence points.

3. **Optional Redis Streams Pipeline**
   - Stream ingestion → enrich → correlate → alert as separate workers.

4. **Correlation Automation**
   - Scheduled correlation runs, MITRE‑mapped incident summaries, and better “case” lifecycle.

5. **Production Hardening**
   - Expanded RBAC scopes and policy-as-code governance workflows.

6. **Scalable Database**
   - Use of Cassandra for better escallability and log analyses (Write-Heavy, Schema-free, Compliance)
   
---

## Security Considerations

Even in a lab environment, Seagull touches sensitive areas:

- Packet capture and low‑level hooks can expose network metadata.
- Logs and events may contain IPs, hostnames, and user identifiers.
- PCAP‑based agents may require elevated privileges (NET_RAW/NET_ADMIN and/or root).

Use this project responsibly:

- Prefer isolated or lab networks for traffic capture.
- Do not deploy in environments where you do not have explicit authorization.
- Treat collected data as sensitive and protect access to the database, portal, and dashboards.

Portal security notes:

- Use strong runtime secrets (prefer `*_FILE` + Docker secrets in prod).
- Use a strong `SEAGULL_JWT_SECRET` and rotate it if leaked.
- Set `SEAGULL_AUDIT_HASH_PEPPER` (or `_FILE`) to strengthen audit-chain integrity hashes.
- Run behind HTTPS and set `SEAGULL_COOKIE_SECURE=true`.
- Keep bootstrap tokens short-lived and one-time; avoid long-lived shared enroll secrets.

### Agent Identity Lifecycle

Control-plane path for agents remains `https://<edge>/agent/*`.

1. Create a short-lived bootstrap token per agent:
   - `POST /api/agents/{agent_id}/bootstrap-tokens`
2. Start/restart the agent with:
   - `SEAGULL_AGENT_BOOTSTRAP_TOKEN` (or `_FILE`) for first enroll
   - `SEAGULL_AGENT_ID`
3. Agent enrolls with the bootstrap token (`POST /agent/agents/enroll`) and receives:
   - a rotating credential
   - a long-lived one-time recovery token
4. Agent persists identity state under `/var/lib/seagull` and keeps the legacy credential file for compatibility.
5. Agent uses `X-Agent-ID` + `X-Agent-Credential` for `/agent/*` requests.
6. Backend stores only salted credential/recovery-token hashes and binds them to `agent_id`.
7. The agent rotates the credential before expiry via `POST /agent/agents/credential/rotate`.
8. If the active credential is expired, revoked, or lost during switchover, the agent automatically reenrolls with the recovery token, then falls back to the bootstrap token if still available.

Operational notes:

- Keep bootstrap tokens short-lived and low-use.
- Credential rotation keeps a short overlap window so switchover is crash-safe.
- Disabling an agent revokes active credentials and all recovery/bootstrap tokens.
- Operators can hard-reset an agent identity with `POST /api/agents/{agent_id}/identity/reissue`.
- No step-ca, edge reloader, or runtime edge cert/key issuance is required for public edge.

### Detection Content Engineering

Catalog layout:

- `rules/packs/core/*`: stable detections for auth/baseline.
- `rules/packs/network/*`: stable detections for recon/lateral/impact.
- `rules/packs/lab/*`: experimental detections for dev/lab rollout.

Pack activation by environment (same loader/motor, different activation only):

- `SEAGULL_RULES_ENV`: logical environment label used by rule filters (`dev`, `homolog`, `prod`, `lab`).
- `SEAGULL_RULES_ENABLED_PACKS`: CSV allowlist of packs to load (e.g. `core,network`).
- `SEAGULL_RULES_DISABLED_PACKS`: optional CSV denylist.
- `SEAGULL_RULES_INCLUDE_EXPERIMENTAL`: enables/disables rules with `maturity: experimental`.

Recommended defaults:

- Dev/Lab: `SEAGULL_RULES_ENABLED_PACKS=core,network,lab` and `SEAGULL_RULES_INCLUDE_EXPERIMENTAL=true`.
- Prod: `SEAGULL_RULES_ENABLED_PACKS=core,network` and `SEAGULL_RULES_INCLUDE_EXPERIMENTAL=false`.

False-positive reduction controls:

- Per-rule `tuning.allowlist` supports `src_ips`, `dst_ips`, `agent_ids`, `dst_ports`, `protos`, `src_cidrs`, `dst_cidrs`.
- Rule suppressions and schedules remain available through portal governance APIs.
- Prefer precise group keys and higher thresholds for stable packs; keep noisier analytics in `lab`.
- Agents now enrich telemetry with confidence/context fields consumed by stable rules:
  - `scan_probe`: `extra.scan_confidence`, `extra.scan_type`, `extra.syn_only`, `extra.collector`
  - `lateral_conn`: `extra.lateral_confidence`, `extra.lateral_kind`, `extra.syn_only`, `extra.collector`
  - `flow`: `extra.flow_state_class`, `extra.flow_confidence`, `extra.tcp_state_name`, `extra.collector`

Validation suite:

- Rule behavior/unit tests: `backend/tests/test_rules_and_correlations.py`
- Catalog quality checks (schema/severity/ATT&CK mapping + pack filtering): `backend/tests/test_detection_catalog.py`
- Run only detection validation:
  - `./seagull test --detections`

---

## Performance: Rollups (Grafana/Postgres CPU reduction)

Seagull includes an optional rollup worker that pre‑aggregates `net_events` into 1‑minute buckets.
This significantly reduces CPU usage caused by Grafana dashboards that run COUNT/GROUP BY queries over large windows.

- Worker group: `seagull-ingest-pipeline` (child: `rollup-1m`)
- Tables: `event_rollups_1m`, `ssh_fail_rollups_1m`
- Offsets: `search_index_offsets` (`rollup_events_1m`, `rollup_ssh_fail_1m`)

Tune via `.env`:

- `SEAGULL_ROLLUP_EVERY_SECONDS`, `SEAGULL_ROLLUP_MAX_ROWS`
