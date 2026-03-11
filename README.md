# Dynasmon NetWatch

Dynasmon NetWatch is a threat hunting platform designed as a lightweight, opinionated mini‑SIEM. It started as a network telemetry pipeline and is evolving toward an “XDR‑foundation” architecture inspired by Wazuh endpoint management.

At this stage, NetWatch provides an end‑to‑end pipeline:

- Multiple Go agents that capture and ship telemetry (proc/authlog + PCAP‑based collectors + endpoint syscollector)
- A FastAPI backend that ingests and persists events into PostgreSQL
- A rules engine + worker that evaluates YAML detections and generates alerts
- A **NetWatch Portal** (React) with authentication and an operator‑friendly UI
- Optional search indexing into Elasticsearch (Postgres → ES) for fast hunting
- Optional workers for **rollups** (Postgres CPU reduction) and **SSH enrichment** (Lupe/IPInfo)

## Recent changes (already implemented)

These items used to be “future work” and are now part of the project:

- **NetWatch Portal (React)** with login, RBAC (admin vs. user), and a consistent “SOC console” UI.
- **Cursor (keyset) pagination** for heavy timelines:
  - Events: `GET /events`
  - Alerts (admin‑only): `GET /alerts`
  - Inventory history paging: `GET /inventory/{agent_id}/history/page`
- **Lupe SSH Insights** (`GET /events/ssh/summary`) + optional enrichment worker (`netwatch-lupe-enricher`) that adds Geo/ASN metadata, using my personal tool: https://github.com/dynasmon/lupe.
- **Correlation Rules / Incidents** (admin‑only): CRUD correlation rules + run correlation to produce incident‑like findings.
- **Rollup worker** (`netwatch-rollup-worker`) that pre‑aggregates data into 1‑minute buckets to keep Grafana responsive.
- **Redis is now actively used** for portal rate‑limiting (best‑effort fail‑open) instead of being “reserved”.

---

## High‑Level Architecture

Dynasmon NetWatch is composed of multiple services, orchestrated with Docker Compose:

- **netwatch-agent-*** (Go)
  - Runs close to the network (host or segment).
  - Supports multiple telemetry sources (selected via `NETWATCH_SOURCES`), including:
    - `proc` (flows from `/proc/net/tcp*`)
    - `authlog` (SSH/auth log parsing)
    - `scan` (PCAP‑based scan detection)
    - `lateral` (PCAP + proc‑assisted lateral movement telemetry)
    - `ddos` (PCAP‑based DoS/DDoS heuristics)
    - `syscollector` (OS + package inventory snapshots)
  - Sends batched events to the backend over HTTP.

- **netwatch-backend** (FastAPI)
  - Ingestion API (agent‑auth): `POST /ingest/events`
  - Control plane (agent‑auth): `/agents/enroll`, `/agents/heartbeat`, `/agents/config`
  - Portal APIs (user/admin): `/events`, `/inventory`, `/overview`, `/auth/*`, `/account/*`, `/admin/*`
  - Normalizes and persists to PostgreSQL.
  - Adds baseline hardening headers + GZip for JSON.

- **netwatch-portal** (React + Vite)
  - Operator UI: Overview, Agents, Events (with pagination), SSH Insights, Inventory, Alerts, Correlations, Settings.
  - Uses portal auth (`/auth/login`, `/auth/refresh`, `/auth/me`) and does not rely on localStorage roles.

- **netwatch-rules-worker**
  - Periodically loads baseline YAML detections from `./rules/` (supports packs under `./rules/packs/**`).
  - Applies optional rule overrides (enable/disable/severity) and writes findings to the `alerts` table.

- **PostgreSQL**
  - Stores raw events in `net_events`.
  - Stores alerts in `alerts`.
  - Stores portal users/sessions, agent inventory snapshots, correlation rules, and offsets for workers.

- **Redis**
  - Used for portal rate‑limiting (login/OTP) with short TTL keys.
  - Can be extended later for Streams/queues if desired.

- **Grafana**
  - Provisioned automatically (datasources + dashboards) via `infra/grafana/provisioning`.
  - Reads Postgres for rollups/events/alerts and Elasticsearch for indexed hunting (optional).

- **Elasticsearch (optional)**
  - Stores indexed events for fast hunting and flexible aggregations (index pattern `netwatch-events-*`).
  - Fed asynchronously by `netwatch-es-indexer` (Postgres → Elasticsearch).

- **Optional workers**
  - `netwatch-rollup-worker`: pre‑aggregates data into 1‑minute rollup tables.
  - `netwatch-lupe-enricher`: enriches SSH events (`ssh_auth`) with Geo/ASN metadata (IPInfo).

---

## Technology Stack

### Agent

- **Language:** Go
- **Telemetry:** `/proc/net/tcp*`, authlog parsing, gopacket PCAP capture
- **Security:** agent tokens (`Authorization: Bearer <agent_id>.<secret>`) issued at enroll

### Backend

- **Language:** Python
- **Framework:** FastAPI (Pydantic + OpenAPI)
- **DB:** SQLAlchemy + PostgreSQL
- **Auth (Portal):** access/refresh tokens with HttpOnly cookies + Bearer access token
- **Auth (Agents):** per‑agent token created at enroll; optional `X-Enroll-Token` gate
- **Perf:** bulk inserts for ingest, optional rollups for dashboard load reduction

### Portal

- **React + TypeScript**, Vite
- **Tailwind CSS** (UI tuned for “SOC console” layout)
- **Auth‑aware routing** (ProtectedLayout) + admin‑only sections

### Observability / Search

- **Grafana** (provisioned dashboards)
- **Elasticsearch + Kibana** (optional)

---

## Getting Started

### Prerequisites

- Docker
- Docker Compose (Docker CLI plugin or standalone)
- Git (to clone the repository)

### 1. Clone the repository

```bash
git clone https://gitlab.com/nathanmblima/dynasmon-netwatch.git
cd dynasmon-netwatch
```

### 2. Configure environment variables

Start from the template:

```bash
cp .env.example .env
```

Create runtime secret files (recommended for prod and supported in dev):

```bash
mkdir -p secrets
openssl rand -hex 24 > secrets/postgres_password.txt
openssl rand -hex 24 > secrets/grafana_admin_password.txt
openssl rand -hex 32 > secrets/netwatch_jwt_secret.txt
openssl rand -hex 24 > secrets/netwatch_bootstrap_admin_password.txt
openssl rand -hex 24 > secrets/netwatch_enroll_token.txt
openssl rand -hex 24 > secrets/netwatch_redis_password.txt
openssl rand -hex 24 > secrets/netwatch_es_password.txt
```

The backend now supports both `VAR` and `VAR_FILE` for secrets. Compose prod mounts Docker secrets under `/run/secrets/*`.

Minimum required for secure bootstrap:

- `NETWATCH_JWT_SECRET` or `NETWATCH_JWT_SECRET_FILE`
- `NETWATCH_BOOTSTRAP_ADMIN_PASSWORD` or `NETWATCH_BOOTSTRAP_ADMIN_PASSWORD_FILE`
- In dev, `NETWATCH_BOOTSTRAP_ADMIN_RESET_ON_START=true` can resync the bootstrap admin password on startup.

Recommended hardening:

- Set `NETWATCH_ENROLL_TOKEN`/`NETWATCH_ENROLL_TOKEN_FILE` and only allow enroll when the agent sends `X-Enroll-Token`.
- When behind HTTPS, set `NETWATCH_COOKIE_SECURE=true` and consider `NETWATCH_COOKIE_SAMESITE=strict`.

If you enable SSH enrichment (Lupe), set:

- `NETWATCH_IPINFO_TOKEN` (IPInfo token)

### 3. Bootstrap and start (single command)

```bash
make dev
```

This command:

- Creates `.env` from `.env.example` when missing
- Uses `docker-compose.yml + compose.dev.yml`
- Builds and starts the development stack

For production-style local runs:

```bash
make prod
```

This uses `docker-compose.yml + compose.prod.yml` with Docker secrets mounts (`/run/secrets/*`).
Startup fails fast in prod if required secrets are missing/weak.

### 4. Start optional profile (`extra`)

```bash
make up-extra
```

By default, this starts:

- `netwatch-backend`
- `netwatch-portal`
- `netwatch-rules-worker`
- `netwatch-es-indexer`
- `netwatch-rollup-worker`
- `netwatch-lupe-enricher` (will run; enrichment is a no‑op unless `NETWATCH_IPINFO_TOKEN` is set)
- `netwatch-postgres`
- `netwatch-redis`
- `netwatch-elasticsearch`
- `netwatch-grafana`
- `netwatch-agent-proc-1`
- `netwatch-agent-scan-1`
- `netwatch-agent-ddos`

Optional services in profile `extra`:

- `netwatch-kibana`
- `netwatch-agent-lateral`

The `make up-extra` target starts the profile above.

### 5. Open the Portal

- Portal: `http://localhost:${NETWATCH_PORTAL_PORT:-8080}`
- Login with:
  - Username: `NETWATCH_BOOTSTRAP_ADMIN_USERNAME` (default: `admin`)
  - Password: `NETWATCH_BOOTSTRAP_ADMIN_PASSWORD`

The admin account is bootstrapped on an empty database at backend startup.
After logging in, change your password via **Settings** (or `POST /account/change-password`).

### 6. Verify the Backend

```bash
curl http://localhost:${NETWATCH_BACKEND_PORT:-8000}/health
```

Expected:

```json
{"status":"ok"}
```

### 7. Grafana / Kibana

- Grafana: `http://localhost:${GRAFANA_PORT:-3000}`
  - Credentials: `GF_SECURITY_ADMIN_USER` + value from `GF_SECURITY_ADMIN_PASSWORD` or `GF_SECURITY_ADMIN_PASSWORD_FILE`
  - Datasources + dashboards are **auto‑provisioned** from `infra/grafana/provisioning`.

- Kibana (optional): `http://localhost:${KIBANA_PORT:-5601}` (start with `--profile extra`)

### 8. Developer quality pipeline

Local commands:

- `make lint` -> backend (`ruff`), frontend (`eslint`), agent (`gofmt` + `go vet`)
- `make test` -> backend (`pytest`), agent (`go test`), frontend smoke (`npm run smoke`)
- `make build-prod` -> production image builds with `compose.prod.yml`
- `make deps-check` -> `pip-audit`, `npm audit`, `govulncheck`

CI (`.github/workflows/ci.yml`) runs lint/tests, image build, dependency checks, and secret scanning (`gitleaks`) on push and pull request.

### 9. Database migrations and lifecycle (Alembic)

The project now uses Alembic for schema versioning.

- Migration files live in `backend/alembic/versions/`
- Initial baseline migration: `20260308_0001`
- Runtime no longer depends on `Base.metadata.create_all()` for schema evolution

Lifecycle flow:

- **Initial bootstrap (dev)**: `compose.dev.yml` sets `NETWATCH_DB_AUTO_UPGRADE=true`, so services apply `alembic upgrade head` automatically.
- **Upgrade before prod deploy**: run migrations explicitly, then start services.

Useful commands:

- `make db-upgrade` -> run `alembic upgrade head` via backend container
- `make db-current` -> show current revision

For production-like runs (`compose.prod.yml`), `NETWATCH_DB_AUTO_UPGRADE=false` by default.

Troubleshooting (Postgres auth failed):

- If you see `password authentication failed for user "netwatch"` after changing `POSTGRES_PASSWORD`, your existing `postgres-data` volume still has the old password.
- Option 1 (keep data): set `.env` `POSTGRES_PASSWORD` back to the password used when that volume was first created.
- Option 2 (reset local dev DB): `docker compose down -v` and start again to reinitialize with current credentials.

### 10. Development observability

Backend and workers now emit structured JSON logs with a common shape:

- `ts`, `level`, `service`, `logger`, `event`, and contextual fields
- request context on API logs (`request_id`, `trace_id`)

API runtime observability:

- `X-Request-Id`, `X-Trace-Id`, `X-Response-Time-Ms` response headers
- clearer error payloads with `request_id`
- in-memory debugging metrics at `GET /metrics`

Tracing (local/simple):

- Send `X-Trace-Id` in requests to correlate logs across calls
- If missing, backend generates one automatically

---

## Packet Capture Requirements (PCAP Agents)

The `scan`, `lateral`, and `ddos` agents use packet capture and require elevated capabilities. In Docker Compose, those services run with `network_mode: host` and `cap_add: NET_RAW, NET_ADMIN`.

If you do not want to run PCAP‑based collectors, disable those services (or don’t start the `extra` profile).

---

## DoS/DDoS (Reducing False Positives)

The `netwatch-agent-ddos` collector supports hard thresholds to avoid emitting low‑signal detections.

Key environment variables:

- `NETWATCH_DDOS_MIN_PACKETS`  
  Minimum packet count in the evaluation window required to emit a detection.

- `NETWATCH_DDOS_MIN_REQUESTS`  
  Minimum L7 “request‑like” count (e.g., HTTP indicators / TLS handshakes) in the evaluation window required to emit L7 detections.

- `NETWATCH_DDOS_MIN_CONFIDENCE`  
  Minimum confidence score required to emit a `dos_attack` event.

Noise control for lab environments:

- `NETWATCH_PROC_DROP_LIKELY_OUTBOUND=true`
- `NETWATCH_EPHEMERAL_PORT_MIN=49152`

These settings help drop traffic likely related to outbound connections where the local host is using ephemeral destination ports.

---

## SSH Insights (Lupe)

NetWatch includes an SSH Insights endpoint:

- `GET /events/ssh/summary`

When the optional enrichment worker is enabled (`netwatch-lupe-enricher`), SSH auth events can be enriched with:

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
   - Reverse‑proxy templates (Caddy/Nginx), HTTPS defaults, tighter CSP, and improved RBAC.

6. **Scalable Database**
   - Use of Cassandra for better escallability and log analyses (Write-Heavy, Schema-free, Compliance)
   
---

## Security Considerations

Even in a lab environment, NetWatch touches sensitive areas:

- Packet capture and low‑level hooks can expose network metadata.
- Logs and events may contain IPs, hostnames, and user identifiers.
- PCAP‑based agents may require elevated privileges (NET_RAW/NET_ADMIN and/or root).

Use this project responsibly:

- Prefer isolated or lab networks for traffic capture.
- Do not deploy in environments where you do not have explicit authorization.
- Treat collected data as sensitive and protect access to the database, portal, and dashboards.

Portal security notes:

- Use strong runtime secrets (prefer `*_FILE` + Docker secrets in prod).
- Use a strong `NETWATCH_JWT_SECRET` and rotate it if leaked.
- Run behind HTTPS and set `NETWATCH_COOKIE_SECURE=true`.
- Set `NETWATCH_ENROLL_TOKEN` to prevent opportunistic agent enrollment.

---

## Performance: Rollups (Grafana/Postgres CPU reduction)

NetWatch includes an optional rollup worker that pre‑aggregates `net_events` into 1‑minute buckets.
This significantly reduces CPU usage caused by Grafana dashboards that run COUNT/GROUP BY queries over large windows.

- Worker: `netwatch-rollup-worker` (Docker Compose)
- Tables: `event_rollups_1m`, `ssh_fail_rollups_1m`
- Offsets: `search_index_offsets` (`rollup_events_1m`, `rollup_ssh_fail_1m`)

Tune via `.env`:

- `NETWATCH_ROLLUP_EVERY_SECONDS`, `NETWATCH_ROLLUP_MAX_ROWS`
