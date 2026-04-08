# Dynasmon NetWatch

Dynasmon NetWatch is a threat hunting platform designed as a lightweight, opinionated mini‑SIEM. It started as a network telemetry pipeline and is evolving toward an “XDR‑foundation” architecture inspired by Wazuh endpoint management.

At this stage, NetWatch provides an end‑to‑end pipeline:

- Multiple Go agents that capture and ship telemetry (proc/authlog + PCAP‑based collectors + endpoint syscollector)
- A FastAPI backend that ingests and persists events into PostgreSQL
- A rules engine executed by the grouped intelligence worker container
- A **NetWatch Portal** (React) with authentication and an operator‑friendly UI
- Optional search indexing into Elasticsearch (Postgres → ES) for fast hunting
- Grouped background worker services for ingest, intelligence, and maintenance domains

## Recent changes (already implemented)

These items used to be “future work” and are now part of the project:

- **NetWatch Portal (React)** with login, RBAC (admin vs. user), and a consistent “SOC console” UI.
- **Cursor (keyset) pagination** for heavy timelines:
  - Events: `GET /events`
  - Alerts (admin‑only): `GET /alerts`
  - Inventory history paging: `GET /inventory/{agent_id}/history/page`
- **Lupe SSH Insights** (`GET /events/ssh/summary`) + optional `ip-intel` worker process (inside `netwatch-intelligence-worker`) that adds Geo/ASN metadata, using my personal tool: https://github.com/dynasmon/lupe.
- **Correlation Rules / Incidents** (admin‑only): CRUD correlation rules + run correlation to produce incident‑like findings.
- **1-minute rollup worker logic** (now hosted in `netwatch-ingest-pipeline`) that pre‑aggregates data to reduce dashboard query cost.
- **Redis is now actively used** for portal rate‑limiting (best‑effort fail‑open) instead of being “reserved”.
- **Administrative audit/governance**:
  - append-only admin audit timeline (`admin_audit_events`)
  - login/auth evidence with persistence and queryability
  - audit coverage for users, allowlists, rule governance, agent admin actions, and platform settings
  - dedicated retention worker logic (now hosted in `netwatch-maintenance-worker`)

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
  - Sends batched events to the backend over HTTPS with rotating agent credentials (bound to agent_id).

- **netwatch-backend** (FastAPI)
  - Ingestion API (agent‑auth): `POST /ingest/events`
  - Control plane (agent‑auth): `/agents/enroll`, `/agents/heartbeat`, `/agents/config`
  - Portal APIs (user/admin): `/events`, `/inventory`, `/overview`, `/auth/*`, `/account/*`, `/admin/*`
  - Normalizes and persists to PostgreSQL.
  - Adds baseline hardening headers + GZip for JSON.

- **netwatch-portal** (React + Vite)
  - Operator UI: Overview, Agents, Events (with pagination), SSH Insights, Inventory, Alerts, Correlations, Settings.
  - Uses portal auth (`/auth/login`, `/auth/refresh`, `/auth/me`) and does not rely on localStorage roles.

- **caddy** (public reverse proxy with automatic HTTPS)
  - Terminates HTTPS for externally exposed entrypoints.
  - Routes `/` -> portal, `/api/*` -> backend, `/agent/*` -> backend.
  - Adds HSTS + security headers and forwards `X-Forwarded-*` headers to upstream services.

- **netwatch-ingest-pipeline**
  - Runs ingest queue draining, Elasticsearch indexing, and 1-minute rollups in one supervised group.
  - Child modules: `app.workers.ingest_worker`, `app.workers.es_indexer`, `app.workers.rollup_1m`.

- **netwatch-intelligence-worker**
  - Runs rule evaluation and enrichment/correlation workers in one supervised group.
  - Child modules: `app.workers.runner`, `app.workers.ip_intel`, `app.workers.proto_intel`, `app.workers.attack_chain`.

- **netwatch-maintenance-worker**
  - Runs administrative maintenance loops.
  - Child modules: `app.workers.audit_retention` and (in production when enabled) the bootstrap token rotator.

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
  - Stores indexed events for fast hunting and flexible aggregations (index pattern `netwatch-events-*`).
  - Fed asynchronously by the `es-indexer` child inside `netwatch-ingest-pipeline` (Postgres → Elasticsearch).

Worker group manager entrypoints:

- `python -m app.workers.manager ingest`
- `python -m app.workers.manager intelligence`
- `python -m app.workers.manager maintenance`

---

## Technology Stack

### Agent

- **Language:** Go
- **Telemetry:** `/proc/net/tcp*`, authlog parsing, gopacket PCAP capture
- **Security:** HTTPS edge + rotating per-agent credential hashes (no client cert operation for agents).

### Backend

- **Language:** Python
- **Framework:** FastAPI (Pydantic + OpenAPI)
- **DB:** SQLAlchemy + PostgreSQL
- **Auth (Portal):** access/refresh tokens with HttpOnly cookies + Bearer access token
- **Auth (Agents):** bootstrap token + rotating credential flow (hash-only persistence, agent_id binding).
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

- Docker
- Docker Compose (Docker CLI plugin or standalone)
- Git (to clone the repository)

### 1. Clone the repository

```bash
git clone https://gitlab.com/nathanmblima/dynasmon-netwatch.git
cd dynasmon-netwatch
```

### 2. Configure environment variables

No manual `.env` setup is required for first run. `make dev` (and `make prod`) now auto-creates `.env` from `.env.example` when missing, and auto-adds newly introduced variables on future runs while preserving existing values.

If you want to pre-customize values before first startup, create `.env` manually from the template:

```bash
cp .env.example .env
```

Create runtime secret files (recommended for prod and supported in dev):

```bash
mkdir -p secrets
openssl rand -hex 24 > secrets/postgres_password.txt
openssl rand -hex 32 > secrets/netwatch_jwt_secret.txt
openssl rand -hex 24 > secrets/netwatch_bootstrap_admin_password.txt
openssl rand -hex 24 > secrets/netwatch_redis_password.txt
openssl rand -hex 24 > secrets/netwatch_es_password.txt
openssl rand -hex 32 > secrets/netwatch_audit_hash_pepper.txt
openssl rand -hex 24 > secrets/grafana_admin_password.txt  # optional, only if observability profile is enabled
```

The backend now supports both `VAR` and `VAR_FILE` for secrets. Compose prod mounts Docker secrets under `/run/secrets/*`.

Minimum required for secure bootstrap:

- `NETWATCH_JWT_SECRET` or `NETWATCH_JWT_SECRET_FILE`
- `NETWATCH_BOOTSTRAP_ADMIN_PASSWORD` or `NETWATCH_BOOTSTRAP_ADMIN_PASSWORD_FILE`
- In dev, `NETWATCH_BOOTSTRAP_ADMIN_RESET_ON_START=true` can resync the bootstrap admin password on startup.

Recommended hardening:

- Use short-lived bootstrap tokens per agent for enrollment.
- When behind HTTPS, set `NETWATCH_COOKIE_SECURE=true` and consider `NETWATCH_COOKIE_SAMESITE=strict`.
- Configure Caddy edge domain/email for automatic HTTPS:
  - `NETWATCH_CADDY_DOMAIN`
  - `NETWATCH_CADDY_EMAIL`
- Configure audit integrity and retention:
  - `NETWATCH_AUDIT_HASH_PEPPER` / `NETWATCH_AUDIT_HASH_PEPPER_FILE`
  - `NETWATCH_AUDIT_RETENTION_DAYS`
  - `NETWATCH_LOGIN_AUDIT_RETENTION_DAYS`
  - `NETWATCH_GOVERNANCE_RETENTION_DAYS`

For local lab/dev TLS (self-signed), keep your dev certs under `secrets/tls/`:

```bash
mkdir -p secrets/tls
openssl req -x509 -nodes -newkey rsa:4096 \
  -days 365 \
  -keyout secrets/tls/tls.key \
  -out secrets/tls/tls.crt \
  -subj "/CN=localhost"
```

Then trust/import `secrets/tls/ca.crt` in your local OS/browser store if you want to remove browser warnings.

If you enable SSH enrichment (Lupe / IP Intelligence), the preferred setup is local MaxMind GeoLite2 databases mounted into `backend/data/geoip/`:

- `backend/data/geoip/GeoLite2-City.mmdb`
- `backend/data/geoip/GeoLite2-ASN.mmdb`

Optional fallback:

- `NETWATCH_IPINFO_TOKEN` (used only when the local MMDB files are missing and fallback is enabled)

### 3. Bootstrap and start (single command)

```bash
make dev
```

This command:

- Creates `.env` from `.env.example` when missing
- Mints short-lived per-agent bootstrap tokens and rewires agent containers with the fresh tokens
- Uses `docker-compose.yml + compose.dev.yml`
- Builds and starts the development stack

If you run the host agent with `systemd` (`netwatch-agent.service`) and do not want Docker to start
`netwatch-agent-core`/`netwatch-agent-sensor`, run:

```bash
make dev SYSTEMD_AGENT=1
```

Use the same flag for restarts:

```bash
make restart SYSTEMD_AGENT=1
make restart-quick SYSTEMD_AGENT=1
```

### 3.1 Native Linux `systemd` agent deployment

If you want to run the NetWatch agent natively on a Linux host (without containerized agent services), use the deployment scripts under `deploy/systemd/`.

This path is compatible with the existing Docker workflow. When the host `systemd` agent is enabled, use `SYSTEMD_AGENT=1` in the compose/make commands shown above so Docker does not start `netwatch-agent-core`/`netwatch-agent-sensor`.

#### Installed paths

| Purpose | Path |
|---|---|
| Agent binary | `/usr/local/bin/netwatch-agent` |
| Service unit | `/etc/systemd/system/netwatch-agent.service` |
| Environment config | `/etc/netwatch/agent.env` |
| CA file | `/etc/netwatch/pki/root_ca.crt` |
| CA sync helper | `/usr/local/lib/netwatch/netwatch-agent-sync-ca.sh` |
| CA sync timer | `netwatch-agent-ca-sync.timer` |
| State files | `/var/lib/netwatch` |
| Runtime logs | `journalctl -u netwatch-agent` and `/var/log/netwatch` |

#### Install

Run from repository root as `root`:

```bash
bash deploy/systemd/install-agent.sh
```

Install modes:

- Build from source (default):
  ```bash
  BUILD_FROM_SOURCE=1 bash deploy/systemd/install-agent.sh
  ```
- Install from an existing binary:
  ```bash
  BUILD_FROM_SOURCE=0 SOURCE_BINARY=/path/to/netwatch-agent bash deploy/systemd/install-agent.sh
  ```
- Install and auto-start only when runtime prerequisites are met:
  ```bash
  AUTO_START_IF_READY=1 bash deploy/systemd/install-agent.sh
  ```

Installer behavior (idempotent and hardening-oriented):

- Reuses existing user/directories, preserves existing `/etc/netwatch/agent.env`, reloads systemd, enables the service.
- Migrates legacy `NETWATCH_AGENT_BOOTSTRAP_TOKEN_FILE=/etc/netwatch/bootstrap.token` to `/var/lib/netwatch/bootstrap.token`.
- Moves inline `NETWATCH_AGENT_BOOTSTRAP_TOKEN` content to file-based token storage and clears inline value.
- Normalizes bootstrap token file ownership/permissions to `netwatch:netwatch` and `0600`.
- Clears stale `NETWATCH_AGENT_BOOTSTRAP_TOKEN_FILE` when credential-based enroll is already complete and token file was consumed.
- Removes stale systemd drop-ins that override bootstrap token env vars (unless `PRESERVE_BOOTSTRAP_DROPINS=1`).
- Deduplicates managed keys in `agent.env` and applies sane host defaults for authlog and DDoS tuning.
- If `NETWATCH_TLS_CA_FILE` is missing, can auto-seed from local dev CA (`AUTO_INSTALL_DEV_CA=1`, default).
- Auto-discovers the local CA source, writes `NETWATCH_TLS_CA_SOURCE_FILE`, and installs CA sync timer to keep trust aligned.

#### Configure

Edit `/etc/netwatch/agent.env` and set at least:

- `NETWATCH_AGENT_ID`
- `NETWATCH_API_URL`
- One bootstrap source:
  - `NETWATCH_AGENT_BOOTSTRAP_TOKEN`, or
  - `NETWATCH_AGENT_BOOTSTRAP_TOKEN_FILE`
- `NETWATCH_TLS_CA_FILE` (default: `/etc/netwatch/pki/root_ca.crt`)
- `NETWATCH_TLS_CA_SOURCE_FILE` (typically your repo `secrets/tls/ca.crt`)

Optional backend mTLS:

- `NETWATCH_TLS_CERT_FILE`
- `NETWATCH_TLS_KEY_FILE`

If one of `NETWATCH_TLS_CERT_FILE` / `NETWATCH_TLS_KEY_FILE` is set, the other must also be set.

#### Start and inspect

```bash
systemctl start netwatch-agent
systemctl status netwatch-agent --no-pager
journalctl -u netwatch-agent -f
```

#### Current limitations

- No `ExecReload` is configured in the unit.
- Bootstrap token file deletion occurs only after successful enroll/re-enroll.
- Service auto-start is intentionally conservative unless explicitly requested with `AUTO_START_IF_READY=1`.

If you prefer raw Compose commands, use the provided wrapper (it auto-creates/syncs `.env` first):

```bash
./scripts/compose.sh -f docker-compose.yml -f compose.dev.yml up -d --build
```

If you start services manually with `docker compose` (without `make dev`), run token bootstrap before (re)creating agent containers:

```bash
./scripts/mint_agent_bootstrap_tokens.sh
docker compose up -d --force-recreate netwatch-agent-proc netwatch-agent-scan netwatch-agent-ddos netwatch-agent-vuln
docker compose --profile extra up -d --force-recreate netwatch-agent-lateral
```

For production-style local runs:

```bash
make prod
```

This uses `docker-compose.yml + compose.prod.yml` with Caddy edge HTTPS + bootstrap credential flow.
On first run, `make prod` now auto-generates secure missing/placeholder secrets in `.env`, records a production state fingerprint, and resets stale runtime volumes automatically when critical secrets drift.
`make prod-fresh` performs a full clean boot, including runtime state reset under `secrets/runtime/`.

The dev stack runs through HTTPS edge; agents use header-based rotating credentials.
It serves:
- HTTP redirect: `http://localhost:${NETWATCH_EDGE_HTTP_PORT:-8081}`
- HTTPS: `https://localhost:${NETWATCH_EDGE_HTTPS_PORT:-8443}`

### 4. Start optional profiles

```bash
make up-extra
```

`make up-extra` starts the `extra` profile (for additional agent collectors such as `netwatch-agent-lateral`).

To start optional observability tooling (Grafana + Kibana), use:

```bash
make up-observability
make prod-observability
```

or with raw compose:

```bash
docker compose -f docker-compose.yml -f compose.dev.yml --profile observability up -d grafana kibana
```

### 5. Open the Portal

- Dev (default): `http://localhost:${NETWATCH_PORTAL_PORT:-8080}`
- Dev with TLS edge: `https://localhost:${NETWATCH_EDGE_HTTPS_PORT:-8443}`
- Prod compose: `https://<NETWATCH_CADDY_DOMAIN>` (for local runs, use `https://127.0.0.1:${NETWATCH_EDGE_HTTPS_PORT:-8443}`)
- Login with:
  - Username: `NETWATCH_BOOTSTRAP_ADMIN_USERNAME` (default: `admin`)
  - Password: `NETWATCH_BOOTSTRAP_ADMIN_PASSWORD`

The admin account is bootstrapped on an empty database at backend startup.
After logging in, change your password via **Settings** (or `POST /account/change-password`).
If login gets out of sync with `.env`, run `make admin-reset` (backend CLI command) to force-sync the bootstrap admin password into the database.
Important: this login troubleshooting is primarily for `prod` runs behind `caddy` (`/api/*` path).
In `dev` direct backend usage (`compose.dev.yml` / `http://localhost:8000`), host/proxy behaviors differ.

### 6. Verify the Backend

```bash
curl -k https://localhost:${NETWATCH_EDGE_HTTPS_PORT:-8443}/api/health
```

Expected:

```json
{"status":"ok"}
```

### 7. Grafana / Kibana (optional)

- Grafana: `http://localhost:${GRAFANA_PORT:-3000}`
  - Credentials: `GF_SECURITY_ADMIN_USER` + value from `GF_SECURITY_ADMIN_PASSWORD` or `GF_SECURITY_ADMIN_PASSWORD_FILE`
  - Datasources + dashboards are **auto‑provisioned** from `infra/grafana/provisioning`.

- Kibana (optional, behind TLS edge): `https://localhost:${NETWATCH_EDGE_HTTPS_PORT:-8443}/kibana/` (start with `--profile observability`)
- Elasticsearch HTTP API (if intentionally exposed via edge): `https://localhost:${NETWATCH_EDGE_HTTPS_PORT:-8443}/elasticsearch/`

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
- Rule governance migration: `20260309_0002`
- Admin audit/governance migration: `20260311_0003`
- Runtime no longer depends on `Base.metadata.create_all()` for schema evolution

Lifecycle flow:

- **Initial bootstrap (dev)**: `compose.dev.yml` sets `NETWATCH_DB_AUTO_UPGRADE=true`, so services apply `alembic upgrade head` automatically.
- **Upgrade before prod deploy**: run migrations explicitly, then start services.

Useful commands:

- `make db-upgrade` -> run `alembic upgrade head` via backend container
- `make db-current` -> show current revision

For production-like runs (`compose.prod.yml`), `NETWATCH_DB_AUTO_UPGRADE=false` by default.

### 10. Administrative Audit and Governance

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

- worker group: `netwatch-maintenance-worker` (child: `audit-retention`)
- same retention mechanism in dev/prod; only windows/volume change by config
- defaults:
  - dev: 30 days
  - prod: 365 days (compose prod defaults)

Config knobs:

- `NETWATCH_AUDIT_RETENTION_ENABLED`
- `NETWATCH_AUDIT_RETENTION_DAYS`
- `NETWATCH_LOGIN_AUDIT_RETENTION_DAYS`
- `NETWATCH_GOVERNANCE_RETENTION_DAYS`
- `NETWATCH_AUDIT_RETENTION_EVERY_SECONDS`
- `NETWATCH_AUDIT_RETENTION_DELETE_BATCH`

Troubleshooting (Postgres auth failed):

- If you see `password authentication failed for user "netwatch"` after changing `POSTGRES_PASSWORD`, your existing `postgres-data` volume still has the old password.
- Option 1 (keep data): set `.env` `POSTGRES_PASSWORD` back to the password used when that volume was first created.
- Option 2 (reset local dev DB): `docker compose down -v` and start again to reinitialize with current credentials.

### 11. Development observability

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

When enrichment is enabled (via the `ip-intel` child inside `netwatch-intelligence-worker`), SSH auth events can be enriched with:

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
   - Expanded RBAC scopes and policy-as-code governance workflows.

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
- Set `NETWATCH_AUDIT_HASH_PEPPER` (or `_FILE`) to strengthen audit-chain integrity hashes.
- Run behind HTTPS and set `NETWATCH_COOKIE_SECURE=true`.
- Keep bootstrap tokens short-lived and one-time; avoid long-lived shared enroll secrets.

### Agent Identity Lifecycle

Control-plane path for agents remains `https://<edge>/agent/*`.

1. Create a short-lived bootstrap token per agent:
   - `POST /api/agents/{agent_id}/bootstrap-tokens`
2. Start/restart the agent with:
   - `NETWATCH_AGENT_BOOTSTRAP_TOKEN` (or `_FILE`) for first enroll
   - `NETWATCH_AGENT_ID`
3. Agent enrolls with bootstrap token (`POST /agent/agents/enroll`) and receives a rotating credential.
4. Agent uses `X-Agent-ID` + `X-Agent-Credential` for `/agent/*` requests.
5. Backend stores only salted credential hashes and binds credentials to `agent_id`.
6. Rotation is supported by time and use limits; agent rotates via `POST /agent/agents/credential/rotate`.

Operational notes:

- Keep bootstrap tokens short-lived and low-use.
- Revoking/disabling an agent revokes active credentials.
- No step-ca, edge reloader, or runtime edge cert/key issuance is required for public edge.

### Detection Content Engineering

Catalog layout:

- `rules/packs/core/*`: stable detections for auth/baseline.
- `rules/packs/network/*`: stable detections for recon/lateral/impact.
- `rules/packs/lab/*`: experimental detections for dev/lab rollout.

Pack activation by environment (same loader/motor, different activation only):

- `NETWATCH_RULES_ENV`: logical environment label used by rule filters (`dev`, `homolog`, `prod`, `lab`).
- `NETWATCH_RULES_ENABLED_PACKS`: CSV allowlist of packs to load (e.g. `core,network`).
- `NETWATCH_RULES_DISABLED_PACKS`: optional CSV denylist.
- `NETWATCH_RULES_INCLUDE_EXPERIMENTAL`: enables/disables rules with `maturity: experimental`.

Recommended defaults:

- Dev/Lab: `NETWATCH_RULES_ENABLED_PACKS=core,network,lab` and `NETWATCH_RULES_INCLUDE_EXPERIMENTAL=true`.
- Prod: `NETWATCH_RULES_ENABLED_PACKS=core,network` and `NETWATCH_RULES_INCLUDE_EXPERIMENTAL=false`.

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
  - `make test-detections`

---

## Performance: Rollups (Grafana/Postgres CPU reduction)

NetWatch includes an optional rollup worker that pre‑aggregates `net_events` into 1‑minute buckets.
This significantly reduces CPU usage caused by Grafana dashboards that run COUNT/GROUP BY queries over large windows.

- Worker group: `netwatch-ingest-pipeline` (child: `rollup-1m`)
- Tables: `event_rollups_1m`, `ssh_fail_rollups_1m`
- Offsets: `search_index_offsets` (`rollup_events_1m`, `rollup_ssh_fail_1m`)

Tune via `.env`:

- `NETWATCH_ROLLUP_EVERY_SECONDS`, `NETWATCH_ROLLUP_MAX_ROWS`
