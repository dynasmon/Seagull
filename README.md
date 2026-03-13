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
- **Administrative audit/governance**:
  - append-only admin audit timeline (`admin_audit_events`)
  - login/auth evidence with persistence and queryability
  - audit coverage for users, allowlists, rule governance, agent admin actions, and platform settings
  - dedicated retention worker (`netwatch-audit-retention`)

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
  - Sends batched events to the backend over HTTPS + mTLS workload identity.

- **netwatch-backend** (FastAPI)
  - Ingestion API (agent‑auth): `POST /ingest/events`
  - Control plane (agent‑auth): `/agents/enroll`, `/agents/heartbeat`, `/agents/config`
  - Portal APIs (user/admin): `/events`, `/inventory`, `/overview`, `/auth/*`, `/account/*`, `/admin/*`
  - Normalizes and persists to PostgreSQL.
  - Adds baseline hardening headers + GZip for JSON.

- **netwatch-portal** (React + Vite)
  - Operator UI: Overview, Agents, Events (with pagination), SSH Insights, Inventory, Alerts, Correlations, Settings.
  - Uses portal auth (`/auth/login`, `/auth/refresh`, `/auth/me`) and does not rely on localStorage roles.

- **netwatch-edge** (Nginx TLS reverse proxy)
  - Terminates HTTPS for externally exposed entrypoints.
  - Routes `/` -> portal, `/api/*` -> backend, `/agent/*` -> backend (mTLS required), optional `/kibana/*` and `/elasticsearch/*`.
  - Adds HSTS + security headers and forwards `X-Forwarded-*` headers to upstream services.

- **netwatch-rules-worker**
  - Periodically loads baseline YAML detections from `./rules/` (supports packs under `./rules/packs/**`).
  - Applies environment pack filters (`NETWATCH_RULES_ENABLED_PACKS`, `NETWATCH_RULES_INCLUDE_EXPERIMENTAL`) with the same engine in dev/prod.
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
  - `netwatch-audit-retention`: enforces retention for administrative evidence tables.

---

## Technology Stack

### Agent

- **Language:** Go
- **Telemetry:** `/proc/net/tcp*`, authlog parsing, gopacket PCAP capture
- **Security:** mTLS (unique client cert per agent, platform CA, cert-to-agent binding)

### Backend

- **Language:** Python
- **Framework:** FastAPI (Pydantic + OpenAPI)
- **DB:** SQLAlchemy + PostgreSQL
- **Auth (Portal):** access/refresh tokens with HttpOnly cookies + Bearer access token
- **Auth (Agents):** mTLS identity (strict by default) with bootstrap-token enroll/rotation flow
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

No manual `.env` setup is required for first run. `make dev` (and `make prod`) now auto-creates `.env` from `.env.example` when missing, and auto-adds newly introduced variables on future runs while preserving existing values.

If you want to pre-customize values before first startup, create `.env` manually from the template:

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
openssl rand -hex 32 > secrets/netwatch_audit_hash_pepper.txt
```

The backend now supports both `VAR` and `VAR_FILE` for secrets. Compose prod mounts Docker secrets under `/run/secrets/*`.

Minimum required for secure bootstrap:

- `NETWATCH_JWT_SECRET` or `NETWATCH_JWT_SECRET_FILE`
- `NETWATCH_BOOTSTRAP_ADMIN_PASSWORD` or `NETWATCH_BOOTSTRAP_ADMIN_PASSWORD_FILE`
- `NETWATCH_AGENT_AUTH_MODE=mtls`
- In dev, `NETWATCH_BOOTSTRAP_ADMIN_RESET_ON_START=true` can resync the bootstrap admin password on startup.

Recommended hardening:

- Set `NETWATCH_AGENT_AUTH_MODE=mtls`.
- In production, keep `NETWATCH_AGENT_ENROLL_REQUIRE_BOOTSTRAP_TOKEN=true` and use short-lived bootstrap tokens per agent.
- In local dev with auto-regenerated certs, you can use `NETWATCH_AGENT_ENROLL_REQUIRE_BOOTSTRAP_TOKEN=false` + `NETWATCH_FORCE_ENROLL_ON_START=true`.
- When behind HTTPS, set `NETWATCH_COOKIE_SECURE=true` and consider `NETWATCH_COOKIE_SAMESITE=strict`.
- Configure TLS cert/key for the edge proxy:
  - `NETWATCH_TLS_CERT_FILE=./secrets/tls/tls.crt`
  - `NETWATCH_TLS_KEY_FILE=./secrets/tls/tls.key`
- Configure trusted edge CA for agents:
  - `NETWATCH_AGENT_SERVER_CA_FILE=./secrets/tls/ca.crt`
- Configure agent mTLS CA + CRL for the edge proxy:
  - `NETWATCH_AGENT_CA_CERT_FILE=./secrets/agent-ca/ca.crt`
  - `NETWATCH_AGENT_CA_CRL_FILE=./secrets/agent-ca/ca.crl`
- Configure audit integrity and retention:
  - `NETWATCH_AUDIT_HASH_PEPPER` / `NETWATCH_AUDIT_HASH_PEPPER_FILE`
  - `NETWATCH_AUDIT_RETENTION_DAYS`
  - `NETWATCH_LOGIN_AUDIT_RETENTION_DAYS`
  - `NETWATCH_GOVERNANCE_RETENTION_DAYS`

For local lab/dev TLS (self-signed):

```bash
mkdir -p secrets/tls
openssl req -x509 -nodes -newkey rsa:4096 \
  -days 365 \
  -keyout secrets/tls/tls.key \
  -out secrets/tls/tls.crt \
  -subj "/CN=localhost"
```

Then trust/import `secrets/tls/ca.crt` in your local OS/browser store if you want to remove browser warnings.

Initialize agent PKI (platform CA + initial CRL):

```bash
scripts/pki/init_agent_ca.sh
```

Issue one client certificate per agent:

```bash
scripts/pki/issue_agent_cert.sh agent-proc-1
scripts/pki/issue_agent_cert.sh agent-scan-1
scripts/pki/issue_agent_cert.sh agent-ddos-1
scripts/pki/issue_agent_cert.sh agent-lateral-1
scripts/pki/issue_agent_cert.sh agent-vuln-1
```

Configure cert/key paths in `.env` (`AGENT_*_CERT_FILE`, `AGENT_*_KEY_FILE`).

If you enable SSH enrichment (Lupe), set:

- `NETWATCH_IPINFO_TOKEN` (IPInfo token)

### 3. Bootstrap and start (single command)

```bash
make dev
```

This command:

- Creates `.env` from `.env.example` when missing
- Regenerates local edge TLS cert + agent CA/CRL + per-agent mTLS certs
- Uses `docker-compose.yml + compose.dev.yml`
- Builds and starts the development stack

If you prefer raw Compose commands, use the provided wrapper (it auto-creates/syncs `.env` first):

```bash
./scripts/compose.sh -f docker-compose.yml -f compose.dev.yml up -d --build
```

For production-style local runs:

```bash
make prod
```

This uses `docker-compose.yml + compose.prod.yml` with Docker secrets mounts (`/run/secrets/*`).
Startup fails fast in prod if required secrets are missing/weak.
Production now expects TLS cert/key files for `netwatch-edge` (defaults: `secrets/tls/tls.crt` + `secrets/tls/tls.key`).
It also regenerates local certificates before startup (same as dev).

The dev stack also runs through HTTPS edge + mTLS agent route.
It serves:
- HTTP redirect: `http://localhost:${NETWATCH_EDGE_HTTP_PORT:-8081}`
- HTTPS: `https://localhost:${NETWATCH_EDGE_HTTPS_PORT:-8443}`

To disable automatic certificate regeneration for a run:

```bash
NETWATCH_AUTO_GENERATE_CERTS=false make dev
```

### 4. Start optional profile (`extra`)

```bash
make up-extra
```

By default, this starts:

- `netwatch-backend`
- `netwatch-portal`
- `netwatch-rules-worker`
- `netwatch-audit-retention`
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

- Dev (default): `http://localhost:${NETWATCH_PORTAL_PORT:-8080}`
- Dev with TLS edge: `https://localhost:${NETWATCH_EDGE_HTTPS_PORT:-8443}`
- Prod compose: `https://localhost:${NETWATCH_EDGE_HTTPS_PORT:-443}`
- Login with:
  - Username: `NETWATCH_BOOTSTRAP_ADMIN_USERNAME` (default: `admin`)
  - Password: `NETWATCH_BOOTSTRAP_ADMIN_PASSWORD`

The admin account is bootstrapped on an empty database at backend startup.
After logging in, change your password via **Settings** (or `POST /account/change-password`).

### 6. Verify the Backend

```bash
curl -k https://localhost:${NETWATCH_EDGE_HTTPS_PORT:-8443}/api/health
```

Expected:

```json
{"status":"ok"}
```

### 7. Grafana / Kibana

- Grafana: `http://localhost:${GRAFANA_PORT:-3000}`
  - Credentials: `GF_SECURITY_ADMIN_USER` + value from `GF_SECURITY_ADMIN_PASSWORD` or `GF_SECURITY_ADMIN_PASSWORD_FILE`
  - Datasources + dashboards are **auto‑provisioned** from `infra/grafana/provisioning`.

- Kibana (optional, behind TLS edge): `https://localhost:${NETWATCH_EDGE_HTTPS_PORT:-8443}/kibana/` (start with `--profile extra`)
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

- worker: `netwatch-audit-retention`
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

### Agent Identity Lifecycle (mTLS)

Control-plane path for agents is `https://<edge>/agent/*` and requires a valid client certificate chained to the platform CA.

1. Provision platform CA and CRL:
   - `scripts/pki/init_agent_ca.sh`
2. Issue a unique cert/key per agent (`CN=<agent_id>`):
   - `scripts/pki/issue_agent_cert.sh <agent_id>`
3. Create a short-lived bootstrap token (admin API):
   - `POST /api/agents/{agent_id}/bootstrap-tokens`
   - Example:
     ```bash
     curl -sS -X POST "https://localhost:${NETWATCH_EDGE_HTTPS_PORT:-8443}/api/agents/agent-proc-1/bootstrap-tokens" \
       -H "Authorization: Bearer <portal-access-token>" \
       -H "Content-Type: application/json" \
       -d '{"ttl_seconds":900,"max_uses":1}'
     ```
4. Start/restart the agent with:
   - `NETWATCH_TLS_CA_FILE`, `NETWATCH_TLS_CERT_FILE`, `NETWATCH_TLS_KEY_FILE`, `NETWATCH_TLS_SERVER_NAME`
   - `NETWATCH_AGENT_BOOTSTRAP_TOKEN` (one-time)
5. Agent enroll binds the presented certificate fingerprint to `agent_id`.

Rotation:

1. Issue new cert/key for the same `agent_id`.
2. Mint new bootstrap token.
3. Restart agent with new cert/key + bootstrap token.
4. Verify in `GET /api/agents/{agent_id}/identities`.
5. Revoke old identity in backend (`POST /api/agents/{agent_id}/identities/{identity_id}/revoke`) and in CA CRL (`scripts/pki/revoke_agent_cert.sh`).

Revocation:

- Backend revocation is immediate (deny by fingerprint record).
- Edge revocation uses CRL (`ca.crl`) to fail TLS handshake early.
- After updating CRL, reload edge: `docker compose ... restart netwatch-edge`.

Migration from legacy bearer:

- Use `NETWATCH_AGENT_AUTH_MODE=mixed` only during transition windows.
- Enroll all agents with mTLS identity and verify bindings.
- Switch to `NETWATCH_AGENT_AUTH_MODE=mtls` and remove legacy agent bearer tokens.

Troubleshooting:

- TLS handshake fails at edge: verify `ca.crt`, `ca.crl`, and agent cert chain.
- Backend returns `Unbound or revoked agent certificate`: ensure enroll was executed with a valid bootstrap token for that `agent_id`.
- Backend returns `Certificate agent_id mismatch`: certificate `CN` must equal `NETWATCH_AGENT_ID`.
- Enrollment denied with `Bootstrap token already consumed`: mint a new token and retry.

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

- Worker: `netwatch-rollup-worker` (Docker Compose)
- Tables: `event_rollups_1m`, `ssh_fail_rollups_1m`
- Offsets: `search_index_offsets` (`rollup_events_1m`, `rollup_ssh_fail_1m`)

Tune via `.env`:

- `NETWATCH_ROLLUP_EVERY_SECONDS`, `NETWATCH_ROLLUP_MAX_ROWS`
