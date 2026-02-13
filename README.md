# Dynasmon NetWatch

Dynasmon NetWatch is a threat hunting platform designed as a lightweight, opinionated mini-SIEM. It started as a network telemetry pipeline and is evolving toward an “XDR-foundation” architecture inspired by Wazuh-style endpoint management.

In addition to network-like events, the stack now includes a Sprint 1 “endpoint control plane”:

- Agent enroll + heartbeat + config distribution
- Schema v1 (event_type + schema_version + agent metadata)
- Syscollector v0.1 (OS + packages inventory snapshots)
- Log collector v0.1 (auth.log / sshd parsing)
- Basic dashboards: Agents Online, SSH failures, Inventory changes

At this stage, the project provides an end-to-end pipeline:

- Multiple Go agents that capture and ship telemetry (proc/authlog + PCAP-based collectors + endpoint syscollector)
- A FastAPI backend that ingests and persists events
- A PostgreSQL database that stores raw events
- A rules worker that evaluates YAML detections and generates alerts
- A Grafana instance ready to query PostgreSQL for dashboards

The long-term goal is to evolve this into a real threat hunting environment with stronger capture coverage, correlation rules, and anomaly detection.

---

## High-Level Architecture

Dynasmon NetWatch is composed of multiple services, orchestrated with Docker Compose:

- **netwatch-agent-*** (Go)
  - Runs close to the network (host or segment).
  - Supports multiple telemetry sources (selected via `NETWATCH_SOURCES`), including:
    - `proc` (flows from `/proc/net/tcp*`)
    - `authlog` (SSH/auth log parsing)
    - `scan` (PCAP-based scan detection)
    - `lateral` (PCAP + proc-assisted lateral movement telemetry)
    - `ddos` (PCAP-based DoS/DDoS heuristics)
    - `syscollector` (OS + package inventory snapshots)
  - Sends batched events to the backend over HTTP.

- **netwatch-backend** (FastAPI)
  - Ingestion API: `/ingest/events`
  - Control plane APIs: `/agents/enroll`, `/agents/heartbeat`, `/agents/config` (agent-facing)
  - Inventory API: `/inventory` (agent inventory snapshots)
  - Validates and normalizes payloads; persists to PostgreSQL.

- **netwatch-rules-worker**
  - Periodically loads rule definitions from `./rules/`.
  - Evaluates detections over recent events and writes findings to the `alerts` table.

- **PostgreSQL**
  - Stores raw network events in the `net_events` table.
  - Stores detections in the `alerts` table.
  - Acts as the source of truth for dashboards and ad-hoc queries.

- **Redis**
  - Included in the stack to support event pipelines and asynchronous processing.
  - Current rules execution is DB-driven; Redis is reserved for expanding the pipeline (streams/workers) as the project grows.

- **Grafana**
  - Connects to the PostgreSQL database.
  - Provides dashboards and visualizations for threat hunting and monitoring.
  - Dashboards can be provisioned via `infra/grafana/provisioning`.

- **Elasticsearch (optional search index)**
  - Stores indexed events for fast hunting and flexible aggregations (index pattern `netwatch-events-*`).
  - Fed asynchronously by `netwatch-es-indexer` (Postgres → Elasticsearch).

- **netwatch-es-indexer**
  - Polls the `net_events` table and bulk-indexes in batches.
  - Persists its cursor in the `search_index_offsets` table.

---

## Technology Stack

### Agent

- **Language:** Go
- **Current dependencies:**
  - `net/http` for communicating with the backend
  - `encoding/json` for serializing batches of events
  - `github.com/google/uuid` for identifiers
  - `github.com/google/gopacket` for PCAP-based capture and decoding
- **Planned enhancements:**
  - Optional eBPF-based probes for low-overhead telemetry
  - Deeper protocol parsing and enrichment (DNS/HTTP metadata, TLS fingerprints, etc.)

Go was chosen for the agent because it allows building static, single-binary executables with good performance and low memory usage, ideal for distributed agents.

### Backend

- **Language:** Python
- **Framework:** FastAPI
  - Modern, async-friendly web framework
  - First-class support for Pydantic models and automatic OpenAPI documentation
- **Server:** Uvicorn
  - ASGI server used to run FastAPI in production mode
- **Data modeling:**
  - **Pydantic** for request validation and serialization
  - **SQLAlchemy** for ORM and database access
- **Detection pipeline:**
  - YAML rules in `./rules/` evaluated by a worker process
  - Alerts stored in PostgreSQL and exposed via API endpoints

### Storage and Visualization

- **PostgreSQL**
  - Relational database used to store normalized network events and alerts
  - Easy to query for both analytics and threat hunting patterns

- **Grafana**
  - Visualization and dashboarding layer on top of PostgreSQL
  - Ideal for building panels that show:
    - Events per time window
    - Top source and destination IPs
    - Distribution of ports, protocols, and agents
    - Recent alerts and detections

### Orchestration

- **Docker** and **Docker Compose**
  - Each service (agents, backend, PostgreSQL, Redis, Grafana, rules worker) runs in its own container.
  - A single `docker-compose.yml` file defines the entire environment.

---

## Getting Started

### Prerequisites

- Docker
- Docker Compose (Docker CLI plugin or standalone)
- Git (to clone the repository)

### 1. Clone the Repository

```bash
git clone https://gitlab.com/nathanmblima/dynasmon-netwatch.git
cd dynasmon-netwatch
```

### 2. Build the Docker Images

```bash
docker compose build
```

This builds:

- `netwatch-agent` (used by all `netwatch-agent-*` services)
- `netwatch-backend` (also used by `netwatch-rules-worker`)

The PostgreSQL, Redis, and Grafana images are pulled automatically from their official registries.

### 3. Start the Stack

```bash
docker compose up -d
```

This will start (by default):

- `netwatch-backend`
- `netwatch-rules-worker`
- `netwatch-es-indexer`
- `netwatch-postgres`
- `netwatch-redis`
- `netwatch-elasticsearch`
- `netwatch-grafana`
- `netwatch-agent-proc-1`
- `netwatch-agent-scan-1`
- `netwatch-agent-ddos`

Optional (profile: extra):
- `netwatch-kibana`
- `netwatch-agent-lateral`
You can check that everything is up with:

```bash
docker ps
```

### 4. Packet Capture Requirements (PCAP Agents)

The `scan`, `lateral`, and `ddos` agents use packet capture and require elevated capabilities. In Docker Compose, those services run with `network_mode: host` and `cap_add: NET_RAW, NET_ADMIN`.

If you do not want to run PCAP-based collectors, you can disable them by stopping those containers or removing them from your Compose profile.

### 5. Verify the Backend

From your host, verify that the backend health endpoint is reachable:

```bash
curl http://localhost:8000/health
```

Expected response:

```json
{"status": "ok"}
```

To see ingestion happening in real time:

```bash
docker logs netwatch-backend -f
```

You should see logs similar to:

```text
[INGEST] Received 1 events
[INGEST] First event (in memory): {...}
```

### 6. Verify Events in PostgreSQL

Enter the PostgreSQL container:

```bash
docker exec -it netwatch-postgres psql -U netwatch -d netwatch
```

Inside the `psql` shell:

```sql
SELECT id,
       agent_id,
       event_type,
       timestamp,
       src_ip,
       dst_ip,
       dst_port
FROM net_events
ORDER BY id DESC
LIMIT 10;
```

---

## DoS/DDoS (Reducing False Positives)

The `netwatch-agent-ddos` collector supports hard thresholds to avoid emitting low-signal detections.

Key environment variables:

- `NETWATCH_DDOS_MIN_PACKETS`  
  Minimum packet count in the evaluation window required to emit a detection.

- `NETWATCH_DDOS_MIN_REQUESTS`  
  Minimum L7 “request-like” count (e.g., HTTP indicators / TLS handshakes) in the evaluation window required to emit L7 detections.

- `NETWATCH_DDOS_MIN_CONFIDENCE`  
  Minimum confidence score required to emit a `dos_attack` event.

Additionally, the stack supports noise control that helps reduce “return traffic” false positives in lab environments:

- `NETWATCH_PROC_DROP_LIKELY_OUTBOUND=true`
- `NETWATCH_EPHEMERAL_PORT_MIN=49152`

These settings help drop traffic likely related to outbound connections where the local host is using ephemeral destination ports.

---

## Using Grafana with NetWatch

After the stack is running, Grafana is available at:

- URL: `http://localhost:3000`
- Default credentials:
  - User: `admin`
  - Password: `admin` (you will be prompted to change it on first login)

### Configure the PostgreSQL Data Source

1. Log into Grafana.
2. Go to **Configuration > Data sources**.
3. Click **Add data source** and choose **PostgreSQL**.
4. Use the following connection settings:

   - Host: `postgres:5432`
   - Database: `netwatch`
   - User: `netwatch`
   - Password: `netwatch123`
   - TLS/SSL: disabled (within Docker network)

5. Click **Save & test**.

If the connection is successful, Grafana can now query the `net_events` and `alerts` tables.

### First Example Panel

You can create a simple dashboard and add a panel with a query such as:

```sql
SELECT
  timestamp AS "time",
  agent_id,
  event_type
FROM net_events
ORDER BY timestamp DESC
LIMIT 500;
```

---

## Running Services Locally for Development

While Docker is the recommended way to run the full stack, you can also run individual components directly on your machine during development.

### Backend (FastAPI) Local Run

From the `backend/` directory:

```bash
python -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate
pip install -r requirements.txt

uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Make sure your local environment is configured to point to a PostgreSQL instance (or to the `netwatch-postgres` container if you bridge networking accordingly).

### Agent (Go) Local Run

From the `agent/` directory:

```bash
go run ./cmd/agent
```

By default, the agent uses:

- `NETWATCH_AGENT_ID=agent-unknown` (or the value from the environment)
- `NETWATCH_API_URL=http://localhost:8000` (or the value from the environment)

You can override these:

```bash
NETWATCH_AGENT_ID=dev-agent NETWATCH_API_URL=http://localhost:8000 go run ./cmd/agent
```

---

## Roadmap and Future Work

Dynasmon NetWatch is designed to be extended. Planned enhancements include:

1. **Expanded Network Capture Coverage**
   - Extend parsing and enrichment beyond the current telemetry (e.g., DNS metadata, HTTP method/host, TLS fingerprinting).
   - Improve attribution and directionality (client/server inference, service identification).

2. **Device Fingerprinting**
   - Maintain a catalog of observed hosts (MAC/OUI, IPs, open ports, services).
   - Detect new hosts, new services, and unexpected changes in behavior.

3. **Redis-Based Event Pipeline**
   - Push events from ingestion into Redis Streams.
   - Implement worker processes to:
     - Aggregate events
     - Run correlation rules
     - Generate derived metrics

4. **Rules and Correlation Expansion**
   - Broaden the rule catalog (scan families, brute force patterns, DDoS vectors).
   - Add incident-level correlation across multiple detection families.

5. **Advanced Dashboards**
   - Top talkers and top targets
   - Heatmaps of ports and protocols
   - Time series of specific event types (flows, scans, ddos, alerts)

---

## Security Considerations

Even in a lab environment, NetWatch touches sensitive areas:

- Packet capture and low-level hooks can expose network metadata.
- Logs and events may contain IPs, hostnames, and user identifiers.
- PCAP-based agents may require elevated privileges (NET_RAW/NET_ADMIN and/or root).

Use this project responsibly:

- Prefer isolated or lab networks for traffic capture.
- Do not deploy in environments where you do not have explicit authorization.
- Treat collected data as sensitive and protect access to the database and dashboards accordingly.

Dynasmon NetWatch is intended as an educational and research-oriented platform for learning about network monitoring, threat hunting, and security engineering.

### Performance: Rollups (Grafana/Postgres CPU reduction)

NetWatch includes an optional rollup worker that pre-aggregates net_events into 1-minute buckets.
This significantly reduces CPU usage caused by Grafana dashboards that run COUNT/GROUP BY queries over large windows.

- Worker: `netwatch-rollup-worker` (Docker Compose)
- Tables: `event_rollups_1m`, `ssh_fail_rollups_1m`
- Offsets: `search_index_offsets` (`rollup_events_1m`, `rollup_ssh_fail_1m`)

You can tune it via `.env`:
- `NETWATCH_ROLLUP_EVERY_SECONDS`, `NETWATCH_ROLLUP_MAX_ROWS`

