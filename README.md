# Dynasmon NetWatch

Dynasmon NetWatch is a network threat hunting platform designed as a lightweight, opinionated mini-SIEM focused on network telemetry.  
It is built around a distributed agent that ships network events to a central backend, where they are stored, analyzed, and visualized.

At this stage, the project provides an end‑to‑end pipeline:

- A Go agent that generates and ships network-like events
- A FastAPI backend that ingests and persists events
- A PostgreSQL database that stores raw events
- A Grafana instance ready to be wired to PostgreSQL for dashboards

The long‑term goal is to evolve this into a real threat hunting environment with traffic capture, correlation rules, and anomaly detection.

---

## High‑Level Architecture

Dynasmon NetWatch is composed of four main services, orchestrated with Docker Compose:

- **netwatch-agent (Go)**
  - Runs close to the network (host or segment).
  - Generates or captures network events (MVP: synthetic events).
  - Sends batched events to the backend over HTTP.

- **netwatch-backend (FastAPI)**
  - Exposes an HTTP API for agents to send events (`/ingest/events`).
  - Validates and normalizes event payloads.
  - Persists events into PostgreSQL.
  - Future: pushes events into Redis Streams and runs background workers for correlation and alerting.

- **PostgreSQL**
  - Stores raw network events in the `net_events` table.
  - Acts as the source of truth for dashboards and ad‑hoc queries.

- **Grafana**
  - Connects to the PostgreSQL database.
  - Provides dashboards and visualizations for threat hunting and monitoring.

---

## Technology Stack

### Agent

- **Language:** Go
- **Current dependencies:**
  - `net/http` for communicating with the backend
  - `encoding/json` for serializing batches of events
  - `github.com/google/uuid` for flow identifiers
- **Planned enhancements:**
  - `gopacket` or libpcap for passive traffic capture
  - Optional eBPF‑based probes for low‑overhead monitoring

Go was chosen for the agent because it allows building static, single‑binary executables with good performance and low memory usage, ideal for distributed agents.

### Backend

- **Language:** Python
- **Framework:** FastAPI
  - Modern, async‑friendly web framework
  - First‑class support for Pydantic models and automatic OpenAPI documentation
- **Server:** Uvicorn
  - ASGI server used to run FastAPI in production mode
- **Data modeling:**
  - **Pydantic** for request validation and serialization
  - **SQLAlchemy** for ORM and database access
- **Planned integrations:**
  - **Redis** (as a queue via Streams) for event pipelines, correlation engines, and rule execution
  - Background workers consuming from Redis and generating alerts or derived metrics

### Storage and Visualization

- **PostgreSQL**
  - Relational database used to store normalized network events
  - Easy to query for both analytics and threat hunting patterns

- **Grafana**
  - Visualization and dashboarding layer on top of PostgreSQL
  - Ideal for building panels that show:
    - Events per time window
    - Top source and destination IPs
    - Distribution of ports, protocols, and agents

### Orchestration

- **Docker** and **Docker Compose**
  - Each service (agent, backend, PostgreSQL, Redis, Grafana) runs in its own container.
  - A single `docker-compose.yml` file defines the entire environment, making it reproducible and easy to run.

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

Replace `nathanmblima` with your actual GitLab username or group name.

### 2. Build the Docker Images

```bash
docker compose build
```

This builds:

- `netwatch-agent`
- `netwatch-backend`

The PostgreSQL, Redis, and Grafana images are pulled automatically from their official registries.

### 3. Start the Stack

```bash
docker compose up -d
```

This will start:

- `netwatch-agent`
- `netwatch-backend`
- `netwatch-postgres`
- `netwatch-redis`
- `netwatch-grafana`

You can check that everything is up with:

```bash
docker ps
```

### 4. Verify the Backend

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
[INGEST] Recebidos 1 eventos
[INGEST] Primeiro evento: {...}
```

This confirms that the agent is successfully sending events to the backend.

### 5. Verify Events in PostgreSQL

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

You should see rows corresponding to the synthetic events sent by the agent.

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

If the connection is successful, Grafana can now query the `net_events` table.

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

This allows you to quickly validate that events are flowing and explore patterns per agent and event type.

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

1. **Real Network Capture**
   - Use libpcap or gopacket in the agent to capture real traffic.
   - Reconstruct TCP sessions and higher‑level protocols (HTTP, DNS, SSH metadata).

2. **Device Fingerprinting**
   - Maintain a catalog of observed hosts (MAC/OUI, IPs, open ports, services).
   - Detect new hosts, new services, and unexpected changes in behavior.

3. **Redis‑Based Event Pipeline**
   - Push events from the backend into Redis Streams.
   - Implement worker processes to:
     - Aggregate events
     - Run correlation rules
     - Generate alerts

4. **Rule Engine**
   - A flexible rules layer inspired by Sigma/YARA‑style definitions.
   - Conditions such as:
     - Spike in connections from a single host
     - Repeated SSH attempts to many targets
     - Suspicious combinations of ports and protocols

5. **Alerting and Integrations**
   - Store alerts in a separate table.
   - Expose alert APIs to be consumed by other systems.
   - Optional webhooks, email, or chat notifications.

6. **Advanced Dashboards**
   - Top talkers and top targets
   - Heatmaps of ports and protocols
   - Time series of specific event types (flows, DNS, HTTP, alerts)

---

## Security Considerations

Even in a lab environment, NetWatch touches sensitive areas:

- Packet capture and eBPF hooks can expose network metadata.
- Logs and events may contain IPs, hostnames, and user identifiers.

Use this project responsibly:

- Prefer isolated or lab networks for traffic capture.
- Do not deploy in environments where you do not have explicit authorization.
- Treat collected data as sensitive and protect access to the database and dashboards accordingly.

Dynasmon NetWatch is intended as an educational and research‑oriented platform for learning about network monitoring, threat hunting, and security engineering.
