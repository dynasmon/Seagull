# Runtime Secrets

Store local runtime secrets in this directory for Docker Compose. The directory is
ignored by git except this file; never commit private keys.

## Layout

- `bootstrap/` — short-lived per-agent bootstrap tokens generated at deploy time
- `runtime/` — state markers and runtime helper metadata
- `tls/` and `dev-tls/` — server cert/key for the browser portal (Caddy HTTPS edge)
- `pki/` — internal PKI for agent mTLS, auto-generated and refreshed by `./seagull up`
  - `agent-ca.crt` / `agent-ca.key` — CA that signs agent **client** certificates;
    `agent-ca.crt` is mounted into Caddy as the mTLS `trust_pool`; `agent-ca.key`
    never leaves the server host and is never committed
  - `agents/<agent-id>.crt` / `.key` — per-agent clientAuth certificate (CN = agent id)
  - `server-ca.crt` / `server-ca.key` — CA that signs the mTLS **server** certificate;
    agents trust `server-ca.crt` to verify the 8444 listener
  - `server/mtls.crt` / `mtls.key` — the 8444 listener's serverAuth certificate, with
    SAN taken from `SEAGULL_AGENT_MTLS_SERVER_NAMES`. The key is `0644` inside the
    `0700` `server/` directory: the host directory gates access, while the bind mount
    still lets the capability-dropped Caddy container (no `DAC_OVERRIDE`) read it.

## Trust model (two CAs, EKU-separated)

| Direction | Verifier | Trust anchor | Presented certificate |
|---|---|---|---|
| Agent verifies the server | agent (`SEAGULL_TLS_CA_FILE`) | `server-ca.crt` | `server/mtls.crt` (serverAuth) |
| Server verifies the agent | Caddy `trust_pool` | `agent-ca.crt` | `agents/<id>.crt` (clientAuth) |

Separate CAs keep the server and client trust domains independent; the EKUs
(serverAuth vs clientAuth) prevent either certificate from being accepted in the
other role. The same internal-CA mechanism runs in dev and prod — only the SAN /
hostname values differ.

## Channel and identity

- Agents reach the backend **only** through the dedicated mTLS listener
  (`SEAGULL_AGENT_MTLS_PORT`, default 8444) with `client_auth require_and_verify`.
  The portal/API listener (8443 dev, 443 prod) does **not** route `/agent/*`, so the
  agent API is unreachable without a valid client certificate.
- Caddy passes the verified client subject to the backend as `X-Agent-Cert-CN`. The
  backend binds it to the authenticated agent id
  (`SEAGULL_AGENT_MTLS_IDENTITY_BINDING`, default `enforce`): a request whose
  certificate CN does not match its `X-Agent-ID` is rejected with 403. Use `warn` to
  meter mismatches without blocking, or `off` to disable the check.

## Production deployment (agents on separate hosts)

1. On the server host, before `./seagull up`:
   - `SEAGULL_AGENT_MTLS_SERVER_NAMES=agents.example.com` (becomes the server cert SAN)
   - `SEAGULL_CADDY_DOMAIN=...` and `SEAGULL_CADDY_EMAIL=...` for the portal (ACME)
2. In each agent host's environment:
   - `SEAGULL_API_URL=https://agents.example.com:8444/agent`
   - `SEAGULL_TLS_SERVER_NAME=agents.example.com` (must match the URL host and a cert SAN)
3. Deliver to each agent host (the only PKI files an agent host needs — CA **keys**
   never leave the server host):
   - `secrets/pki/server-ca.crt`
   - `secrets/pki/agents/<agent-id>.crt` and `.key`
   then run `sudo ./deploy/systemd/install-agent.sh`.

Always address the listener by hostname, never a bare IP: TLS sends no SNI for IP
literals, and Caddy's strict SNI-Host check (enabled under client auth) returns 421
when the request Host does not match the SNI. The hostname must resolve (DNS) and be
present in the server cert SAN.

## Certificate rotation

`./seagull up` (preflight/prepare) reissues any agent or server certificate within
`SEAGULL_*_CERT_RENEW_BEFORE_DAYS` of expiry. The Go agent transport hot-reloads
cert/key/CA by stat, so a refreshed file is picked up without a restart.

- **Co-located / provisioning host:** schedule `./seagull up` (or re-run
  `install-agent.sh`) to refresh certificates before expiry.
- **Distributed hosts:** the agent host holds no CA key and cannot self-issue. The
  recommended zero-touch design is CSR-based enrollment (the agent generates its own
  keypair, sends a CSR over the existing mTLS + credential channel, the server CA
  signs and returns the certificate) — this is the planned enhancement. Until then,
  rotate by re-issuing on the server host, re-delivering the agent cert/key, and
  re-running `install-agent.sh`. Monitor expiry via the agent's certificate file.

## Disabling mTLS (not the supported path)

mTLS is the default and recommended configuration. To disable it, set
`SEAGULL_MTLS_ENABLED=false`, `SEAGULL_AGENT_MTLS_CLIENT_AUTH=request` (the 8444
listener still starts but no longer requires a client certificate), point
`SEAGULL_AGENT_MTLS_SERVER_CERT_FILE`/`SEAGULL_AGENT_MTLS_SERVER_KEY_FILE` at an
existing cert/key so the listener can load, and blank `SEAGULL_TLS_CERT_FILE`/
`SEAGULL_TLS_KEY_FILE` in the agent env. Agents always use the 8444 listener; the
portal never exposes `/agent/*`.

Each single-value file should contain one value (no quotes).
