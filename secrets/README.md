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
    never leaves the server host and is never committed. It is mounted read-only
    into the backend container, which acts as the issuing service for CSR-based
    enrollment and renewal; the key is `0640` inside the `0700` `pki/` directory for the same
    capability-dropped-container reason as the server key below.
  - `server-ca.crt` / `server-ca.key` — CA that signs the mTLS **server** certificate;
    agents trust `server-ca.crt` to verify the 8444 listener
  - `server/mtls.crt` / `mtls.key` — the 8444 listener's serverAuth certificate, with
    SAN taken from the public agent host and `SEAGULL_AGENT_MTLS_SERVER_NAMES`.
    The key is `0640` inside the
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
   - `SEAGULL_AGENT_PUBLIC_HOST=agents.example.com`
   - `SEAGULL_AGENT_MTLS_SERVER_NAMES=agents.example.com`
   - `SEAGULL_CADDY_DOMAIN=...` and `SEAGULL_CADDY_EMAIL=...` for the portal (ACME)
2. Open the Agents view, select the endpoint architecture and issue a single-use
   enrollment token.
3. Download the pinned Seagull Agent release and `server-ca.crt` using the links in
   the onboarding drawer, verify the release checksum and signature, and run the
   generated installation command.

The agent creates its private key locally and sends only a CSR. The platform never
generates, stores, or transports endpoint private keys.

The advertised hostname or IP address must be present in the server certificate
SAN. `./seagull up` verifies this in production and reissues the certificate when
the public endpoint changes.

## Certificate rotation (zero-touch, CSR-based)

Client certificates renew automatically. The agent owns its keypair and rotates it
without operator action or service restarts:

1. Every `SEAGULL_CONTROL_CERT_ROTATE_EVERY` (default `1h`) the agent inspects its
   certificate; when it is within `SEAGULL_CONTROL_CERT_ROTATE_BEFORE` (default
   `720h` = 30 days) of expiry, it generates a fresh ECDSA P-256 keypair and a CSR
   (`CN = agent id`).
2. The CSR travels over the existing authenticated channel —
   `POST /agents/certificate/renew` on the 8444 mTLS listener — so issuance is gated
   by all three factors at once: a valid current client certificate (Caddy
   `require_and_verify`), a valid rotating agent credential, and the cert↔identity
   binding (the endpoint hard-requires `X-Agent-Cert-CN == agent id`, regardless of
   the global binding mode).
3. The backend signs with `agent-ca.key` (mounted read-only into the container; the
   same issuing-service model as Vault/step-ca). The subject is server-authoritative:
   only the public key is taken from the CSR; CN/O are set from the authenticated
   identity. CSRs are rejected on bad signature (proof-of-possession), CN mismatch,
   or weak keys (`RSA < 2048`, curves other than P-256/P-384).
4. The agent atomically persists the new pair to `/var/lib/seagull/pki/client.{crt,key}`
   (tmp + rename; the pair is verified to match before the swap). The transport
   hot-reloads by stat and falls back to the last-good pair if it ever observes a
   half-written state, so rotation is hitless.

Issuance and outcomes are observable end to end: backend metric
`agent_cert_renew_total{outcome,reason}` plus an `agents.certificate.renew` audit
event; agent heartbeat metrics `tls_client_cert_serial`, `tls_client_cert_not_after`,
`tls_client_cert_seconds_remaining`, `tls_client_cert_renewals_total` and
`tls_client_cert_renew_errors_total`.

On the agent host, the trust anchor and rotating client identity live in
`/var/lib/seagull/pki` (0700, owned by the `seagull` user). The initial trust anchor
is installed from onboarding and subsequent authenticated enrollment or renewal
responses rotate it atomically. Re-running the standalone installer preserves the
existing identity and enrollment state.

Server-side material is refreshed by `./seagull up` (preflight/prepare). The 8444
server certificate reissues within `SEAGULL_SERVER_CERT_RENEW_BEFORE_DAYS` of expiry.
Set `SEAGULL_AGENT_CERT_RENEWAL=disabled` to turn the client renewal endpoint off
(the metric then reports `reason="disabled"`).

### Revocation and containment

There is no CRL/OCSP: a stolen certificate alone only reaches the TLS layer — every
API call additionally requires the live rotating credential bound to the same CN. To
evict a compromised agent, revoke/disable it in the backend (credential checks fail
immediately) — certificate possession grants nothing after that. Keep
`SEAGULL_AGENT_CERT_VALIDITY_DAYS` modest (default 365; lower is safer) since renewal
is automatic anyway.

### CA rotation (manual runbook)

Rotating `agent-ca` or `server-ca` is an operator action: generate the new CA,
temporarily trust old+new (concatenate PEMs in Caddy's `trust_pool` file for clients,
or in `server-ca.crt` on agent hosts for the server side), let agents roll their leaf
certificates onto the new CA, then drop the old PEM from the bundle.

## Disabling mTLS (not the supported path)

mTLS is the default and recommended configuration. To disable it, set
`SEAGULL_MTLS_ENABLED=false`, `SEAGULL_AGENT_MTLS_CLIENT_AUTH=request` (the 8444
listener still starts but no longer requires a client certificate), point
`SEAGULL_AGENT_MTLS_SERVER_CERT_FILE`/`SEAGULL_AGENT_MTLS_SERVER_KEY_FILE` at an
existing cert/key so the listener can load, and blank `SEAGULL_TLS_CERT_FILE`/
`SEAGULL_TLS_KEY_FILE` in the agent env. Agents always use the 8444 listener; the
portal never exposes `/agent/*`.

Each single-value file should contain one value (no quotes).
