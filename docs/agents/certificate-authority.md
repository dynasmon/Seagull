# Where agent certificates are signed

Agents authenticate to the platform with a client certificate, and something has
to sign those certificates. Until now that something was the API process: the
backend mounted `agent-ca.key`, loaded it unencrypted and signed CSRs inline.

The mount was read-only, which prevents an attacker from replacing the CA. It
does nothing about reading it. Any code execution inside a ninety-thousand-line
API process — a deserialization bug, a template injection, a dependency with a
bad release — hands over a key that mints a valid identity for *any* agent id,
for as long as the CA lives. That is the largest single asset in the platform
sitting in the process with the largest attack surface.

## The boundary

The key now lives in `seagull-pki`, a service whose entire job is to sign one
kind of certificate. It has no database, no cache, no message bus, no dependency
beyond `cryptography`, and it runs with a read-only root filesystem, all
capabilities dropped and no published port. It is attached to one network, and
the backend is the only other container on it.

The backend keeps the parts that need the application: who is asking, whether
renewal is enabled, and recording what was issued. It no longer has any path to
the key — the source contains no reference to `agent-ca.key`, and the compose
file mounts it into exactly one service.

| Decision | Made by |
|---|---|
| Is this request from an authenticated agent | backend |
| Is renewal enabled at all | backend |
| Is the agent id well formed | authority |
| Does the CSR common name match the agent id | authority |
| Is the CSR signature valid | authority |
| Is the key strong enough (RSA ≥ 2048, P-256/P-384) | authority |
| How long the certificate lives | authority |
| Recording the serial, fingerprint and window | backend |

The split matters in one direction in particular: the authority does not trust
its caller. It re-derives every property of the certificate it signs from the
CSR and from its own configuration, so a backend that has been taken over cannot
ask for a certificate naming an agent it does not own, or a weak key, or a
ten-year lifetime. What a compromised backend can still do is ask for a
certificate for an agent id it has authenticated — which is what it could do
before by other means.

## The interface

```
POST /certificates
Authorization: Bearer <SEAGULL_PKI_SIGNER_TOKEN>
Content-Type: application/json

{"agent_id": "agent-core-1", "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n..."}
```

A success returns the certificate plus everything the backend records about it:
`certificate_pem`, `ca_pem`, `subject`, `serial_hex`, `fingerprint_sha256`,
`public_key_sha256`, `not_before`, `not_after`. The backend stores that row
without parsing the certificate, so the write path holds no X.509 code.

`GET /health` is unauthenticated and reports whether the CA material loads and
is a CA. It is the compose healthcheck: material that has been deleted, replaced
by a leaf certificate or made unreadable turns the container unhealthy instead
of failing the first enrollment of the day.

Everything else is `404`. The body ceiling is
`SEAGULL_PKI_SIGNER_MAX_BODY_BYTES` (64 KiB), enforced against the declared
length before a byte is read; a request without `Content-Length` is refused with
`411`, so a chunked body cannot slip past the ceiling.

## How failures surface

| Situation | Authority | Agent sees |
|---|---|---|
| CSR outside policy | `422` with a reason | `422 Invalid certificate request: <detail>` |
| Wrong or missing token | `401` | `503 Certificate authority unavailable` |
| CA material missing or invalid | `503` | `503 Certificate authority unavailable` |
| Service down, unreachable, slow | no response | `503 Certificate authority unavailable` |
| Renewal disabled | not contacted | `403 Agent certificate renewal is disabled` |

A rejected token is deliberately *not* reported as a bad request. It is a
misconfiguration of the platform, not a defect in what the agent sent, and
telling an agent to fix its CSR because the operator mistyped a secret would
send everyone looking in the wrong place.

Renewal being disabled is decided before the call: `SEAGULL_AGENT_CERT_RENEWAL`
is a product switch, not a signing policy, and the authority never sees the
request.

## Configuration

| Variable | Read by | Meaning |
|---|---|---|
| `SEAGULL_PKI_SIGNER_URL` | backend | where the authority listens (`http://seagull-pki:8460`) |
| `SEAGULL_PKI_SIGNER_TOKEN` | both | shared secret, minimum 32 characters |
| `SEAGULL_PKI_SIGNER_TOKEN_FILE` | both | same value from a file, for secret managers |
| `SEAGULL_PKI_SIGNER_TIMEOUT_SECONDS` | backend | request timeout, default 10 |
| `SEAGULL_PKI_SIGNER_PORT` | authority | listen port, default 8460 |
| `SEAGULL_PKI_SIGNER_MAX_BODY_BYTES` | authority | request ceiling, default 65536 |
| `SEAGULL_AGENT_MTLS_CA_CERT_FILE` | authority | CA certificate path |
| `SEAGULL_AGENT_MTLS_CA_KEY_FILE` | authority | CA private key path |
| `SEAGULL_AGENT_CERT_VALIDITY_DAYS` | authority | issued lifetime, default 365 |

The authority refuses to start without a token of at least 32 characters. A
signing service that accepts anonymous requests because a variable was left
empty is worse than one that is down: the second is visible. `./seagull up`
generates the token into `.env` on the first run, so a fresh machine never meets
that state.

The token is a second lock, not the first one. The network is what keeps the
authority unreachable; the token is what keeps a mistake in that network from
being enough on its own.

## Rotating the CA

The CA material is mounted from `secrets/pki/`, so rotation is a file change and
`docker compose restart seagull-pki`. The authority reads the material per
request rather than caching it at startup, so a rotated CA takes effect on the
next signature and `GET /health` reports the new state immediately. The edge
loads `agent-ca.crt` as its mTLS trust pool, so it has to be restarted with the
same material — certificates already issued keep verifying only while the old CA
stays in that pool.

## What this does not solve

The key is still a file on the same host, held by a process that can read it.
Moving it behind an external CA, a Vault transit key or an HSM removes that too,
and the interface here is deliberately the shape of one: a request in, a signed
certificate out, no other coupling. Until then the honest statement is narrower
than "the CA is safe" — it is that the CA is no longer reachable from the
process most likely to be compromised.
