# Runtime Secrets

Store local runtime secrets in this directory for Docker Compose.

Expected files/directories for the current production flow:

- `step-ca/ca-password.txt`
- `step-ca/provisioner-password.txt`
- `step-ca/data/` (Smallstep CA state)
- `bootstrap/` (short-lived per-agent bootstrap tokens generated at deploy time)
- `agent-ca/` (legacy local agent mTLS CA + CRL state used in dev flows)
- `agent-pki/` (legacy per-agent client cert/key material used in dev flows)
- `tls/tls.crt`
- `tls/tls.key`

Each file should contain a single value (no quotes). This directory is ignored by git except this file.

For TLS cert/key details, see `secrets/tls/README.md`.
For agent mTLS identity material, see `secrets/agent-ca/README.md` and `secrets/agent-pki/README.md`.
