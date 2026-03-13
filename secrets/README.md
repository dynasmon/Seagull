# Runtime Secrets

Store local runtime secrets in this directory for Docker Compose.

Expected files for `compose.prod.yml`:

- `postgres_password.txt`
- `grafana_admin_password.txt`
- `netwatch_jwt_secret.txt`
- `netwatch_bootstrap_admin_password.txt`
- `netwatch_enroll_token.txt`
- `agent-ca/` (agent mTLS CA + CRL state)
- `agent-pki/` (per-agent client cert/key material)
- `netwatch_redis_password.txt`
- `netwatch_es_password.txt`
- `netwatch_audit_hash_pepper.txt`
- `tls/tls.crt`
- `tls/tls.key`

Each file should contain a single value (no quotes). This directory is ignored by git except this file.

For TLS cert/key details, see `secrets/tls/README.md`.
For agent mTLS identity material, see `secrets/agent-ca/README.md` and `secrets/agent-pki/README.md`.
