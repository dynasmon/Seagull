# Runtime Secrets

Store local runtime secrets in this directory for Docker Compose.

Expected files for `compose.prod.yml`:

- `postgres_password.txt`
- `grafana_admin_password.txt`
- `netwatch_jwt_secret.txt`
- `netwatch_bootstrap_admin_password.txt`
- `netwatch_enroll_token.txt`
- `netwatch_redis_password.txt`
- `netwatch_es_password.txt`

Each file should contain a single value (no quotes). This directory is ignored by git except this file.
