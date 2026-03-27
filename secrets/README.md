# Runtime Secrets

Store local runtime secrets in this directory for Docker Compose.

Expected files/directories for the current flow:

- `bootstrap/` (short-lived per-agent bootstrap tokens generated at deploy time)
- `runtime/` (state markers and runtime helper metadata)
- `tls/` (optional local TLS cert material for dev HTTPS)

Each file should contain a single value (no quotes). This directory is ignored by git except this file.
