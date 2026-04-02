# NetWatch Agent systemd Deployment

This directory provides a native Linux/systemd deployment path for the NetWatch agent, without changing the existing Docker workflow.

## Installed paths

- Binary: `/usr/local/bin/netwatch-agent`
- Service unit: `/etc/systemd/system/netwatch-agent.service`
- Environment config: `/etc/netwatch/agent.env`
- CA file: `/etc/netwatch/pki/root_ca.crt`
- State files: `/var/lib/netwatch`
- Runtime logs: `journalctl -u netwatch-agent` and `/var/log/netwatch`

## Install

Run from the repository root as `root`:

```bash
bash deploy/systemd/install-agent.sh
```

Modes:

- Build from source (default):
  ```bash
  BUILD_FROM_SOURCE=1 bash deploy/systemd/install-agent.sh
  ```
- Install from an existing binary:
  ```bash
  BUILD_FROM_SOURCE=0 SOURCE_BINARY=/path/to/netwatch-agent bash deploy/systemd/install-agent.sh
  ```

The installer is idempotent: it reuses existing user/directories, preserves an existing `/etc/netwatch/agent.env`, reloads systemd, and enables the service.

Additional hardening behavior in the installer:

- Migrates legacy `NETWATCH_AGENT_BOOTSTRAP_TOKEN_FILE=/etc/netwatch/bootstrap.token` to `/var/lib/netwatch/bootstrap.token`.
- Moves inline `NETWATCH_AGENT_BOOTSTRAP_TOKEN` content into the file-based token path and clears the inline value.
- Normalizes bootstrap token file ownership/permissions to `netwatch:netwatch` and `0600`.
- Removes stale systemd drop-ins that override bootstrap token env vars (unless `PRESERVE_BOOTSTRAP_DROPINS=1`).
- If `NETWATCH_TLS_CA_FILE` is missing, it can auto-seed from local dev cert (`AUTO_INSTALL_DEV_CA=1`, default).

## Configure

Edit `/etc/netwatch/agent.env` and set at least:

- `NETWATCH_AGENT_ID`
- `NETWATCH_API_URL`
- One bootstrap source:
  - `NETWATCH_AGENT_BOOTSTRAP_TOKEN`, or
  - `NETWATCH_AGENT_BOOTSTRAP_TOKEN_FILE`
- `NETWATCH_TLS_CA_FILE` (default: `/etc/netwatch/pki/root_ca.crt`)

Optional mTLS to backend:

- `NETWATCH_TLS_CERT_FILE`
- `NETWATCH_TLS_KEY_FILE`

If `NETWATCH_TLS_CERT_FILE` is set, `NETWATCH_TLS_KEY_FILE` must also be set (and vice versa).

## Start and inspect

```bash
systemctl start netwatch-agent
systemctl status netwatch-agent --no-pager
journalctl -u netwatch-agent -f
```

## Current limitations

- No `ExecReload` is configured in the unit.
- Bootstrap token file deletion happens only after a successful enroll/re-enroll.
- The installer does not auto-start the service to avoid starting with incomplete config.
