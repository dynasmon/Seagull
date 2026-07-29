# Local edge configuration

`*.caddy` files placed here are imported by `infra/caddy/Caddyfile` and mounted
read-only at `/etc/caddy/conf.d` in the edge container. The contents are
untracked, so host-specific sites survive `git pull`.

Point `SEAGULL_CADDY_LOCAL_CONFIG_DIR` at another directory to keep the files
outside the repository. Apply changes with `./seagull restart`.
