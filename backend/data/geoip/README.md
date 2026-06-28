# GeoIP databases (MaxMind GeoLite2)

Place `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` in this directory. The backend
resolves the geolocation of event IPs **and** of the home agent locally, in
memory — sub-millisecond, no network, no quota.

Without these files the backend falls back to `ipinfo.io`, which is rate-limited
(HTTP 429 without a token) and, when it fails, leaves the threat map without a
home marker and without arcs.

The files are git-ignored (`backend/data/geoip/*.mmdb`); only this README and the
`.gitkeep` are versioned. The directory is mounted read-only into the backend
and intelligence-worker containers at `/app/data/geoip` (see `compose.yml`).

## How to obtain (MaxMind GeoLite2 — free)

1. Create a free account at https://www.maxmind.com/en/geolite2/signup
2. Generate a license key under **Account → Manage License Keys**
3. Put the key in `.env` as `MAXMIND_LICENSE_KEY=...` (or export it).

`./seagull up` downloads and validates both databases automatically before
starting the containers. The operation is idempotent: valid existing databases
are reused. To install or refresh them manually, run:

```bash
make geoip
./seagull geoip install --force
```

## Alternative (no signup) — DB-IP Lite

DB-IP Lite ships MMDB files that the MaxMind reader can read directly. Download
the City and ASN "lite" databases from https://db-ip.com/db/lite.php, decompress
them, and rename to `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` in this folder.

## Verifying

After the files are in place, recreate the backend and intelligence worker, then
confirm the provider:

```bash
docker compose up -d --build seagull-backend seagull-intelligence-worker
docker compose exec seagull-backend python -c \
  "from app.workers.intelligence.ip_intel.providers import _provider_config, _resolve_provider; print(_resolve_provider(_provider_config()))"
```

It should print `('maxmind_local', 'auto:mmdb_present')`. If it prints `ipinfo`,
the files are not being read — check the names and the `compose.yml` mount.

The intelligence worker should select the same provider:

```bash
docker compose logs seagull-intelligence-worker | grep ip_intel_provider_selected
```
