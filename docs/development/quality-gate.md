# Backend quality gate

Every merge request runs `scripts/ci/backend-quality.sh`. The script is the gate
itself, not a description of one: GitHub Actions and GitLab both invoke it and
nothing else, so the two pipelines cannot drift apart, and a developer can run
the exact pipeline locally with the same command.

```
bash scripts/ci/backend-quality.sh
```

It runs four checks, in the order that fails cheapest first:

| Check | Command | What it protects |
|---|---|---|
| lint | `ruff check app tests` | style, unused names, bugbear rules |
| import contracts | `lint-imports` | the ten feature-tier contracts in `backend/pyproject.toml` |
| tests | `pytest tests` | the full backend suite, not a subset |
| dependency audit | `pip-audit -r requirements.lock --strict` | known advisories in pinned dependencies |

The pytest step needs no services. Tests that require a real PostgreSQL —
concurrency of session claims, of the audit chain, of the outbox lease — skip
themselves unless `SEAGULL_TEST_DB_URL` names a database, and CI does not set
it. Those races do not reproduce on SQLite, so the local skip is honest rather
than convenient: they must be run against PostgreSQL when the code under them
changes.

## Why the suite was allowed to go red

Before this gate, the merge pipeline ran `pytest backend/ -k "yaml_tests or
quality"`. Everything outside detection-rule and quality tests was invisible to
CI, and ten tests had drifted from the code without anyone being told. None of
them described a production bug, which is exactly the problem: a suite with a
stable set of known failures teaches everyone to read a red result as normal,
and the first real regression arrives disguised as more of the same noise.

The four drifts that were left, and what each one turned out to be:

- an admin route test that mocked `SessionLocal` after the route had moved to
  `Depends(routed_db(...))`. `routed_db` built a new closure per call, so the
  dependency could not be overridden by identity at all. It is memoised per
  route key now, which is what makes `app.dependency_overrides[routed_db("...")]`
  work, and the private session-resolution helper the admin module carried was
  replaced by the shared `managed_session`.
- a live-overview test asserting an event-type cap of two against a floor that
  refuses anything under four. The cap resolution moved into
  `max_event_types_per_second()`, so the test asks the code what the cap is
  instead of restating a number, and the floor has its own assertion.
- a recovery test building Redis keys through `app.features.ingest.control.recovery`
  after the builders moved to `queue_keys`. Keys come from the module that owns
  them; only collaborators are patched on the module under test.
- three UEBA tests constructing `UebaWorkerConfig` field by field — sixty of
  them — so every new field broke the suite. The fixture now starts from
  `load_worker_config()` and states only the four thresholds the tests depend
  on.

Fixing the last one surfaced a real defect. `net_events.id` became `BigInteger`
when the identifiers outgrew 32 bits, and SQLite only autoincrements
`INTEGER PRIMARY KEY`, so every SQLite-backed test that inserted an event was
failing on a NOT NULL violation. Ten primary keys across `events`,
`exposure` and `network_topology` had the same problem. They share one column
type now, `app.core.db.BigIntId`, which is `BIGINT` everywhere and `INTEGER`
on SQLite.

## Accepted advisories

`pip-audit` fails the build on any advisory that is not listed in
`backend/pip-audit-accepted.txt`. The file holds the twenty advisories that
were already open when the gate was introduced, one per line, with the package
and version they were accepted against:

```
PYSEC-2026-249       starlette 0.47.3
```

The point of the list is that it is a diff. A new vulnerable dependency fails
the pipeline the day it is added; the existing debt is enumerated instead of
being hidden behind a permanently red job or a `continue-on-error` nobody
reads. Retiring an entry means upgrading the package and deleting the line —
the audit itself will fail if a line is deleted while the advisory still
applies.

The four packages currently listed are `starlette`, `pyjwt`, `cryptography` and
`python-dotenv`. `python-dotenv` is not imported anywhere in the backend or the
CLI and should be removed rather than upgraded. `starlette` cannot be bumped on
its own because its version is bounded by FastAPI, so that upgrade is a set,
not a line.
