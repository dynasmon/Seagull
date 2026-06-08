# Detection Validation Architecture

Backtesting lets you simulate a detection rule against historical event data before enabling it in production.

Validation is part of the detections feature, not a separate worker. The same
rule loading, compatibility, canonical-field mapping, detection, aggregation,
and evidence-building code paths are used by rule execution and by backtesting.
`dry_run` controls whether matched results are returned as a simulation or
persisted as alert records.

## Backtest via API

The detections API exposes a backtest endpoint (admin-only):

```
POST /api/detections/rules/{rule_id}/backtest
```

Request body:

```json
{
  "started_at": "2025-01-01T00:00:00Z",
  "ended_at":   "2025-01-02T00:00:00Z",
  "limit": 10000,
  "dry_run": true,
  "sample_limit": 5
}
```

Response:

```json
{
  "dry_run": true,
  "rule_id": "ssh_bruteforce_authlog_v2",
  "source_file": "rules/packs/core/auth.yml",
  "started_at": "2025-01-01T00:00:00Z",
  "ended_at":   "2025-01-02T00:00:00Z",
  "scanned_events": 8231,
  "event_limit": 10000,
  "truncated": false,
  "match_count": 3,
  "matched_entities": [
    {"src_ip": "1.2.3.4", "dst_ip": "10.0.0.1", "hit_count": 2},
    {"src_ip": "5.6.7.8", "dst_ip": "10.0.0.1", "hit_count": 1}
  ],
  "severity_distribution": {"high": 3},
  "sample_evidence": [...]
}
```

`dry_run: true` runs the simulation without creating any alert records.

## Backtest via Python

```python
from datetime import datetime
from app.core.db import SessionLocal
from app.features.detections.testing.backtest import run_detection_backtest

db = SessionLocal()
try:
    result = run_detection_backtest(
        db,
        rule_id="ssh_bruteforce_authlog_v2",
        started_at=datetime(2025, 1, 1),
        ended_at=datetime(2025, 1, 2),
        limit=10000,
        dry_run=True,
        sample_limit=5,
    )
finally:
    db.close()

print(result)
```

## In-memory backtest (no DB required)

Use `backtest_detection_rule()` when you have events in memory (e.g. in a unit test):

```python
from app.features.detections.testing.backtest import backtest_detection_rule

rule = {
    "id": "my_rule_v1",
    "schema_version": 2,
    "detection": {
        "selection": {"event.type": "ssh_auth", "destination.port": 22},
        "condition": "selection",
    },
    "aggregation": {
        "type": "threshold",
        "window": "5m",
        "group_by": ["source.ip", "destination.ip"],
        "condition": {"operator": ">=", "value": 5},
        "min_events": 5,
    },
    "severity": "medium",
    "suppression": {"cooldown": "10m"},
}

events = [
    {"event_type": "ssh_auth", "dst_port": 22, "src_ip": "1.2.3.4", "dst_ip": "10.0.0.1", "timestamp": ...},
    ...
]

result = backtest_detection_rule(rule, events, dry_run=True)
```

## YAML unit tests

Rules can include a `tests:` block. Tests are evaluated in-memory using the rule's detection and aggregation logic.

```yaml
tests:
  - name: "fires when threshold exceeded"
    events:
      - event.type: ssh_auth
        destination.port: 22
        source.ip: 1.2.3.4
        destination.ip: 10.0.0.1
        # repeat enough times to breach threshold
    expect_alert: true

  - name: "does not fire below threshold"
    events:
      - event.type: ssh_auth
        destination.port: 22
        source.ip: 1.2.3.4
        destination.ip: 10.0.0.1
    expect_alert: false
```

Run YAML tests:

```bash
cd backend
pytest tests/detections/
```

## Rule validation

Validate all rules in a directory:

```bash
cd backend
python - <<'PY'
from app.workers.intelligence.rules.loader import load_and_validate_rules
report = load_and_validate_rules(strict=False)
for e in report.get("errors", []):
    print(e)
for r in report.get("rules", []):
    print(r["id"], r.get("maturity"), r.get("schema_version"))
PY
```

With `strict=True` the loader raises on the first validation error. This is useful in CI.

## Validate a single rule file

```bash
cd backend
python - <<'PY'
from app.features.detections.rules.loader import load_and_validate_rules
report = load_and_validate_rules(rules_dir="../rules/packs/core", strict=True)
print(report)
PY
```

## How validation fits the runtime

| Surface | Uses | Persists alerts |
|---|---|---|
| YAML loader | Parses rule files, applies compatibility handling, validates schema shape. | No |
| YAML `tests:` block | Runs rule logic against inline event fixtures in memory. | No |
| In-memory backtest | Runs one rule against caller-provided event dictionaries. | No |
| API backtest with `dry_run: true` | Runs one rule against historical database events and returns match evidence. | No |
| API backtest with `dry_run: false` | Runs one rule against historical database events through the alert creation path. | Yes |
| Rules worker | Runs enabled rules continuously on live telemetry. | Yes |

Rule metadata such as `enabled`, `status`, and `maturity` is loaded with the
rule definition. Runtime governance overlays can disable, tune, or suppress a
rule without changing the YAML file.

## Tuning after deployment

If a rule fires on known-benign traffic after deployment:

- Add an inline allowlist in `tuning.allowlist.src_cidrs` or `tuning.allowlist.src_ips`.
- Or create a `AlertRuleTuningModel` record in the portal with a context-scoped override.
- Or create a `AlertRuleSuppressionModel` record for a time-bounded suppression window.

Changes to inline YAML tuning require a rules reload (the worker picks up the new file on the next cycle).

## Safety properties

- `dry_run: true` never creates alerts.
- Truncated backtests report `truncated: true` so callers know match volume may
  be incomplete.
- YAML tests run in memory and are safe for CI.
- `dry_run: false` uses the live alert persistence path and should be treated as
  a data-changing operation.
