# Detection Rule Format v2

Schema version 2 is the preferred format for new rules. It uses canonical field names and an explicit AST-based detection block rather than the flat `match` dict used by v1.

## Minimal example

```yaml
schema_version: 2
id: ssh_threshold_example_v1
name: "SSH auth threshold example"
description: "High volume of SSH authentication events from one source."
enabled: true
status: active
maturity: stable
severity: medium
confidence: 70

logsource:
  source: ssh_auth
  event_type: ssh_auth

attack:
  tactic: credential_access
  technique_id: T1110.001
  technique: "Brute Force: Password Guessing"
  confidence: 70

detection:
  selection:
    event.type: ssh_auth
    destination.port: 22
  condition: selection

aggregation:
  type: threshold
  window: 5m
  group_by:
    - source.ip
    - destination.ip
  condition:
    operator: ">="
    value: 20
  min_events: 20

suppression:
  cooldown: 15m
  rules: []

tuning: {}

response:
  playbook: "Investigate the source IP for repeated SSH activity."
  false_positives: "Automated provisioning systems or jump hosts may produce false positives."
```

## File layout

Rules are stored as YAML files under `rules/packs/<pack-name>/<category>.yml`. A pack file defines shared metadata at the top and rules in a `rules:` list:

```yaml
schema_version: 2          # applies to the pack file format
pack: network
category: scan
pack_version: 1
maturity: stable

rules:
  - schema_version: 2      # each rule declares its own schema version
    id: ...
    ...
```

If a rule omits `schema_version`, it inherits the pack-level value. If neither is present, v1 is assumed.

## Top-level fields

| Field | Required | Notes |
|---|---|---|
| `schema_version` | no | `1` or `2`; default `1` |
| `id` | yes | Unique rule ID — use snake_case with a `_vN` suffix |
| `name` | yes | Human-readable title |
| `description` | yes | One or two sentences explaining what the rule detects |
| `enabled` | no | `true` / `false`; default `true` |
| `status` | no | `draft`, `active`, `disabled`, `deprecated` |
| `maturity` | no | `stable` or `experimental` |
| `severity` | yes | `low`, `medium`, `high`, `critical` |
| `confidence` | no | Integer 0–100 |
| `risk_score` | no | Integer 0–100 (optional override) |
| `logsource` | no | Hint for filtering/categorization |
| `attack` | no | ATT&CK mapping |
| `detection` | yes | Selection predicates and condition expression |
| `aggregation` | yes | Aggregation type, window, group-by, threshold condition |
| `suppression` | no | Cooldown and suppression rules |
| `tuning` | no | Inline allowlist and per-scope overrides |
| `response` | no | Playbook and false-positive guidance |
| `tests` | no | YAML unit test cases |
| `environments` | no | List of env names this rule applies to |
| `env_overrides` | no | Per-environment field patches |

## detection block

The `detection` block defines named selections and a boolean condition expression over them.

```yaml
detection:
  selection_main:
    event.type: ssh_auth
    destination.port: 22
  selection_failed:
    user.name|exists: true
    ssh.action|in:
      - failed_password
      - invalid_user
  condition: selection_main and selection_failed
```

### Selection predicates

Each key in a selection is `<canonical-field>` or `<canonical-field>|<operator>`.

```yaml
selection:
  source.ip: 10.0.0.1           # eq
  destination.port|neq: 80      # neq
  http.request.host|contains: malware
  process.name|startswith: cmd
  file.path|endswith: .ps1
  network.bytes|gte: 1000000
  source.ip|cidr: 10.0.0.0/8
  destination.ip|exists: true
  user.name|regex: "^root$"
  destination.port|in:
    - 22
    - 443
    - 3389
```

### Condition expressions

The condition field supports `and`, `or`, `not`, `1 of <pattern>*`, `all of <pattern>*`, `1 of them`, `all of them`.

```yaml
detection:
  selection_a:
    event.type: net_flow
  selection_b:
    destination.port: 4444
  condition: selection_a and selection_b

detection:
  selection_*:
    source.ip: 1.2.3.4
  condition: 1 of selection_*

detection:
  selection_a:
    event.type: heuristic
  filter_b:
    threat.heuristic.name: expected_scan
  condition: selection_a and not filter_b
```

## aggregation block

The aggregation block determines how matching events are counted and when an alert is produced.

### type: threshold

Count events matching the detection block over the window, grouped by `group_by`. Fire when count meets the condition.

```yaml
aggregation:
  type: threshold
  window: 5m
  group_by:
    - source.ip
    - destination.ip
  condition:
    operator: ">="
    value: 20
  min_events: 20
```

### type: cardinality

Count distinct values of `field` over the window, grouped by `group_by`. Fire when distinct count meets the condition.

```yaml
aggregation:
  type: cardinality
  window: 10m
  group_by:
    - source.ip
    - destination.ip
  field: destination.port
  condition:
    operator: ">="
    value: 15
  min_events: 30
```

### type: multi_cardinality

Assert multiple distinct-count conditions simultaneously. All must pass.

```yaml
aggregation:
  type: multi_cardinality
  window: 10m
  group_by:
    - source.ip
  min_events: 20
  distinct_conditions:
    - field: destination.ip
      operator: ">="
      value: 5
    - field: destination.port
      operator: ">="
      value: 2
```

### Window and cooldown

Windows and cooldowns use a duration string: `30s`, `5m`, `2h`. Cooldown is set in `suppression.cooldown`.

## suppression block

```yaml
suppression:
  cooldown: 15m
  rules:
    - condition:
        source.ip: 10.10.0.0/8
      schedule: null
    - schedule:
        start: "2025-01-01T00:00:00Z"
        end: "2025-01-02T00:00:00Z"
      condition: null
```

## tuning block

Inline allowlisting and per-scope min_events / condition / severity overrides.

```yaml
tuning:
  allowlist:
    src_cidrs:
      - 10.0.0.0/8
    src_ips:
      - 192.168.1.50
  scopes: []
```

## response block

```yaml
response:
  playbook: "Block the source IP at the edge, review affected systems."
  false_positives: "Expected during planned vulnerability scans."
```

## tests block

YAML unit tests run with `pytest` or the backtest API. See [backtesting.md](backtesting.md).

```yaml
tests:
  - name: "triggers on threshold breach"
    events:
      - event.type: ssh_auth
        destination.port: 22
        source.ip: 1.2.3.4
        destination.ip: 10.0.0.1
    expect_alert: true
```

## env_overrides

Override specific fields for a given deployment environment.

```yaml
env_overrides:
  prod:
    aggregation:
      condition:
        value: 50
  dev:
    enabled: false
```

The `default` (or `*`) key applies to all environments before env-specific patches.

## Rule IDs

- Use snake_case.
- End with `_vN` where N is an integer that increments when the detection logic changes incompatibly.
- Example: `ssh_bruteforce_authlog_v2`, `port_scan_cardinality_v1`.

Breaking changes (changed field, changed aggregation type, changed condition threshold): bump the version suffix and keep the old rule disabled rather than deleting it, until it has been archived.

## How v1 and v2 coexist

Both schema versions are loaded and executed in the same cycle. `schema_version` in the rule dict determines which execution path (`engine.py` for v1, `compiler.py` for v2) handles the rule. The governance overlay (`AlertRuleOverrideModel`) works identically for both.

To migrate a v1 rule to v2:

1. Translate `type` to the equivalent `aggregation.type` (`aggregate_count` → `threshold`, `distinct_count` → `cardinality`, `multi_distinct` → `multi_cardinality`).
2. Translate `match` fields to canonical names in a `detection.selection` block.
3. Move `group_by` into `aggregation.group_by` using canonical names.
4. Move `distinct_field` into `aggregation.field`.
5. Set `schema_version: 2`.
6. Keep the old v1 rule disabled in the same pack file until the v2 version is validated in production.
