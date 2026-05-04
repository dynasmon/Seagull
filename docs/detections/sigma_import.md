# Sigma Import

Seagull supports a narrow, review-first Sigma import path. The importer is intentionally incomplete.

Its job is to convert a curated subset of Sigma YAML into Seagull Detection Rule Format v2 while surfacing every unsupported field, modifier, or structural feature as an explicit warning. It does not claim full Sigma compatibility.

## Scope

The importer lives in:

`backend/app/features/detections/rules/sigma_import.py`

Local helper:

```bash
cd backend
python -m app.features.detections.rules.sigma_import --input /path/to/rule.yml --output /path/to/seagull_rule.yml --strict
```

`--strict` rejects any import that produces blocking warnings.

## Supported Sigma Subset

Supported top-level Sigma fields:

- `title`
- `id`
- `description`
- `status`
- `level`
- `tags`
- `references`
- `falsepositives`
- `logsource`
- `detection`

Supported `logsource` keys:

- `category`
- `product`
- `service`

Supported detection structure:

- Named selection mappings
- `condition`
- `timeframe`
- Boolean condition expressions that Seagull v2 can parse
- `and`, `or`, `not`
- `1 of pattern`
- `all of pattern`
- `1 of them` and `all of them` are rewritten to Seagull wildcard form

Supported Sigma value/modifier behavior:

- scalar equality
- list equality as `in`
- `|contains`
- `|contains|all`
- `|startswith`
- `|endswith`
- `|gt`
- `|gte`
- `|lt`
- `|lte`
- `|exists`
- `|neq`

Imported rules are always emitted as:

- `schema_version: 2`
- `enabled: false`
- `status: disabled`
- `maturity: experimental`

The importer also maps:

- Sigma `level` to Seagull `severity`
- Sigma `falsepositives` to `response.false_positives`
- ATT&CK tags such as `attack.discovery` and `attack.t1046` to Seagull `attack`

## Unsupported Sigma Features

The following are not supported by this adapter:

- full Sigma backend compatibility
- field names outside the documented mapping table
- unsupported modifiers such as `|re`, `|cidr`, `|base64`, `|utf16`, `|wide`, `|windash`, `|expand`, `|fieldref`
- Sigma keyword lists
- list-of-mapping selections
- unsupported modifier combinations
- unsupported `logsource` keys
- unsupported top-level Sigma fields
- multiple ATT&CK tactics or techniques beyond the first mapped value

Unsupported content is never silently discarded:

- the importer returns structured warnings
- warnings are embedded in `sigma_import`
- incompatible selections are converted into inert placeholder selections so the generated rule stays safe by default
- strict mode rejects the import instead of writing a lossy conversion

## Field Mapping

Only fields Seagull can evaluate are mapped.

| Sigma field or alias | Seagull canonical field |
| --- | --- |
| `source.ip`, `src_ip`, `SourceIp` | `source.ip` |
| `source.port`, `src_port`, `SourcePort` | `source.port` |
| `destination.ip`, `dst_ip`, `DestinationIp` | `destination.ip` |
| `destination.port`, `dst_port`, `DestinationPort` | `destination.port` |
| `network.transport`, `proto`, `transport` | `network.transport` |
| `network.protocol`, `app_proto` | `network.protocol` |
| `event.type`, `event_type` | `event.type` |
| `user.name`, `user`, `username` | `user.name` |
| `process.name`, `ProcessName`, `ImageName` | `process.name` |
| `process.executable`, `Image` | `process.executable` |
| `process.parent.name`, `ParentImage`, `ParentProcessName` | `process.parent.name` |
| `file.path`, `TargetFilename`, `FilePath` | `file.path` |
| `dns.question.name`, `QueryName` | `dns.question.name` |
| `http.request.host`, `HttpHost`, `RequestHost` | `http.request.host` |
| `http.request.method`, `HttpMethod` | `http.request.method` |
| `tls.server_name`, `SNI` | `tls.server_name` |
| `tls.ja3`, `JA3` | `tls.ja3` |
| `tls.ja4`, `JA4` | `tls.ja4` |
| `ssh.action`, `SshAction` | `ssh.action` |

If a Sigma rule depends on anything outside this table, the importer warns and the affected selection is blocked.

## Review Process

Imported Sigma rules are starting points, not production-ready detections.

Review checklist:

1. Read `sigma_import.warnings` and resolve every blocking warning.
2. Compare the original Sigma detection with the generated Seagull `detection` block.
3. Confirm the mapped fields exist in Seagull telemetry for the target environment.
4. Confirm the condition and timeframe still make sense under Seagull aggregation semantics.
5. Add or refine response guidance, false-positive guidance, and ATT&CK metadata as needed.
6. Keep the rule disabled until validation and backtesting are complete.

## Testing Process

Use the normal Seagull validation path after import.

Examples:

```bash
cd backend
pytest tests/test_sigma_import.py
```

```bash
cd backend
python - <<'PY'
from app.features.detections.testing import validate_detection_content
print(validate_detection_content(rules_dir="../rules"))
PY
```

Recommended validation flow for imported content:

1. Run the Sigma importer in `--strict` mode when possible.
2. Place curated output under `rules/packs/**`.
3. Run detection content validation.
4. Add YAML tests or backtests for the generated rule before enabling anything.

## Why Imported Rules Must Not Be Blindly Enabled

Sigma and Seagull do not share identical telemetry, field semantics, or execution behavior.

Blind enablement is unsafe because:

- Seagull does not implement the full Sigma modifier and backend ecosystem.
- A field alias may be syntactically mapped but still not be populated in local telemetry.
- Unsupported Sigma selections are intentionally blocked, which means the generated rule may be incomplete.
- Imported rules default to a single-event threshold aggregation and need reviewer confirmation.

Treat Sigma imports as analyst-reviewed drafts, not turnkey detections.
