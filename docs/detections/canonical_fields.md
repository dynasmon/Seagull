# Canonical Fields

Seagull v2 rules and the Sigma importer use canonical field names. The canonical field map is the single source of truth for which telemetry fields are available in the detection engine.

Source: `backend/app/features/detections/domain/canonical_fields.py`

## Field reference

| Canonical name | DB column / attribute | Notes |
|---|---|---|
| `agent.id` | `agent_id` | UUID of the reporting agent |
| `event.type` | `event_type` | Telemetry event type (see below) |
| `event.timestamp` | `timestamp` | UTC timestamp of the event |
| `source.ip` | `src_ip` | Source IP address |
| `source.port` | `src_port` | Source TCP/UDP port |
| `destination.ip` | `dst_ip` | Destination IP address |
| `destination.port` | `dst_port` | Destination TCP/UDP port |
| `network.transport` | `proto` | Transport protocol (tcp, udp, etc.) |
| `network.bytes` | `bytes` | Total bytes transferred |
| `network.protocol` | `app_proto` | Application-layer protocol (e.g. http, tls, ssh) |
| `network.protocol.reason` | `app_proto_reason` | Protocol classification reason |
| `network.protocol.confidence_band` | `app_proto_conf_band` | Protocol confidence band |
| `dns.question.name` | `dns_qname` | DNS query name |
| `http.request.host` | `http_host` | HTTP Host header value |
| `http.request.method` | `http_method` | HTTP method |
| `tls.server_name` | `tls_sni` | TLS SNI (Server Name Indication) |
| `tls.alpn.first` | `tls_alpn_first` | First ALPN protocol |
| `tls.ja3` | `ja3` | JA3 TLS fingerprint |
| `tls.ja4` | `ja4` | JA4 TLS fingerprint |
| `tls.ja4.ptype` | `ja4_ptype` | JA4 protocol type |
| `ssh.action` | `ssh_action` | SSH event action (e.g. accepted, failed_password) |
| `user.name` | `ssh_username` | Username in SSH auth events |
| `process.pid` | `proc_pid` | Process ID |
| `process.parent.pid` | `proc_ppid` | Parent process ID |
| `process.name` | `proc_name` | Process name |
| `process.executable` | `proc_exe` | Full executable path |
| `process.parent.name` | `proc_parent_name` | Parent process name |
| `file.path` | `fim_path` | File path (file integrity monitoring) |
| `file.category` | `fim_category` | File category |
| `threat.heuristic.name` | `heuristic_name` | Heuristic signal name |
| `threat.heuristic.confidence` | `heuristic_confidence` | Heuristic confidence score |

## Common event types

| Event type | Source | Description |
|---|---|---|
| `net_flow` | proc / PCAP | Network connection flow |
| `ssh_auth` | authlog | SSH authentication attempt |
| `scan_probe` | PCAP scan | Port scan probe |
| `lateral_conn` | PCAP lateral | Lateral movement connection |
| `ddos_pkt` | PCAP ddos | DoS/DDoS packet burst |
| `heuristic` | heuristics engine | Heuristic threat signal |

## Using fields in v2 detection blocks

Use canonical names in `detection.selection` predicates:

```yaml
detection:
  selection:
    source.ip: 10.0.0.1         # equality
    destination.port: 22        # equality
    event.type: ssh_auth        # equality
    source.port|gte: 1024       # operator suffix
    network.protocol|in:        # list
      - ssh
      - sftp
    destination.ip|cidr: 10.0.0.0/8   # CIDR
  condition: selection
```

Supported operator suffixes: `eq`, `neq`, `contains`, `startswith`, `endswith`, `gt`, `gte`, `lt`, `lte`, `exists`, `regex`, `cidr`, `in`.

## Using fields in v1 match blocks

v1 rules use runtime field names (the DB column names). Field names without a suffix are treated as equality matches.

```yaml
match:
  event_type: ssh_auth
  dst_port: 22
  src_ip_cidr: 192.168.0.0/16
```

Supported operator suffixes for v1: `_gte`, `_lte`, `_gt`, `_lt`, `_neq`, `_in`, `_cidr`, `_contains`, `_startswith`, `_endswith`.

## Adding a new field

1. Add the field to `NetEventModel` in `backend/app/features/events/models.py` (Alembic migration required).
2. Add a `CanonicalFieldSpec` entry to `CANONICAL_FIELD_MAP` in `canonical_fields.py`.
3. Add the runtime field to `SUPPORTED_RUNTIME_EVENT_FIELDS` in `features/detections/rules/registry.py`.
4. Update this document.

Fields that are not in `CANONICAL_FIELD_MAP` cannot be used in v2 rules or Sigma imports. The engine rejects unknown fields at validation time.
