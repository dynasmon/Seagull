from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CanonicalFieldSpec:
    canonical_name: str
    model_attr: str
    storage_kind: str = "column"
    jsonb_path: tuple[str, ...] = ()


class UnsupportedCanonicalFieldError(ValueError):
    pass


CANONICAL_FIELD_MAP: dict[str, CanonicalFieldSpec] = {
    "agent.id": CanonicalFieldSpec("agent.id", "agent_id"),
    "event.type": CanonicalFieldSpec("event.type", "event_type"),
    "event.timestamp": CanonicalFieldSpec("event.timestamp", "timestamp"),
    "source.ip": CanonicalFieldSpec("source.ip", "src_ip"),
    "source.port": CanonicalFieldSpec("source.port", "src_port"),
    "destination.ip": CanonicalFieldSpec("destination.ip", "dst_ip"),
    "destination.port": CanonicalFieldSpec("destination.port", "dst_port"),
    "network.transport": CanonicalFieldSpec("network.transport", "proto"),
    "network.bytes": CanonicalFieldSpec("network.bytes", "bytes"),
    "network.protocol": CanonicalFieldSpec("network.protocol", "app_proto"),
    "network.protocol.reason": CanonicalFieldSpec("network.protocol.reason", "app_proto_reason"),
    "network.protocol.confidence_band": CanonicalFieldSpec(
        "network.protocol.confidence_band",
        "app_proto_conf_band",
    ),
    "dns.question.name": CanonicalFieldSpec("dns.question.name", "dns_qname"),
    "http.request.host": CanonicalFieldSpec("http.request.host", "http_host"),
    "http.request.method": CanonicalFieldSpec("http.request.method", "http_method"),
    "tls.server_name": CanonicalFieldSpec("tls.server_name", "tls_sni"),
    "tls.alpn.first": CanonicalFieldSpec("tls.alpn.first", "tls_alpn_first"),
    "tls.ja3": CanonicalFieldSpec("tls.ja3", "ja3"),
    "tls.ja4": CanonicalFieldSpec("tls.ja4", "ja4"),
    "tls.ja4.ptype": CanonicalFieldSpec("tls.ja4.ptype", "ja4_ptype"),
    "ssh.action": CanonicalFieldSpec("ssh.action", "ssh_action"),
    "user.name": CanonicalFieldSpec("user.name", "ssh_username"),
    "process.pid": CanonicalFieldSpec("process.pid", "proc_pid"),
    "process.parent.pid": CanonicalFieldSpec("process.parent.pid", "proc_ppid"),
    "process.name": CanonicalFieldSpec("process.name", "proc_name"),
    "process.executable": CanonicalFieldSpec("process.executable", "proc_exe"),
    "process.parent.name": CanonicalFieldSpec("process.parent.name", "proc_parent_name"),
    "file.path": CanonicalFieldSpec("file.path", "fim_path"),
    "file.category": CanonicalFieldSpec("file.category", "fim_category"),
    "threat.heuristic.name": CanonicalFieldSpec("threat.heuristic.name", "heuristic_name"),
    "threat.heuristic.confidence": CanonicalFieldSpec(
        "threat.heuristic.confidence",
        "heuristic_confidence",
    ),
    "ssh.auth.source": CanonicalFieldSpec(
        "ssh.auth.source", "extra", storage_kind="jsonb", jsonb_path=("source",)
    ),
    "ssh.auth.action": CanonicalFieldSpec(
        "ssh.auth.action", "extra", storage_kind="jsonb", jsonb_path=("action",)
    ),
    "process.command_line": CanonicalFieldSpec(
        "process.command_line", "extra", storage_kind="jsonb", jsonb_path=("command",)
    ),
    "process.user.name": CanonicalFieldSpec(
        "process.user.name", "extra", storage_kind="jsonb", jsonb_path=("username",)
    ),
    "process.user.target": CanonicalFieldSpec(
        "process.user.target", "extra", storage_kind="jsonb", jsonb_path=("target_user",)
    ),
    "process.working_dir": CanonicalFieldSpec(
        "process.working_dir", "extra", storage_kind="jsonb", jsonb_path=("working_dir",)
    ),
    "file.hash.sha256": CanonicalFieldSpec(
        "file.hash.sha256", "extra", storage_kind="jsonb", jsonb_path=("sha256",)
    ),
    "network.flow.direction": CanonicalFieldSpec(
        "network.flow.direction", "extra", storage_kind="jsonb", jsonb_path=("flow_direction",)
    ),
}


def canonical_field_names() -> tuple[str, ...]:
    return tuple(sorted(CANONICAL_FIELD_MAP))


def resolve_canonical_field(field_name: str) -> CanonicalFieldSpec:
    key = str(field_name or "").strip()
    spec = CANONICAL_FIELD_MAP.get(key)
    if spec is None:
        raise UnsupportedCanonicalFieldError(f"Unsupported canonical field: {key or '<empty>'}")
    return spec
