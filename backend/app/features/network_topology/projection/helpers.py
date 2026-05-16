from __future__ import annotations

import hashlib
import ipaddress
from datetime import datetime, timezone
from typing import Any

from app.features.network_topology.classification import infer_subnet_cidr

_STALE_AGENT_HOURS = 24 * 7

_WELL_KNOWN_PORTS: dict[int, tuple[str, str]] = {
    20: ("FTP Data", "file"), 21: ("FTP", "file"), 22: ("SSH", "remote"),
    23: ("Telnet", "remote"), 25: ("SMTP", "mail"), 53: ("DNS", "infrastructure"),
    67: ("DHCP", "infrastructure"), 69: ("TFTP", "file"), 80: ("HTTP", "web"),
    88: ("Kerberos", "security"), 110: ("POP3", "mail"), 111: ("RPC", "infrastructure"),
    123: ("NTP", "infrastructure"), 135: ("MSRPC", "infrastructure"),
    137: ("NetBIOS-NS", "infrastructure"), 139: ("SMB", "file"), 143: ("IMAP", "mail"),
    161: ("SNMP", "monitoring"), 162: ("SNMP Trap", "monitoring"),
    179: ("BGP", "infrastructure"), 389: ("LDAP", "security"), 443: ("HTTPS", "web"),
    445: ("SMB", "file"), 465: ("SMTPS", "mail"), 500: ("IKE/IPSec", "security"),
    514: ("Syslog", "monitoring"), 587: ("SMTP Submit", "mail"), 636: ("LDAPS", "security"),
    993: ("IMAPS", "mail"), 995: ("POP3S", "mail"), 1080: ("SOCKS", "infrastructure"),
    1194: ("OpenVPN", "security"), 1433: ("MSSQL", "database"), 1521: ("Oracle DB", "database"),
    1883: ("MQTT", "messaging"), 2049: ("NFS", "file"), 2181: ("ZooKeeper", "infrastructure"),
    2375: ("Docker", "container"), 2376: ("Docker TLS", "container"),
    2379: ("etcd", "infrastructure"), 2380: ("etcd Peer", "infrastructure"),
    3000: ("Grafana", "monitoring"), 3306: ("MySQL", "database"), 3389: ("RDP", "remote"),
    4443: ("HTTPS Alt", "web"), 5000: ("Dev HTTP", "web"), 5432: ("PostgreSQL", "database"),
    5601: ("Kibana", "monitoring"), 5672: ("RabbitMQ", "messaging"), 5900: ("VNC", "remote"),
    5985: ("WinRM", "remote"), 5986: ("WinRM TLS", "remote"), 6379: ("Redis", "database"),
    6443: ("Kubernetes API", "container"), 7001: ("Cassandra", "database"),
    7474: ("Neo4j", "database"), 7687: ("Neo4j Bolt", "database"),
    8080: ("HTTP Alt", "web"), 8443: ("HTTPS Alt", "web"), 8888: ("Jupyter", "monitoring"),
    9000: ("SonarQube", "monitoring"), 9090: ("Prometheus", "monitoring"),
    9092: ("Kafka", "messaging"), 9200: ("Elasticsearch", "database"),
    9300: ("ES Cluster", "database"), 10250: ("Kubelet", "container"),
    10255: ("Kubelet RO", "container"), 11211: ("Memcached", "database"),
    15672: ("RabbitMQ UI", "messaging"), 27017: ("MongoDB", "database"),
    27018: ("MongoDB Shard", "database"), 27019: ("MongoDB Config", "database"),
    50000: ("Jenkins", "monitoring"), 61616: ("ActiveMQ", "messaging"),
}

_APP_PROTO_MAP: dict[str, tuple[str, str]] = {
    "http": ("HTTP", "web"), "https": ("HTTPS", "web"), "tls": ("TLS", "web"),
    "dns": ("DNS", "infrastructure"), "ssh": ("SSH", "remote"), "ftp": ("FTP", "file"),
    "smtp": ("SMTP", "mail"), "imap": ("IMAP", "mail"), "pop3": ("POP3", "mail"),
    "ntp": ("NTP", "infrastructure"), "snmp": ("SNMP", "monitoring"), "smb": ("SMB", "file"),
    "rdp": ("RDP", "remote"), "ldap": ("LDAP", "security"), "dcerpc": ("MSRPC", "infrastructure"),
    "dhcp": ("DHCP", "infrastructure"), "mqtt": ("MQTT", "messaging"),
    "modbus": ("Modbus", "infrastructure"), "dnp3": ("DNP3", "infrastructure"),
    "krb5": ("Kerberos", "security"), "tftp": ("TFTP", "file"), "telnet": ("Telnet", "remote"),
    "mysql": ("MySQL", "database"), "pgsql": ("PostgreSQL", "database"),
    "redis": ("Redis", "database"), "mongodb": ("MongoDB", "database"),
    "nfs": ("NFS", "file"), "bgp": ("BGP", "infrastructure"), "irc": ("IRC", "messaging"),
}

def _resolve_service_info(port: int | None, proto: str | None, app_proto: str | None) -> dict[str, str]:
    app = str(app_proto or "").strip().lower()
    if app and app not in ("", "unknown", "failed", "n/a"):
        if app in _APP_PROTO_MAP:
            name, category = _APP_PROTO_MAP[app]
            return {"name": name, "category": category}
        return {"name": app.upper(), "category": "other"}
    if port and port in _WELL_KNOWN_PORTS:
        name, category = _WELL_KNOWN_PORTS[port]
        return {"name": name, "category": category}
    if port:
        return {"name": f"Port {port}", "category": "other"}
    return {"name": "Unknown Service", "category": "other"}

def _node_key(*parts: str) -> str:
    raw = "topo:" + ":".join(str(p) for p in parts)
    if len(raw) <= 200:
        return raw
    digest = hashlib.sha256(raw.encode()).hexdigest()[:16]
    return f"topo:{parts[0]}:{digest}"

def _edge_key(edge_type: str, src: str, dst: str) -> str:
    raw = f"{edge_type}::{src}::{dst}"
    if len(raw) <= 250:
        return raw
    digest = hashlib.sha256(raw.encode()).hexdigest()[:24]
    return f"{edge_type}::{digest}"

def _flow_edge_key(src: str, dst: str, port: int | None, proto: str | None) -> str:
    raw = f"observed_flow::{src}::{dst}::{port or 0}::{proto or ''}"
    if len(raw) <= 250:
        return raw
    digest = hashlib.sha256(raw.encode()).hexdigest()[:24]
    return f"observed_flow::{digest}"

def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value or "").strip())
        return True
    except Exception:
        return False

def _matching_interface_network_cidr(interfaces: list[dict[str, Any]], ip: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return None
    for iface in interfaces:
        for raw_cidr in iface.get("cidrs") or []:
            try:
                network = ipaddress.ip_interface(str(raw_cidr)).network
            except Exception:
                continue
            if addr in network:
                return str(network)
    return None

def _ip_node_key(ip: str, ip_info: dict[str, Any]) -> str:
    node_class = ip_info.get("node_class", "unknown")
    return _node_key(node_class, ip)

def _network_from_iface_cidrs(iface_cidrs: list[str], fallback_ip: str) -> str | None:
    for cidr_str in iface_cidrs:
        try:
            net = ipaddress.ip_interface(cidr_str.strip()).network
            net_str = str(net)
            # Skip loopback and link-local subnets
            if net.is_loopback or net.is_link_local:
                continue
            return net_str
        except Exception:
            continue
    return infer_subnet_cidr(fallback_ip)

def _to_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

def _is_stale_agent(last_seen: datetime | None, now: datetime) -> bool:
    if last_seen is None:
        return True
    ts = _to_utc(last_seen)
    return (now - ts).total_seconds() > _STALE_AGENT_HOURS * 3600

def _sev_to_score(severity: str) -> int:
    return {"critical": 90, "high": 70, "medium": 50, "low": 30, "informational": 10}.get(
        str(severity or "").lower(), 0
    )

def _sev_weight(severity: str) -> float:
    return {"critical": 3.0, "high": 2.0, "medium": 1.5, "low": 1.0, "informational": 0.5}.get(
        str(severity or "").lower(), 1.0
    )
