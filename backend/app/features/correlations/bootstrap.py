from __future__ import annotations

from datetime import datetime

from app.core.db import SessionLocal
from app.features.correlations.models import CorrelationRuleModel


def bootstrap_correlation_rules() -> None:
    db = SessionLocal()
    try:
        existing = db.query(CorrelationRuleModel).count()
        if existing and existing > 0:
            return

        now = datetime.utcnow()
        seeds = [
            CorrelationRuleModel(
                name="Recon followed by SSH brute force",
                description="Ordered scan-to-credential-access sequence from the same source.",
                enabled=True,
                severity="high",
                strategy="sequence",
                group_by="src_ip",
                window_seconds=900,
                min_alerts=2,
                include_patterns=[
                    "admin_ports_vertical_recon_v1",
                    "admin_surface_horizontal_recon_v1",
                    "high_rate_single_target_probe_v1",
                    "wide_ssh_recon_v1",
                    "ssh_invalid_user_burst_v1",
                    "ssh_failed_password_burst_target_v1",
                    "ssh_single_source_multi_target_fail_v1",
                ],
                exclude_patterns=[],
                stages=[
                    {
                        "id": "recon",
                        "name": "Recon",
                        "include_patterns": [
                            "admin_ports_vertical_recon_v1",
                            "admin_surface_horizontal_recon_v1",
                            "high_rate_single_target_probe_v1",
                            "wide_ssh_recon_v1",
                        ],
                        "min_count": 1,
                        "required": True,
                        "maxspan_seconds": 600,
                    },
                    {
                        "id": "ssh_bruteforce",
                        "name": "SSH Brute Force",
                        "include_patterns": [
                            "ssh_invalid_user_burst_v1",
                            "ssh_failed_password_burst_target_v1",
                            "ssh_single_source_multi_target_fail_v1",
                        ],
                        "after": "recon",
                        "within_seconds": 600,
                        "min_count": 1,
                        "required": True,
                        "maxspan_seconds": 600,
                    },
                ],
                entity={"type": "src_ip", "field": "src_ip"},
                created_at=now,
                updated_at=now,
            ),
            CorrelationRuleModel(
                name="Distributed brute force against one target",
                description="Distinct source IPs drive repeated SSH brute-force alerts against the same destination.",
                enabled=True,
                severity="high",
                strategy="cardinality",
                group_by="dst_ip",
                window_seconds=900,
                min_alerts=3,
                include_patterns=[
                    "ssh_invalid_user_burst_v1",
                    "ssh_failed_password_burst_target_v1",
                ],
                exclude_patterns=[],
                stages=[],
                entity={"type": "dst_ip", "field": "dst_ip"},
                strategy_config={
                    "source": "alerts",
                    "field": "src_ip",
                    "threshold": 3,
                },
                created_at=now,
                updated_at=now,
            ),
            CorrelationRuleModel(
                name="Accepted SSH after repeated failures",
                description="Attack-chain evidence shows a successful SSH login after brute-force activity from the same suspect IP.",
                enabled=True,
                severity="critical",
                strategy="temporal_join",
                group_by="suspect_ip",
                window_seconds=1800,
                min_alerts=1,
                include_patterns=[],
                exclude_patterns=[],
                stages=[],
                entity={"type": "suspect_ip", "field": "suspect_ip"},
                evidence_config={
                    "families": [
                        {
                            "id": "failures",
                            "name": "Repeated Failures",
                            "source": "attack_chain_steps",
                            "field_filters": [{"field": "kind", "op": "eq", "value": "ssh_bruteforce"}],
                            "min_count": 1,
                        },
                        {
                            "id": "accepted",
                            "name": "Accepted SSH",
                            "source": "attack_chain_steps",
                            "field_filters": [{"field": "kind", "op": "eq", "value": "ssh_bruteforce_success"}],
                            "after": "failures",
                            "within_seconds": 1800,
                            "min_count": 1,
                        },
                    ]
                },
                created_at=now,
                updated_at=now,
            ),
            CorrelationRuleModel(
                name="Privilege escalation after accepted SSH login",
                description="Attack-chain evidence shows privilege escalation after a suspicious accepted SSH session.",
                enabled=True,
                severity="critical",
                strategy="temporal_join",
                group_by="suspect_ip",
                window_seconds=3600,
                min_alerts=1,
                include_patterns=[],
                exclude_patterns=[],
                stages=[],
                entity={"type": "suspect_ip", "field": "suspect_ip"},
                evidence_config={
                    "families": [
                        {
                            "id": "accepted_ssh",
                            "name": "Accepted SSH",
                            "source": "attack_chain_steps",
                            "field_filters": [
                                {"field": "kind", "op": "contains_any", "value": ["ssh_bruteforce_success", "ssh_new_source"]},
                            ],
                            "min_count": 1,
                        },
                        {
                            "id": "privilege_escalation",
                            "name": "Privilege Escalation",
                            "source": "attack_chain_steps",
                            "field_filters": [
                                {"field": "stage", "op": "eq", "value": "privilege_escalation"},
                            ],
                            "after": "accepted_ssh",
                            "within_seconds": 3600,
                            "min_count": 1,
                        },
                    ]
                },
                created_at=now,
                updated_at=now,
            ),
            CorrelationRuleModel(
                name="Suspicious process followed by outbound beaconing",
                description="Host execution alerts are followed by beaconing or contextual outbound command-and-control evidence on the same agent.",
                enabled=True,
                severity="high",
                strategy="temporal_join",
                group_by="agent_id",
                window_seconds=3600,
                min_alerts=2,
                include_patterns=[],
                exclude_patterns=[],
                stages=[],
                entity={"type": "agent_id", "field": "agent_id"},
                evidence_config={
                    "families": [
                        {
                            "id": "suspicious_process",
                            "name": "Suspicious Process",
                            "source": "alerts",
                            "include_patterns": [
                                "proc_remote_fetch_exec_v1",
                                "proc_service_shell_child_v1",
                                "privilege_proc_euid_root_nonroot_uid_chain_v1",
                            ],
                            "field_filters": [{"field": "agent_id", "op": "exists"}],
                            "min_count": 1,
                        },
                        {
                            "id": "outbound_beaconing",
                            "name": "Outbound Beaconing",
                            "source": "alerts",
                            "include_patterns": [
                                "beacon_suspect_heuristic_v1",
                                "outbound_contextual_rare_destination_v1",
                                "outbound_tls_on_suspicious_ports_v1",
                                "outbound_http_on_admin_or_control_ports_v1",
                            ],
                            "field_filters": [{"field": "agent_id", "op": "exists"}],
                            "after": "suspicious_process",
                            "within_seconds": 3600,
                            "min_count": 1,
                        },
                    ]
                },
                created_at=now,
                updated_at=now,
            ),
            CorrelationRuleModel(
                name="Persistence followed by suspicious outbound activity",
                description="Persistence-oriented host alerts precede outbound beaconing or exfiltration-like evidence from the same agent.",
                enabled=True,
                severity="critical",
                strategy="temporal_join",
                group_by="agent_id",
                window_seconds=6 * 3600,
                min_alerts=2,
                include_patterns=[],
                exclude_patterns=[],
                stages=[],
                entity={"type": "agent_id", "field": "agent_id"},
                evidence_config={
                    "families": [
                        {
                            "id": "persistence",
                            "name": "Persistence",
                            "source": "alerts",
                            "include_patterns": [
                                "persistence_authorized_keys_change_v1",
                                "persistence_systemd_unit_change_v1",
                                "persistence_cron_change_v1",
                            ],
                            "field_filters": [{"field": "agent_id", "op": "exists"}],
                            "min_count": 1,
                        },
                        {
                            "id": "outbound_activity",
                            "name": "Suspicious Outbound Activity",
                            "source": "alerts",
                            "include_patterns": [
                                "outbound_contextual_rare_destination_v1",
                                "outbound_contextual_bursty_upload_anomaly_v1",
                                "beacon_suspect_heuristic_v1",
                                "exfil_suspect_heuristic_v1",
                            ],
                            "field_filters": [{"field": "agent_id", "op": "exists"}],
                            "after": "persistence",
                            "within_seconds": 6 * 3600,
                            "min_count": 1,
                        },
                    ]
                },
                created_at=now,
                updated_at=now,
            ),
            CorrelationRuleModel(
                name="Exposure or vulnerability followed by exploit-like activity",
                description="Exposure findings with exploitability or critical CVE context are followed by exploit-like host activity on the same enrolled asset.",
                enabled=True,
                severity="critical",
                strategy="temporal_join",
                group_by="agent_id",
                window_seconds=24 * 3600,
                min_alerts=1,
                include_patterns=[],
                exclude_patterns=[],
                stages=[],
                entity={"type": "agent_id", "field": "agent_id"},
                evidence_config={
                    "families": [
                        {
                            "id": "exposure_signal",
                            "name": "Exposure Signal",
                            "source": "exposure_findings",
                            "field_filters": [
                                {"field": "agent_id", "op": "exists"},
                                {"field": "reason_codes", "op": "contains_any", "value": ["critical_cve", "exploitability_signal"]},
                            ],
                            "min_count": 1,
                        },
                        {
                            "id": "exploit_like_activity",
                            "name": "Exploit-Like Activity",
                            "source": "alerts",
                            "include_patterns": [
                                "proc_remote_fetch_exec_v1",
                                "proc_service_shell_child_v1",
                                "privilege_proc_euid_root_nonroot_uid_chain_v1",
                                "beacon_suspect_heuristic_v1",
                            ],
                            "field_filters": [{"field": "agent_id", "op": "exists"}],
                            "after": "exposure_signal",
                            "within_seconds": 24 * 3600,
                            "min_count": 1,
                        },
                    ]
                },
                created_at=now,
                updated_at=now,
            ),
            CorrelationRuleModel(
                name="DDoS or L7 impact with prior recon",
                description="Reconnaissance against a destination is followed by DDoS or L7 impact alerts on the same target.",
                enabled=True,
                severity="critical",
                strategy="temporal_join",
                group_by="dst_ip",
                window_seconds=24 * 3600,
                min_alerts=2,
                include_patterns=[],
                exclude_patterns=[],
                stages=[],
                entity={"type": "dst_ip", "field": "dst_ip"},
                evidence_config={
                    "families": [
                        {
                            "id": "prior_recon",
                            "name": "Prior Recon",
                            "source": "alerts",
                            "include_patterns": [
                                "admin_ports_vertical_recon_v1",
                                "multi_protocol_scan_pattern_v1",
                                "high_rate_single_target_probe_v1",
                            ],
                            "min_count": 1,
                        },
                        {
                            "id": "impact",
                            "name": "Impact",
                            "source": "alerts",
                            "include_patterns": [
                                "ddos_attack_high_conf_v1",
                                "ddos_udp_amp_high_conf_v1",
                                "ddos_tcp_syn_high_conf_v1",
                                "ddos_icmp_flood_high_conf_v1",
                                "l7_http_flood_v1",
                                "l7_tls_handshake_flood_v1",
                            ],
                            "after": "prior_recon",
                            "within_seconds": 24 * 3600,
                            "min_count": 1,
                        },
                    ]
                },
                created_at=now,
                updated_at=now,
            ),
        ]

        db.add_all(seeds)
        db.commit()
    finally:
        db.close()
