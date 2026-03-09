"""Database bootstrap helpers.

Runtime-safe bootstrap without raw SQL queries:
- ensure important secondary indexes (checkfirst)
- seed offset rows used by background workers

Table creation is handled by Alembic migrations (upgrade head).
"""

from sqlalchemy import Index, func, inspect
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.dialects.postgresql import insert

from app.models.agents import AgentModel
from app.models.alert_rule_overrides import AlertRuleOverrideModel
from app.models.alerts import AlertModel
from app.models.attack_chain import AttackChainAllowlistModel, AttackChainCaseModel, AttackChainStepModel
from app.models.events import EventRollup1mModel, IngestStats1sModel, NetEventModel, NetEventRollup1sModel, SshFailRollup1mModel
from app.models.inventory import AgentInventorySnapshotModel
from app.models.ip_enrichment_cache import IpEnrichmentCacheModel
from app.models.portal_login_events import PortalLoginEventModel
from app.models.portal_otp_tokens import PortalOneTimeTokenModel
from app.models.portal_refresh_sessions import PortalRefreshSessionModel
from app.models.portal_users import PortalUserModel
from app.models.search_index_offsets import SearchIndexOffsetModel
from app.models.vuln import VulnFindingModel, VulnScanModel


def _ensure_indexes(conn) -> None:
    insp = inspect(conn)
    table_names = set(insp.get_table_names(schema="public"))

    idx_specs: list[tuple[str, Index]] = [
        (
            "net_events",
            Index("idx_net_events_ts", NetEventModel.timestamp),
        ),
        (
            "net_events",
            Index("idx_net_events_type_ts", NetEventModel.event_type, NetEventModel.timestamp),
        ),
        (
            "net_events",
            Index("idx_net_events_agent_ts", NetEventModel.agent_id, NetEventModel.timestamp),
        ),
        (
            "net_events",
            Index("idx_net_events_ts_id", NetEventModel.timestamp, NetEventModel.id),
        ),
        (
            "net_events",
            Index(
                "idx_net_events_flow_ts",
                NetEventModel.timestamp,
                postgresql_where=(NetEventModel.event_type == "flow"),
            ),
        ),
        (
            "net_events",
            Index(
                "idx_net_events_dos_ts",
                NetEventModel.timestamp,
                postgresql_where=(NetEventModel.event_type == "dos_attack"),
            ),
        ),
        (
            "net_events",
            Index(
                "idx_net_events_ssh_action_ts",
                NetEventModel.extra["action"].astext,
                NetEventModel.timestamp,
                postgresql_where=(NetEventModel.event_type == "ssh_auth"),
            ),
        ),
        (
            "net_events",
            Index(
                "idx_net_events_ssh_geo_country_ts",
                NetEventModel.extra["geo_country"].astext,
                NetEventModel.timestamp,
                postgresql_where=(NetEventModel.event_type == "ssh_auth"),
            ),
        ),
        (
            "net_events",
            Index(
                "idx_net_events_ssh_geo_org_ts",
                NetEventModel.extra["geo_org"].astext,
                NetEventModel.timestamp,
                postgresql_where=(NetEventModel.event_type == "ssh_auth"),
            ),
        ),
        (
            "net_events",
            Index(
                "idx_net_events_ssh_asn_ts",
                NetEventModel.extra["asn"].astext,
                NetEventModel.timestamp,
                postgresql_where=(NetEventModel.event_type == "ssh_auth"),
            ),
        ),
        (
            "agents",
            Index("idx_agents_last_seen_at", AgentModel.last_seen_at),
        ),
        (
            "alerts",
            Index("idx_alerts_created_at", AlertModel.created_at),
        ),
        (
            "alerts",
            Index("idx_alerts_sev_created_at", AlertModel.severity, AlertModel.created_at),
        ),
        (
            "alerts",
            Index("idx_alerts_created_at_id", AlertModel.created_at, AlertModel.id),
        ),
        (
            "alerts",
            Index("idx_alerts_mitre_tactic_created_at_id", AlertModel.mitre_tactic, AlertModel.created_at.desc(), AlertModel.id.desc()),
        ),
        (
            "alerts",
            Index("idx_alerts_mitre_technique_id_created_at_id", AlertModel.mitre_technique_id, AlertModel.created_at.desc(), AlertModel.id.desc()),
        ),
        (
            "alerts",
            Index("idx_alerts_confidence_created_at_id", AlertModel.confidence, AlertModel.created_at.desc(), AlertModel.id.desc()),
        ),
        (
            "agent_inventory_snapshots",
            Index("idx_inv_agent_collected_id", AgentInventorySnapshotModel.agent_id, AgentInventorySnapshotModel.collected_at, AgentInventorySnapshotModel.id),
        ),
        (
            "agent_inventory_snapshots",
            Index("idx_inv_agent_time", AgentInventorySnapshotModel.agent_id, AgentInventorySnapshotModel.collected_at.desc()),
        ),
        (
            "agent_inventory_snapshots",
            Index("idx_inv_hash", AgentInventorySnapshotModel.agent_id, AgentInventorySnapshotModel.packages_hash),
        ),
        (
            "event_rollups_1m",
            Index("idx_event_rollups_1m_bucket", EventRollup1mModel.bucket_ts.desc()),
        ),
        (
            "ssh_fail_rollups_1m",
            Index("idx_ssh_fail_rollups_1m_bucket", SshFailRollup1mModel.bucket_ts.desc()),
        ),
        (
            "net_event_rollups_1s",
            Index("idx_net_event_rollups_1s_bucket", NetEventRollup1sModel.bucket_ts.desc()),
        ),
        (
            "net_event_rollups_1s",
            Index("idx_net_event_rollups_1s_target_bucket", NetEventRollup1sModel.dst_ip, NetEventRollup1sModel.dst_port, NetEventRollup1sModel.bucket_ts.desc()),
        ),
        (
            "ingest_stats_1s",
            Index("idx_ingest_stats_1s_bucket", IngestStats1sModel.bucket_ts.desc()),
        ),
        (
            "alert_rule_overrides",
            Index("idx_alert_rule_overrides_updated_at", AlertRuleOverrideModel.updated_at.desc()),
        ),
        (
            "vuln_scans",
            Index("idx_vuln_scans_started_at_id", VulnScanModel.started_at.desc(), VulnScanModel.id.desc()),
        ),
        (
            "vuln_scans",
            Index("idx_vuln_scans_reporter_started", VulnScanModel.reporter_agent_id, VulnScanModel.started_at.desc(), VulnScanModel.id.desc()),
        ),
        (
            "vuln_scans",
            Index("idx_vuln_scans_status_started", VulnScanModel.status, VulnScanModel.started_at.desc(), VulnScanModel.id.desc()),
        ),
        (
            "vuln_findings",
            Index("idx_vuln_findings_last_seen_id", VulnFindingModel.last_seen_at.desc(), VulnFindingModel.id.desc()),
        ),
        (
            "vuln_findings",
            Index("idx_vuln_findings_asset_agent_last_seen", VulnFindingModel.asset_agent_id, VulnFindingModel.last_seen_at.desc(), VulnFindingModel.id.desc()),
        ),
        (
            "vuln_findings",
            Index("idx_vuln_findings_reporter_last_seen", VulnFindingModel.reporter_agent_id, VulnFindingModel.last_seen_at.desc(), VulnFindingModel.id.desc()),
        ),
        (
            "vuln_findings",
            Index("idx_vuln_findings_status_last_seen", VulnFindingModel.status, VulnFindingModel.last_seen_at.desc(), VulnFindingModel.id.desc()),
        ),
        (
            "vuln_findings",
            Index("idx_vuln_findings_sev_last_seen", VulnFindingModel.severity_rank.desc(), VulnFindingModel.last_seen_at.desc(), VulnFindingModel.id.desc()),
        ),
        (
            "vuln_findings",
            Index("idx_vuln_findings_cve_last_seen", VulnFindingModel.cve, VulnFindingModel.last_seen_at.desc(), VulnFindingModel.id.desc()),
        ),
        (
            "vuln_findings",
            Index("idx_vuln_findings_external_id", VulnFindingModel.external_id),
        ),
        (
            "vuln_findings",
            Index("gin_vuln_findings_tags", VulnFindingModel.tags, postgresql_using="gin"),
        ),
        (
            "vuln_findings",
            Index("gin_vuln_findings_asset", VulnFindingModel.asset, postgresql_using="gin"),
        ),
        (
            "ip_enrichment_cache",
            Index("idx_ip_enrichment_cache_expires_at", IpEnrichmentCacheModel.expires_at),
        ),
        (
            "ip_enrichment_cache",
            Index("idx_ip_enrichment_cache_country", IpEnrichmentCacheModel.country),
        ),
        (
            "ip_enrichment_cache",
            Index("idx_ip_enrichment_cache_asn", IpEnrichmentCacheModel.asn),
        ),
        (
            "portal_users",
            Index("idx_portal_users_username", PortalUserModel.username),
        ),
        (
            "portal_refresh_sessions",
            Index("idx_portal_refresh_user_id", PortalRefreshSessionModel.user_id),
        ),
        (
            "portal_refresh_sessions",
            Index("idx_portal_refresh_family_id", PortalRefreshSessionModel.family_id),
        ),
        (
            "portal_one_time_tokens",
            Index("idx_portal_otp_user_id", PortalOneTimeTokenModel.user_id),
        ),
        (
            "portal_login_events",
            Index("idx_portal_login_events_created_at", PortalLoginEventModel.created_at.desc()),
        ),
        (
            "portal_login_events",
            Index("idx_portal_login_events_user_id_created_at", PortalLoginEventModel.user_id, PortalLoginEventModel.created_at.desc()),
        ),
        (
            "portal_login_events",
            Index("idx_portal_login_events_username_created_at", PortalLoginEventModel.username, PortalLoginEventModel.created_at.desc()),
        ),
        (
            "attack_chain_cases",
            Index("idx_attack_chain_cases_agent_status_last_seen", AttackChainCaseModel.agent_id, AttackChainCaseModel.status, AttackChainCaseModel.last_seen_at.desc(), AttackChainCaseModel.id.desc()),
        ),
        (
            "attack_chain_cases",
            Index("idx_attack_chain_cases_suspect_last_seen", AttackChainCaseModel.suspect_ip, AttackChainCaseModel.last_seen_at.desc(), AttackChainCaseModel.id.desc()),
        ),
        (
            "attack_chain_cases",
            Index(
                "uq_attack_chain_open_case",
                AttackChainCaseModel.agent_id,
                func.coalesce(AttackChainCaseModel.suspect_ip, ""),
                unique=True,
                postgresql_where=(AttackChainCaseModel.status == "open"),
            ),
        ),
        (
            "attack_chain_steps",
            Index("idx_attack_chain_steps_case_time", AttackChainStepModel.case_id, AttackChainStepModel.timestamp.asc(), AttackChainStepModel.id.asc()),
        ),
        (
            "attack_chain_steps",
            Index("idx_attack_chain_steps_case_fp_created", AttackChainStepModel.case_id, AttackChainStepModel.fingerprint, AttackChainStepModel.created_at.desc()),
        ),
        (
            "attack_chain_steps",
            Index("idx_attack_chain_steps_stage_time", AttackChainStepModel.stage, AttackChainStepModel.timestamp.desc(), AttackChainStepModel.id.desc()),
        ),
        (
            "attack_chain_cases",
            Index("gin_attack_chain_cases_context", AttackChainCaseModel.context, postgresql_using="gin"),
        ),
        (
            "attack_chain_steps",
            Index("gin_attack_chain_steps_details", AttackChainStepModel.details, postgresql_using="gin"),
        ),
        (
            "attack_chain_allowlist",
            Index(
                "idx_attack_chain_allowlist_type_enabled_updated",
                AttackChainAllowlistModel.rule_type,
                AttackChainAllowlistModel.enabled,
                AttackChainAllowlistModel.updated_at.desc(),
                AttackChainAllowlistModel.id.desc(),
            ),
        ),
        (
            "attack_chain_allowlist",
            Index(
                "idx_attack_chain_allowlist_scope",
                AttackChainAllowlistModel.agent_id,
                AttackChainAllowlistModel.username,
                AttackChainAllowlistModel.target_user,
            ),
        ),
    ]

    for table_name, idx in idx_specs:
        if table_name in table_names:
            idx.create(bind=conn, checkfirst=True)


def _seed_offsets(conn) -> None:
    for name in ["events", "rollup_events_1m", "rollup_ssh_fail_1m", "vuln_findings", "lupe_enricher_ssh_v1"]:
        stmt = (
            insert(SearchIndexOffsetModel)
            .values(name=name, last_id=0)
            .on_conflict_do_nothing(index_elements=[SearchIndexOffsetModel.name])
        )
        conn.execute(stmt)


def bootstrap_schema(bind: Engine | Connection) -> None:
    # Alembic migrations already run in a transaction and pass a live Connection.
    # Reusing that connection avoids nested begin() errors.
    if isinstance(bind, Connection):
        _ensure_indexes(bind)
        _seed_offsets(bind)
        return

    with bind.begin() as conn:
        _ensure_indexes(conn)
        _seed_offsets(conn)
