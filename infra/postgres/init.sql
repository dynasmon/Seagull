-- NetWatch Postgres init script
--
-- This file is executed only on *fresh* database initialization.
-- Keep it idempotent and safe even if application tables are not created yet.

DO $$
BEGIN
  IF to_regclass('public.net_events') IS NOT NULL THEN
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_net_events_ts ON net_events("timestamp")';
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_net_events_type_ts ON net_events(event_type, "timestamp")';
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_net_events_agent_ts ON net_events(agent_id, "timestamp")';
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_net_events_recent_brin ON net_events USING brin("timestamp")';
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_net_events_app_proto_ts ON net_events(app_proto, "timestamp" DESC)';
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_net_events_dns_qname_ts ON net_events(dns_qname, "timestamp" DESC)';
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_net_events_http_host_ts ON net_events(http_host, "timestamp" DESC)';
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_net_events_tls_sni_ts ON net_events(tls_sni, "timestamp" DESC)';
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_net_events_ja4_ts ON net_events(ja4, "timestamp" DESC)';
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_net_events_ssh_action_col_ts ON net_events(ssh_action, "timestamp" DESC) WHERE event_type = ''ssh_auth''';
  END IF;
  IF to_regclass('public.alerts') IS NOT NULL THEN
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at)';
  END IF;
  IF to_regclass('public.agents') IS NOT NULL THEN
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_agents_last_seen_at ON agents(last_seen_at)';
  END IF;
  IF to_regclass('public.agent_inventory_latest') IS NOT NULL THEN
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_inv_latest_collected ON agent_inventory_latest(collected_at DESC)';
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_inv_latest_packages_count ON agent_inventory_latest(packages_count DESC, agent_id ASC)';
  END IF;
END $$;
