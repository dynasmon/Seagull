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
  END IF;
  IF to_regclass('public.alerts') IS NOT NULL THEN
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at)';
  END IF;
  IF to_regclass('public.agents') IS NOT NULL THEN
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_agents_last_seen_at ON agents(last_seen_at)';
  END IF;
END $$;