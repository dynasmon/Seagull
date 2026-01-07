CREATE INDEX IF NOT EXISTS idx_net_events_ts ON net_events ("timestamp");
CREATE INDEX IF NOT EXISTS idx_net_events_type_ts ON net_events (event_type, "timestamp");
CREATE INDEX IF NOT EXISTS idx_net_events_agent_ts ON net_events (agent_id, "timestamp");

CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at);
