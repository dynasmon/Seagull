CREATE INDEX IF NOT EXISTS idx_net_events_ts ON net_events ("timestamp");
CREATE INDEX IF NOT EXISTS idx_net_events_ts_type ON net_events ("timestamp", event_type);
CREATE INDEX IF NOT EXISTS idx_net_events_agent_ts ON net_events (agent_id, "timestamp");

CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_created_severity ON alerts (created_at, severity);
