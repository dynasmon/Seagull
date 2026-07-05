CREATE TABLE IF NOT EXISTS net_events_ssh_user_1h
(
    bucket_ts DateTime('UTC'),
    agent_id LowCardinality(String),
    action LowCardinality(String),
    username String,
    cnt UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(bucket_ts)
ORDER BY (bucket_ts, agent_id, action, username)
TTL bucket_ts + toIntervalDay(90) DELETE
SETTINGS index_granularity = 8192, non_replicated_deduplication_window = 1000;

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_net_events_ssh_user_1h
TO net_events_ssh_user_1h
AS
SELECT
    toStartOfHour(timestamp) AS bucket_ts,
    agent_id,
    ifNull(ssh_action, '') AS action,
    ifNull(ssh_username, '') AS username,
    count() AS cnt
FROM net_events_raw
WHERE event_type = 'ssh_auth' AND ifNull(ssh_username, '') != ''
GROUP BY bucket_ts, agent_id, action, username;
