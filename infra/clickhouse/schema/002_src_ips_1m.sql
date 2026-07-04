CREATE TABLE IF NOT EXISTS net_events_src_ips_1m
(
    bucket_ts DateTime('UTC'),
    agent_id LowCardinality(String),
    src_ip String,
    cnt UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(bucket_ts)
ORDER BY (bucket_ts, agent_id, src_ip)
TTL bucket_ts + toIntervalDay(14) DELETE
SETTINGS index_granularity = 8192, non_replicated_deduplication_window = 1000;

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_net_events_src_ips_1m
TO net_events_src_ips_1m
AS
SELECT
    toStartOfMinute(timestamp) AS bucket_ts,
    agent_id,
    ifNull(src_ip, '') AS src_ip,
    count() AS cnt
FROM net_events_raw
WHERE src_ip IS NOT NULL
GROUP BY bucket_ts, agent_id, src_ip;
