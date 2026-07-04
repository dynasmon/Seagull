CREATE TABLE IF NOT EXISTS net_events_ssh_ip_1h
(
    bucket_ts DateTime('UTC'),
    agent_id LowCardinality(String),
    action LowCardinality(String),
    src_ip String,
    cnt SimpleAggregateFunction(sum, UInt64),
    geo_country SimpleAggregateFunction(max, String),
    geo_org SimpleAggregateFunction(max, String),
    asn SimpleAggregateFunction(max, String),
    asn_org SimpleAggregateFunction(max, String)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(bucket_ts)
ORDER BY (bucket_ts, agent_id, action, src_ip)
TTL bucket_ts + toIntervalDay(90) DELETE
SETTINGS index_granularity = 8192, non_replicated_deduplication_window = 1000;

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_net_events_ssh_ip_1h
TO net_events_ssh_ip_1h
AS
SELECT
    toStartOfHour(timestamp) AS bucket_ts,
    agent_id,
    ifNull(ssh_action, '') AS action,
    ifNull(src_ip, '') AS src_ip,
    count() AS cnt,
    max(JSONExtractString(extra_json, 'geo_country')) AS geo_country,
    max(JSONExtractString(extra_json, 'geo_org')) AS geo_org,
    max(JSONExtractString(extra_json, 'asn')) AS asn,
    max(JSONExtractString(extra_json, 'asn_org')) AS asn_org
FROM net_events_raw
WHERE event_type = 'ssh_auth'
GROUP BY bucket_ts, agent_id, action, src_ip;
