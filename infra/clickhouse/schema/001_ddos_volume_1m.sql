CREATE TABLE IF NOT EXISTS net_events_ddos_volume_1m
(
    bucket_ts DateTime('UTC'),
    agent_id LowCardinality(String),
    events SimpleAggregateFunction(sum, UInt64),
    packets SimpleAggregateFunction(sum, Float64),
    peak_pps SimpleAggregateFunction(max, Float64),
    peak_bps SimpleAggregateFunction(max, Float64)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(bucket_ts)
ORDER BY (bucket_ts, agent_id)
TTL bucket_ts + toIntervalDay(90) DELETE
SETTINGS index_granularity = 8192, non_replicated_deduplication_window = 1000;

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_net_events_ddos_volume_1m
TO net_events_ddos_volume_1m
AS
SELECT
    toStartOfMinute(timestamp) AS bucket_ts,
    agent_id,
    count() AS events,
    sum(if(event_type = 'dos_attack', JSONExtractFloat(extra_json, 'packets'), 1.0)) AS packets,
    max(greatest(JSONExtractFloat(extra_json, 'pps'), JSONExtractFloat(extra_json, 'estimated_pps'))) AS peak_pps,
    max(greatest(JSONExtractFloat(extra_json, 'bps'), JSONExtractFloat(extra_json, 'estimated_bps'))) AS peak_bps
FROM net_events_raw
WHERE event_type IN ('dos_attack', 'ddos_telemetry')
GROUP BY bucket_ts, agent_id;
