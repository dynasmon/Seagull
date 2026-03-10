export type MetricCounter = {
  name: string;
  labels: Record<string, string>;
  value: number;
};

export type MetricHistogram = {
  name: string;
  labels: Record<string, string>;
  count: number;
  sum: number;
  min: number;
  max: number;
  avg: number;
};

export type MetricsSnapshot = {
  service: string;
  counters: MetricCounter[];
  histograms: MetricHistogram[];
};

export type SystemStatusResponse = {
  service: {
    name: string;
    environment: string;
    version: string;
    now_utc: string;
    uptime_seconds: number;
  };
  components: {
    api: { status: string; latency_ms?: number | null; error?: string | null };
    database: { status: string; latency_ms?: number | null; error?: string | null };
    redis: { status: string; latency_ms?: number | null; error?: string | null };
    elasticsearch: {
      status: string;
      latency_ms?: number | null;
      mode: string;
      url: string;
      available: boolean;
      error?: string | null;
    };
    ingest_pressure: {
      status: string;
      latency_ms?: number | null;
      storm: {
        active: boolean;
        phase?: string;
        eps: number;
        sample_hot_percent: number;
        sample_warm_percent: number;
        drop_percent: number;
        backlog_events: number;
        backlog_messages: number;
        reason: string;
        since: string | null;
        open_alert_id: number | null;
      };
    };
  };
  fleet: {
    total_agents: number;
    online_agents: number;
    offline_agents: number;
    revoked_agents: number;
    inventory: {
      fresh: number;
      stale: number;
      no_inventory: number;
    };
  };
  observability: {
    counters_total: number;
    histograms_total: number;
    http_requests_total: number;
  };
};
