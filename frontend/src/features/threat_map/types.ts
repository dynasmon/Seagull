export type ThreatGeoIp = {
  ip: string;
  count: number;
  severity: string;
  scope?: string | null;
  label?: string | null;
  is_public?: boolean | null;
  asn?: string | null;
  asn_org?: string | null;
  org?: string | null;
};

export type ThreatGeoRuleCount = {
  rule_id: string;
  count: number;
};

export type ThreatGeoPoint = {
  lat: number;
  lon: number;
  country?: string | null;
  region?: string | null;
  city?: string | null;
  org?: string | null;
  asn_org?: string | null;
  count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  severity: string;
  unique_ips: number;
  last_seen?: string | null;
  top_ips: ThreatGeoIp[];
  top_rules: ThreatGeoRuleCount[];
};

export type ThreatGeoMeta = {
  source: string;
  cache_hit: boolean;
  query_latency_ms?: number | null;
  query_window_start?: string | null;
  query_window_end?: string | null;
};

export type ThreatGeoResponse = {
  generated_at: string;
  since_minutes: number;
  severity?: string | null;
  total_alerts: number;
  located_ips: number;
  unlocated_ips: number;
  points: ThreatGeoPoint[];
  meta: ThreatGeoMeta;
};
