export type ThreatProvenance = "alert" | "event" | "mixed";
export type ThreatDirection = "inbound" | "outbound" | "internal" | "transit" | "mixed";
export type ThreatEndpointRole = "source" | "destination";
export type ThreatSourceMode = "both" | "events" | "alerts";

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
  provenance?: ThreatProvenance;
  role?: ThreatEndpointRole | null;
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
  provenance: ThreatProvenance;
  direction: ThreatDirection;
  alert_count: number;
  event_count: number;
};

export type ThreatGeoEndpoint = {
  lat: number;
  lon: number;
  country?: string | null;
  region?: string | null;
  city?: string | null;
  label?: string | null;
  scope?: string | null;
};

export type ThreatGeoFlow = {
  id: string;
  origin?: ThreatGeoEndpoint | null;
  target?: ThreatGeoEndpoint | null;
  direction: ThreatDirection;
  provenance: ThreatProvenance;
  severity: string;
  weight: number;
  count: number;
  unique_ips: number;
  last_seen?: string | null;
};

export type ThreatGeoRankCountry = {
  country: string;
  count: number;
  unique_ips: number;
  severity: string;
  provenance: ThreatProvenance;
};

export type ThreatGeoRankIp = {
  ip: string;
  count: number;
  severity: string;
  country?: string | null;
  org?: string | null;
  asn_org?: string | null;
  scope?: string | null;
  label?: string | null;
  is_public?: boolean | null;
  provenance: ThreatProvenance;
  role?: ThreatEndpointRole | null;
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
  source: ThreatSourceMode;
  home?: ThreatGeoEndpoint | null;
  total_alerts: number;
  total_events: number;
  located_ips: number;
  unlocated_ips: number;
  ddos_attacks: number;
  ddos_located_sources: number;
  ddos_unlocated_sources: number;
  points: ThreatGeoPoint[];
  flows: ThreatGeoFlow[];
  top_source_countries: ThreatGeoRankCountry[];
  top_destination_countries: ThreatGeoRankCountry[];
  top_source_ips: ThreatGeoRankIp[];
  top_destination_ips: ThreatGeoRankIp[];
  meta: ThreatGeoMeta;
};
