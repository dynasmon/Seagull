export type TopologySeverity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "informational"
  | "unknown"
  | (string & {});

export type TopologyNodeType =
  | "agent"
  | "host"
  | "interface"
  | "subnet"
  | "service"
  | "external_ip"
  | "gateway"
  | "docker_network"
  | "unknown"
  | (string & {});

export type TopologyEdgeType =
  | "owns_interface"
  | "member_of_subnet"
  | "observed_flow"
  | "listens_on"
  | "resolved_dns"
  | "alert_related"
  | "exposure_related"
  | "route_next_hop"
  | "same_agent"
  | "inferred_relationship"
  | (string & {});

export type TopologyIpScope =
  | ""
  | "public_internet"
  | "internal_network"
  | "private_address"
  | "loopback"
  | "link_local"
  | "unique_local"
  | "cgnat"
  | "reserved"
  | "invalid"
  | "unknown"
  | (string & {});

export type TopologyTimeWindowMinutes = 15 | 60 | 360 | 1440 | 10080;

export type TopologyNodeTypeStat = {
  node_type: string;
  count: number;
};

export type TopologyCoverage = {
  agents_projected?: number;
  agents_with_inventory?: number;
  interfaces_extracted?: number;
  subnets_inferred?: number;
  flow_edges_added?: number;
  services_projected?: number;
  alert_edges_added?: number;
  exposure_edges_added?: number;
  stale_nodes_marked?: number;
  warnings?: string[];
  [key: string]: unknown;
};

export type TopologyFreshness = {
  generated_at?: string;
  projected_at?: string | null;
  last_projected_at?: string | null;
  data_window?: Record<string, unknown>;
  freshness_seconds?: number | null;
  stale?: boolean;
  source_coverage?: Record<string, unknown>;
  truncation?: Record<string, unknown>;
};

export type TopologyNode = {
  node_key: string;
  node_type: TopologyNodeType;
  agent_id: string | null;
  label: string;
  ip: string | null;
  cidr: string | null;
  port: number | null;
  protocol: string | null;
  severity: TopologySeverity;
  risk_score: number;
  confidence: number;
  is_stale: boolean;
  event_count: number;
  alert_count: number;
  observation_count: number;
  first_seen_at: string;
  last_seen_at: string;
  updated_at: string;
  metadata: Record<string, unknown>;
};

export type TopologyEdge = {
  edge_key: string;
  source_node_key: string;
  target_node_key: string;
  edge_type: TopologyEdgeType;
  agent_id: string | null;
  weight: number;
  confidence: number;
  severity: TopologySeverity;
  port: number | null;
  protocol: string | null;
  event_count: number;
  alert_count: number;
  first_seen_at: string;
  last_seen_at: string;
  updated_at: string;
  metadata: Record<string, unknown>;
};

export type TopologyObservation = {
  id: number;
  node_key: string;
  edge_key: string | null;
  agent_id: string | null;
  source_type: string;
  source_id: string | null;
  observed_at: string;
  summary: string;
  confidence: number;
  raw_context: Record<string, unknown>;
};

export type TopologyEvidencePageMeta = {
  limit: number;
  total: number;
  omitted: number;
};

export type TopologyEvidenceSource = {
  source_type: string;
  count: number;
  latest_observed_at: string | null;
};

export type TopologyRelatedAlert = {
  id: number;
  created_at: string;
  rule_id: string;
  severity: TopologySeverity;
  status: string;
  confidence: number;
  description: string;
  src_ip: string | null;
  dst_ip: string | null;
  dst_port: number | null;
};

export type TopologyRelatedFlow = {
  id: number;
  timestamp: string;
  agent_id: string;
  event_type: string;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  protocol: string | null;
  bytes: number | null;
  app_proto: string | null;
};

export type TopologyRelatedExposureFinding = {
  finding_key: string;
  asset_key: string;
  agent_id: string | null;
  finding_type: string;
  severity: TopologySeverity;
  status: string;
  confidence: number;
  title: string;
  summary: string;
  last_seen_at: string;
};

export type TopologyRelatedAttackChainCase = {
  id: number;
  agent_id: string;
  suspect_ip: string | null;
  status: string;
  score: number;
  max_stage: string;
  step_count: number;
  first_seen_at: string;
  last_seen_at: string;
};

export type TopologyGraphHealth = TopologyFreshness & {
  max_nodes_applied: number;
  max_edges_applied: number;
  node_count: number;
  edge_count: number;
  nodes_truncated: boolean;
  edges_truncated: boolean;
};

export type TopologyGraph = TopologyFreshness & {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  graph_health: TopologyGraphHealth;
};

export type TopologyNodeDetail = {
  node: TopologyNode;
  observations: TopologyObservation[];
  evidence_meta: TopologyEvidencePageMeta;
  evidence_sources: TopologyEvidenceSource[];
  connected_nodes: TopologyNode[];
  edges: TopologyEdge[];
  related_alerts: TopologyRelatedAlert[];
  related_flows: TopologyRelatedFlow[];
  related_services: TopologyNode[];
  related_exposure_findings: TopologyRelatedExposureFinding[];
  related_attack_chain_cases: TopologyRelatedAttackChainCase[];
};

export type TopologyEdgeDetail = {
  edge: TopologyEdge;
  observations: TopologyObservation[];
  evidence_meta: TopologyEvidencePageMeta;
  evidence_sources: TopologyEvidenceSource[];
  source_node: TopologyNode | null;
  target_node: TopologyNode | null;
  related_alerts: TopologyRelatedAlert[];
  related_flows: TopologyRelatedFlow[];
  related_exposure_findings: TopologyRelatedExposureFinding[];
  related_attack_chain_cases: TopologyRelatedAttackChainCase[];
  application_protocols: string[];
  total_bytes: number;
};

export type TopologySubnet = {
  node_key: string;
  cidr: string;
  label: string;
  agent_id: string | null;
  host_count: number;
  interface_count: number;
  agent_count: number;
  severity: TopologySeverity;
  confidence: number;
  first_seen_at: string;
  last_seen_at: string;
  metadata: Record<string, unknown>;
};

export type TopologyInsightGroup = "needs_attention" | "normal_activity" | "visibility_gaps";
export type TopologyInsightSeverity = "critical" | "high" | "medium" | "low" | "info" | "ok";

export type TopologyInsight = {
  id: string;
  group: TopologyInsightGroup;
  severity: TopologyInsightSeverity;
  title: string;
  detail: string;
  count: number | null;
};

export type TopologyVisibility = {
  inventory_coverage: number;
  flow_coverage: boolean;
  alert_coverage: boolean;
  protocol_coverage: boolean;
  exposure_coverage: boolean;
  last_inventory_at: string | null;
  last_event_at: string | null;
  last_alert_at: string | null;
  known_limitations: string[];
};

export type TopologySummary = TopologyFreshness & {
  total_nodes: number;
  total_edges: number;
  agent_count: number;
  host_count: number;
  subnet_count: number;
  external_ip_count: number;
  service_count: number;
  docker_network_count: number;
  unknown_count: number;
  stale_node_count: number;
  alert_edge_count: number;
  exposure_edge_count: number;
  node_type_breakdown: TopologyNodeTypeStat[];
  insights: TopologyInsight[];
  visibility: TopologyVisibility | null;
};

export type TopologyRecalculateResult = {
  accepted: boolean;
  projected_nodes: number;
  projected_edges: number;
  duration_ms: number;
  requested_at: string;
  coverage: TopologyCoverage;
};

export type TopologyGraphParams = {
  max_nodes?: number;
  max_edges?: number;
  min_confidence?: number;
  agent_id?: string;
  node_types?: string[];
  edge_types?: string[];
  ip_scope?: string;
  since?: string;
  until?: string;
  include_stale?: boolean;
  signal?: AbortSignal;
};

export type TopologySubnetParams = {
  page_size?: number;
  cursor?: string | null;
  agent_id?: string;
  since?: string;
  until?: string;
  signal?: AbortSignal;
};

export type TopologyObservationParams = {
  page_size?: number;
  cursor?: string | null;
  node_key?: string;
  agent_id?: string;
  source_type?: string;
  since?: string;
  until?: string;
  signal?: AbortSignal;
};

export type TopologyFilters = {
  agent_id: string;
  window_minutes: TopologyTimeWindowMinutes;
  node_type: string;
  edge_type: string;
  ip_scope: TopologyIpScope;
  min_confidence: number;
  severity: TopologySeverity | "";
  q: string;
};
