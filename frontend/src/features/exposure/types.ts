export type ExposureSeverity = "informational" | "low" | "medium" | "high" | "critical" | "unknown";
export type ExposureStatus = "active" | "inactive" | "stale" | "unknown";
export type ExposureFindingStatus = "open" | "acknowledged" | "resolved" | "suppressed";
export type ExposureAssetSort = "risk_desc" | "risk_asc" | "updated_desc" | "last_seen_desc";

export type EvidenceRef = {
  source_type: string;
  source_id: string;
  observed_at: string;
  title: string;
  summary: string;
  metadata: Record<string, unknown>;
};

export type ScoreBreakdown = {
  exposure_score: number;
  vulnerability_score: number;
  active_threat_score: number;
  persistence_score: number;
  attack_chain_score: number;
  asset_criticality_score: number;
  reliability_penalty: number;
};

export type ScoreExplanationComponent = {
  component: string;
  score: number;
};

export type ScoreReason = {
  code: string;
  description: string;
};

export type ScoreExplanation = {
  risk_score: number;
  severity: ExposureSeverity;
  confidence: number;
  score_components: ScoreExplanationComponent[];
  reasons: ScoreReason[];
  confidence_note: string;
};

export type Recommendation = {
  action: string;
  title: string;
  reason: string;
  priority: number;
  safety_level: string;
  requires_admin: boolean;
  related_evidence_refs: EvidenceRef[];
  reason_code: string | null;
  metadata: Record<string, unknown>;
};

export type ExposureCount = {
  key: string;
  count: number;
};

export type ExposureAssetPosture = {
  asset_key: string;
  agent_id: string | null;
  asset_type: string;
  display_name: string;
  hostname: string | null;
  environment: string | null;
  criticality: string;
  severity: ExposureSeverity;
  risk_score: number;
  confidence: number;
  status: ExposureStatus;
  first_seen_at: string;
  last_seen_at: string;
  updated_at: string;
  score_breakdown: ScoreBreakdown;
  reason_codes: string[];
  top_recommendations: Recommendation[];
  evidence_counts: Record<string, number>;
  metadata: Record<string, unknown>;
};

export type ExposureFinding = {
  finding_key: string;
  asset_key: string;
  agent_id: string | null;
  finding_type: string;
  severity: ExposureSeverity;
  score_delta: number;
  confidence: number;
  title: string;
  summary: string;
  status: ExposureFindingStatus;
  first_seen_at: string;
  last_seen_at: string;
  updated_at: string;
  related_node_keys: string[];
  evidence_refs: EvidenceRef[];
  reason_codes: string[];
  recommendations: Recommendation[];
  metadata: Record<string, unknown>;
};

export type ExposureGraphNode = {
  node_key: string;
  node_type: string;
  asset_key: string | null;
  agent_id: string | null;
  label: string;
  severity: ExposureSeverity;
  risk_score: number;
  confidence: number;
  first_seen_at: string;
  last_seen_at: string;
  updated_at: string;
  properties: Record<string, unknown>;
  source_refs: EvidenceRef[];
};

export type ExposureGraphEdge = {
  edge_key: string;
  source_node_key: string;
  target_node_key: string;
  edge_type: string;
  asset_key: string | null;
  agent_id: string | null;
  weight: number;
  confidence: number;
  first_seen_at: string;
  last_seen_at: string;
  updated_at: string;
  properties: Record<string, unknown>;
  evidence_refs: EvidenceRef[];
};

export type ExposureLegendItem = {
  key: string;
  label: string;
};

export type ExposureGraphLegend = {
  node_types: ExposureLegendItem[];
  edge_types: ExposureLegendItem[];
};

export type ExposureGraphHealth = {
  depth_applied: number;
  max_nodes_applied: number;
  max_edges_applied: number;
  node_count: number;
  edge_count: number;
  nodes_truncated: boolean;
  edges_truncated: boolean;
  posture_updated_at: string | null;
  stale_agent: boolean;
  stale_inventory: boolean;
};

export type ExposureGraph = {
  root_node_key: string;
  recommended_focus_node_keys: string[];
  nodes: ExposureGraphNode[];
  edges: ExposureGraphEdge[];
  legend: ExposureGraphLegend;
  graph_health: ExposureGraphHealth;
};

export type ExposureLinkedAttackChainStep = {
  id: number;
  case_id: number;
  stage: string;
  label: string;
  score_delta: number;
  timestamp: string;
  event_id: number | null;
  event_type: string | null;
};

export type ExposureLinkedAttackChainCase = {
  id: number;
  status: string;
  score: number;
  max_stage: string;
  step_count: number;
  suspect_ip: string | null;
  first_seen_at: string;
  last_seen_at: string;
  recent_steps: ExposureLinkedAttackChainStep[];
};

export type ExposureLinkedAlert = {
  id: number;
  created_at: string;
  rule_id: string;
  severity: ExposureSeverity;
  confidence: number;
  description: string;
  src_ip: string | null;
  dst_ip: string | null;
  dst_port: number | null;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  metadata: Record<string, unknown>;
};

export type ExposureLinkedVulnerability = {
  id: number;
  fingerprint: string;
  cve: string | null;
  title: string;
  severity: ExposureSeverity;
  severity_rank: number;
  confidence: number;
  cvss: string | null;
  location: string | null;
  description: string;
  remediation: string;
  observation_state: string;
  operator_disposition: string;
  first_seen_at: string;
  last_seen_at: string;
};

export type ExposureLinkedInvestigation = {
  id: number;
  workspace_key: string;
  title: string;
  status: string;
  severity: string;
  priority: string;
  assignee: string | null;
  updated_at: string;
  linked_attack_chain_case_id: number | null;
  summary: Record<string, unknown>;
};

export type ExposureLinkedResponseAction = {
  id: number;
  action_type: string;
  status: string;
  requested_by: string;
  requested_at: string;
  expires_at: string | null;
  delivered_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  cancelled_at: string | null;
  cancelled_by: string | null;
  last_error: string | null;
  latest_result_status: string | null;
  payload: Record<string, unknown>;
};

export type ExposureScoreHistoryPoint = {
  bucket_ts: string;
  risk_score: number;
  severity: ExposureSeverity;
  confidence: number;
  score_breakdown: ScoreBreakdown;
};

export type ExposureAssetDetail = {
  posture: ExposureAssetPosture;
  score_breakdown: ScoreBreakdown;
  score_explanation: ScoreExplanation;
  reason_codes: string[];
  top_findings: ExposureFinding[];
  top_recommendations: Recommendation[];
  linked_attack_chain_cases: ExposureLinkedAttackChainCase[];
  linked_alerts: ExposureLinkedAlert[];
  linked_vulnerabilities: ExposureLinkedVulnerability[];
  linked_investigations: ExposureLinkedInvestigation[];
  linked_response_actions: ExposureLinkedResponseAction[];
  recent_score_history: ExposureScoreHistoryPoint[];
  updated_at: string;
};

export type ExposureAttackPathStage = {
  stage: string;
  label: string;
  source: string;
  confidence: number;
};

export type ExposureAttackPath = {
  path_key: string;
  asset_key: string;
  severity: ExposureSeverity;
  risk_score: number;
  confidence: number;
  title: string;
  summary: string;
  stages: ExposureAttackPathStage[];
  nodes: ExposureGraphNode[];
  edges: ExposureGraphEdge[];
  evidence_refs: EvidenceRef[];
  recommendations: Recommendation[];
};

export type ExposureSummary = {
  total_assets: number;
  critical_assets: number;
  high_assets: number;
  medium_assets: number;
  low_assets: number;
  informational_assets: number;
  avg_risk_score: number;
  max_risk_score: number;
  active_findings: number;
  active_attack_paths: number;
  stale_agents: number;
  stale_inventory_assets: number;
  top_reason_codes: ExposureCount[];
  top_recommendations: ExposureCount[];
  updated_at: string | null;
};

export type ExposureRecalculateResult = {
  accepted: boolean;
  mode: string;
  requested_at: string;
  replay_from_event_id: number | null;
};

export type ExposureInvestigationResult = {
  created: boolean;
  workspace_id: number;
  workspace_key: string;
  title: string;
  severity: string;
  priority: string;
  bookmark_count_added: number;
};

export type ExposureTriageResponseAction = {
  action_id: number;
  action_type: string;
  agent_id: string;
  status: string;
  requested_at: string;
  expires_at: string | null;
};

export type ExposureErrorOut = {
  code: string;
  message: string;
  context: Record<string, unknown>;
};

export type ExposureAssetsParams = {
  page_size?: number;
  cursor?: string | null;
  q?: string | null;
  severity?: string | null;
  min_score?: number | null;
  agent_id?: string | null;
  status?: string | null;
  reason_code?: string | null;
  has_attack_chain?: boolean | null;
  has_critical_vuln?: boolean | null;
  has_persistence_signal?: boolean | null;
  sort?: ExposureAssetSort;
  signal?: AbortSignal;
};

export type ExposurePathsParams = {
  page_size?: number;
  cursor?: string | null;
  severity?: string | null;
  agent_id?: string | null;
  min_score?: number | null;
  reason_code?: string | null;
  signal?: AbortSignal;
};

export type ExposureFindingsParams = {
  page_size?: number;
  cursor?: string | null;
  asset_key?: string | null;
  agent_id?: string | null;
  finding_type?: string | null;
  severity?: string | null;
  status?: string | null;
  q?: string | null;
  signal?: AbortSignal;
};

export type ExposureGraphParams = {
  depth?: number;
  node_types?: string[];
  edge_types?: string[];
  min_confidence?: number;
  max_nodes?: number;
  max_edges?: number;
  include_resolved?: boolean;
  signal?: AbortSignal;
};
