import type {
  TopologyEdge,
  TopologyNode,
  TopologyObservation,
  TopologyRelatedAlert,
  TopologyRelatedAttackChainCase,
  TopologyRelatedExposureFinding,
  TopologyRelatedFlow,
} from "../../types";

function clean(value: unknown): string {
  return String(value ?? "").trim();
}

function withQuery(path: string, params: URLSearchParams): string {
  const query = params.toString();
  return query ? `${path}?${query}` : path;
}

function firstNonEmpty(...values: unknown[]): string {
  for (const value of values) {
    const text = clean(value);
    if (text) return text;
  }
  return "";
}

export function buildEventsPivotUrl(input: {
  ip?: string | null;
  agentId?: string | null;
  port?: number | string | null;
  eventId?: number | string | null;
  eventType?: string | null;
  search?: string | null;
}): string {
  const params = new URLSearchParams();
  const search = clean(input.search) || [input.ip, input.port].map(clean).filter(Boolean).join(" ") || firstNonEmpty(input.ip, input.port);
  if (search) params.set("search", search);
  if (clean(input.agentId)) params.set("agent_id", clean(input.agentId));
  if (clean(input.eventType)) params.set("event_type", clean(input.eventType));
  const eventId = Number(input.eventId);
  if (Number.isFinite(eventId) && eventId > 0) params.set("event_id", String(Math.trunc(eventId)));
  return withQuery("/events", params);
}

export function buildAlertsPivotUrl(input: {
  ip?: string | null;
  severity?: string | null;
  status?: string | null;
  ruleId?: string | null;
  search?: string | null;
}): string {
  const params = new URLSearchParams();
  const search = firstNonEmpty(input.search, input.ip);
  if (search) params.set("search", search);
  if (clean(input.severity)) params.set("severity", clean(input.severity).toLowerCase());
  if (clean(input.status)) params.set("status", clean(input.status).toLowerCase());
  if (clean(input.ruleId)) params.set("rule_id", clean(input.ruleId));
  return withQuery("/alerts/queue", params);
}

export function buildInventoryPivotUrl(input: { agentId?: string | null; openDrawer?: boolean }): string | null {
  const agentId = clean(input.agentId);
  if (!agentId) return null;
  const params = new URLSearchParams();
  params.set("agent_id", agentId);
  if (input.openDrawer) params.set("open_drawer", "1");
  return withQuery("/inventory", params);
}

export function buildExposureAssetPivotUrl(input: { assetKey?: string | null; agentId?: string | null; q?: string | null }): string | null {
  const params = new URLSearchParams();
  params.set("tab", "assets");
  if (clean(input.assetKey)) params.set("asset_key", clean(input.assetKey));
  if (clean(input.agentId)) params.set("agent_id", clean(input.agentId));
  if (clean(input.q)) params.set("q", clean(input.q));
  if (params.toString() === "tab=assets") return null;
  return withQuery("/exposure", params);
}

export function buildExposureFindingPivotUrl(input: { findingKey?: string | null; assetKey?: string | null; q?: string | null }): string | null {
  const params = new URLSearchParams();
  params.set("tab", "findings");
  if (clean(input.findingKey)) params.set("finding_key", clean(input.findingKey));
  if (clean(input.assetKey)) params.set("asset_key", clean(input.assetKey));
  if (clean(input.q)) params.set("q", clean(input.q));
  if (params.toString() === "tab=findings") return null;
  return withQuery("/exposure", params);
}

export function buildAttackChainPivotUrl(input: { caseId?: number | string | null; suspectIp?: string | null; agentId?: string | null }): string | null {
  const params = new URLSearchParams();
  const caseId = Number(input.caseId);
  if (Number.isFinite(caseId) && caseId > 0) params.set("case_id", String(Math.trunc(caseId)));
  const query = params.toString();
  return query ? `/attack-chain?${query}` : null;
}

export function nodePrimaryIp(node: TopologyNode): string {
  return firstNonEmpty(node.ip, node.cidr);
}

export function nodeAssetKey(node: TopologyNode): string {
  return clean(node.metadata?.exposure_asset_key);
}

export function nodeEventsPivot(node: TopologyNode): string {
  return buildEventsPivotUrl({
    ip: node.ip || node.cidr,
    agentId: node.agent_id,
    port: node.port,
  });
}

export function nodeAlertsPivot(node: TopologyNode): string {
  return buildAlertsPivotUrl({ ip: node.ip || node.cidr, severity: node.severity });
}

export function edgeEventsPivot(edge: TopologyEdge, sourceIp?: string | null, targetIp?: string | null): string {
  return buildEventsPivotUrl({
    ip: firstNonEmpty(sourceIp, targetIp),
    agentId: edge.agent_id,
    port: edge.port,
  });
}

export function edgeAlertsPivot(edge: TopologyEdge, sourceIp?: string | null, targetIp?: string | null): string {
  return buildAlertsPivotUrl({
    ip: firstNonEmpty(sourceIp, targetIp),
    severity: edge.severity,
  });
}

export function observationPivotUrl(observation: TopologyObservation): string | null {
  const sourceType = clean(observation.source_type).toLowerCase();
  const sourceId = clean(observation.source_id);
  if ((sourceType === "event" || sourceType === "flow") && Number(sourceId) > 0) {
    return buildEventsPivotUrl({ eventId: sourceId });
  }
  if (sourceType === "alert" && sourceId) {
    return buildAlertsPivotUrl({ search: sourceId });
  }
  if (sourceType === "inventory" && observation.agent_id) {
    return buildInventoryPivotUrl({ agentId: observation.agent_id, openDrawer: true });
  }
  if (sourceType === "exposure" && sourceId) {
    return buildExposureAssetPivotUrl({ assetKey: sourceId });
  }
  return null;
}

export function flowPivotUrl(flow: TopologyRelatedFlow): string {
  return buildEventsPivotUrl({
    eventId: flow.id,
    agentId: flow.agent_id,
    ip: flow.src_ip || flow.dst_ip,
    port: flow.dst_port || flow.src_port,
    eventType: flow.event_type,
  });
}

export function alertPivotUrl(alert: TopologyRelatedAlert): string {
  return buildAlertsPivotUrl({
    search: String(alert.id),
    severity: alert.severity,
    status: alert.status,
    ruleId: alert.rule_id,
  });
}

export function exposureFindingPivotUrl(finding: TopologyRelatedExposureFinding): string {
  return buildExposureFindingPivotUrl({
    findingKey: finding.finding_key,
    assetKey: finding.asset_key,
    q: finding.finding_key,
  }) || "/exposure";
}

export function attackChainCasePivotUrl(item: TopologyRelatedAttackChainCase): string {
  return buildAttackChainPivotUrl({ caseId: item.id, suspectIp: item.suspect_ip, agentId: item.agent_id }) || "/attack-chain";
}
