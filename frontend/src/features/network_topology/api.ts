import { apiGet, apiPost } from "@/shared/lib/http";
import type { CursorPage } from "@/shared/types/pagination";

import type {
  TopologyEdgeDetail,
  TopologyGraph,
  TopologyGraphParams,
  TopologyGroupDetail,
  TopologyNodeDetail,
  TopologyObservation,
  TopologyObservationParams,
  TopologyRecalculateResult,
  TopologySubnet,
  TopologySubnetDetail,
  TopologySubnetParams,
  TopologySummary,
} from "./types";

const BASE = "/api/network-topology";

function appendOptional(q: URLSearchParams, key: string, value: string | number | boolean | null | undefined) {
  if (value === null || value === undefined) return;
  const text = String(value).trim();
  if (!text) return;
  q.set(key, text);
}

function appendList(q: URLSearchParams, key: string, values: string[] | undefined) {
  for (const value of values ?? []) {
    const text = String(value || "").trim();
    if (text) q.append(key, text);
  }
}

function withQuery(path: string, q: URLSearchParams): string {
  const qs = q.toString();
  return qs ? `${path}?${qs}` : path;
}

export function buildTopologyGraphPath(params: TopologyGraphParams = {}): string {
  const q = new URLSearchParams();
  appendOptional(q, "max_nodes", params.max_nodes);
  appendOptional(q, "max_edges", params.max_edges);
  appendOptional(q, "min_confidence", params.min_confidence);
  appendOptional(q, "agent_id", params.agent_id);
  appendList(q, "node_types", params.node_types);
  appendList(q, "edge_types", params.edge_types);
  appendOptional(q, "ip_scope", params.ip_scope);
  appendOptional(q, "since", params.since);
  appendOptional(q, "until", params.until);
  appendOptional(q, "include_stale", params.include_stale);
  appendOptional(q, "view_mode", params.view_mode);
  appendOptional(q, "group_by", params.group_by);
  appendOptional(q, "focused_group_key", params.focused_group_key);
  appendOptional(q, "exclusive_focus", params.exclusive_focus);
  return withQuery(`${BASE}/graph`, q);
}

export function buildTopologySubnetsPath(params: TopologySubnetParams = {}): string {
  const q = new URLSearchParams();
  appendOptional(q, "page_size", params.page_size ?? 50);
  appendOptional(q, "cursor", params.cursor);
  appendOptional(q, "agent_id", params.agent_id);
  appendOptional(q, "since", params.since);
  appendOptional(q, "until", params.until);
  return withQuery(`${BASE}/subnets`, q);
}

export function buildTopologySubnetDetailPath(cidr: string): string {
  const q = new URLSearchParams();
  appendOptional(q, "cidr", cidr);
  return withQuery(`${BASE}/subnets/detail`, q);
}

export function buildTopologyObservationsPath(params: TopologyObservationParams = {}): string {
  const q = new URLSearchParams();
  appendOptional(q, "page_size", params.page_size ?? 50);
  appendOptional(q, "cursor", params.cursor);
  appendOptional(q, "node_key", params.node_key);
  appendOptional(q, "agent_id", params.agent_id);
  appendOptional(q, "source_type", params.source_type);
  appendOptional(q, "since", params.since);
  appendOptional(q, "until", params.until);
  return withQuery(`${BASE}/observations`, q);
}

export function getTopologySummary(signal?: AbortSignal) {
  return apiGet<TopologySummary>(`${BASE}/summary`, { signal });
}

export function getTopologyGraph(params: TopologyGraphParams = {}) {
  return apiGet<TopologyGraph>(buildTopologyGraphPath(params), { signal: params.signal });
}

export function getTopologyNodeDetail(nodeKey: string, signal?: AbortSignal) {
  return apiGet<TopologyNodeDetail>(`${BASE}/nodes/${encodeURIComponent(nodeKey)}`, { cacheMs: 0, signal });
}

export function getTopologyEdgeDetail(edgeKey: string, signal?: AbortSignal) {
  return apiGet<TopologyEdgeDetail>(`${BASE}/edges/${encodeURIComponent(edgeKey)}`, { cacheMs: 0, signal });
}

export function listTopologySubnets(params: TopologySubnetParams = {}) {
  return apiGet<CursorPage<TopologySubnet>>(buildTopologySubnetsPath(params), { cacheMs: 0, signal: params.signal });
}

export function getTopologySubnetDetail(cidr: string, signal?: AbortSignal) {
  return apiGet<TopologySubnetDetail>(buildTopologySubnetDetailPath(cidr), { cacheMs: 0, signal });
}

export function listTopologyObservations(params: TopologyObservationParams = {}) {
  return apiGet<CursorPage<TopologyObservation>>(buildTopologyObservationsPath(params), {
    cacheMs: 0,
    signal: params.signal,
  });
}

export function getTopologyGroupDetail(groupKey: string, signal?: AbortSignal) {
  return apiGet<TopologyGroupDetail>(`${BASE}/groups/${encodeURIComponent(groupKey)}`, { cacheMs: 0, signal });
}

export function requestTopologyRecalculate() {
  return apiPost<TopologyRecalculateResult>(`${BASE}/recalculate`);
}
