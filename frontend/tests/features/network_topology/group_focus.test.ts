import { describe, expect, it } from "vitest";

import { graphToConnectionView } from "@/features/network_topology/lib/graph/graphTransform";
import { nodeImportance, type TopologyLayout, type TopologyLayoutNode } from "@/features/network_topology/lib/layout/topologyLayout";
import type { TopologyGraph, TopologyNode } from "@/features/network_topology/types";

const makeNode = (key: string, overrides: object = {}): TopologyNode => ({
  node_key: key,
  node_type: "host" as const,
  agent_id: null,
  label: key,
  ip: `10.0.0.${key.slice(-1)}`,
  cidr: null,
  port: null,
  protocol: null,
  severity: "low" as const,
  risk_score: 0,
  confidence: 80,
  is_stale: false,
  event_count: 0,
  alert_count: 0,
  observation_count: 0,
  first_seen_at: "2026-01-01T00:00:00Z",
  last_seen_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
  metadata: {},
  ...overrides,
});

const makeEdge = (src: string, tgt: string) => ({
  edge_key: `${src}->${tgt}`,
  source_node_key: src,
  target_node_key: tgt,
  edge_type: "observed_flow" as const,
  agent_id: null,
  weight: 1,
  confidence: 80,
  severity: "low" as const,
  port: null,
  protocol: null,
  event_count: 1,
  alert_count: 0,
  first_seen_at: "2026-01-01T00:00:00Z",
  last_seen_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
  metadata: {},
});

const mockGraph: TopologyGraph = {
  nodes: [makeNode("node-1"), makeNode("node-2"), makeNode("node-3")],
  edges: [makeEdge("node-1", "node-2"), makeEdge("node-2", "node-3")],
  generated_at: undefined,
  projected_at: null,
  last_projected_at: null,
  freshness_seconds: null,
  stale: false,
  graph_health: {
    node_count: 3,
    edge_count: 2,
    nodes_truncated: false,
    edges_truncated: false,
    max_nodes_applied: 350,
    max_edges_applied: 650,
  },
};

function buildLayout(graph: TopologyGraph): TopologyLayout {
  const layoutNodes: TopologyLayoutNode[] = graph.nodes.map((n, idx) => ({
    ...n,
    x: idx * 200,
    y: 0,
    radius: 12,
    group_key: null,
    importance: nodeImportance(n),
  }));
  const nodeByKey = new Map(layoutNodes.map((n) => [n.node_key, n]));
  return {
    width: 1680,
    height: 1040,
    nodes: layoutNodes,
    edges: graph.edges.map((e) => ({
      ...e,
      source: nodeByKey.get(e.source_node_key) ?? null,
      target: nodeByKey.get(e.target_node_key) ?? null,
    })),
    areas: [],
  };
}

const defaultSel = { selectedKey: null, selectedKind: null as null, highlightedKeys: new Set<string>() };

describe("graphToConnectionView – focus state", () => {
  it("dims nodes outside the focused group", () => {
    const focusState = { focusedNodeKeys: new Set(["node-1", "node-2"]) };
    const { nodes } = graphToConnectionView(mockGraph, buildLayout(mockGraph), defaultSel, undefined, focusState);
    const n3 = nodes.find((n) => n.id === "node-3");
    expect(n3?.data.isDimmed).toBe(true);
  });

  it("does not dim nodes inside the focused group", () => {
    const focusState = { focusedNodeKeys: new Set(["node-1", "node-2"]) };
    const { nodes } = graphToConnectionView(mockGraph, buildLayout(mockGraph), defaultSel, undefined, focusState);
    const n1 = nodes.find((n) => n.id === "node-1");
    const n2 = nodes.find((n) => n.id === "node-2");
    expect(n1?.data.isDimmed).toBe(false);
    expect(n2?.data.isDimmed).toBe(false);
  });

  it("dims edges where both endpoints are outside the focused group", () => {
    const focusState = { focusedNodeKeys: new Set(["node-1"]) };
    const { edges } = graphToConnectionView(mockGraph, buildLayout(mockGraph), defaultSel, undefined, focusState);
    const e23 = edges.find((e) => e.id === "node-2->node-3");
    expect(e23?.data?.isDimmed).toBe(true);
  });

  it("does not dim edges where at least one endpoint is in the focused group", () => {
    const focusState = { focusedNodeKeys: new Set(["node-1", "node-2"]) };
    const { edges } = graphToConnectionView(mockGraph, buildLayout(mockGraph), defaultSel, undefined, focusState);
    const e12 = edges.find((e) => e.id === "node-1->node-2");
    expect(e12?.data?.isDimmed).toBe(false);
  });

  it("search state takes priority over focus state for dimming", () => {
    const focusState = { focusedNodeKeys: new Set(["node-1"]) };
    const searchState = {
      matchedNodeKeys: new Set(["node-3"]),
      matchedGroupKeys: new Set<string>(),
      activeMatchKey: null,
    };
    const { nodes } = graphToConnectionView(mockGraph, buildLayout(mockGraph), defaultSel, searchState, focusState);
    const n1 = nodes.find((n) => n.id === "node-1");
    const n3 = nodes.find((n) => n.id === "node-3");
    expect(n1?.data.isDimmed).toBe(true);
    expect(n3?.data.isDimmed).toBe(false);
  });

  it("without focus state falls back to selection dimming", () => {
    const selState = {
      selectedKey: "node-1",
      selectedKind: "node" as const,
      highlightedKeys: new Set(["node-1", "node-1->node-2"]),
    };
    const { nodes } = graphToConnectionView(mockGraph, buildLayout(mockGraph), selState, undefined, undefined);
    const n2 = nodes.find((n) => n.id === "node-2");
    expect(n2?.data.isDimmed).toBe(true);
  });

  it("does not dim anything when no focus, no search, and no selection", () => {
    const { nodes } = graphToConnectionView(mockGraph, buildLayout(mockGraph), defaultSel, undefined, undefined);
    expect(nodes.every((n) => !n.data.isDimmed)).toBe(true);
  });
});
