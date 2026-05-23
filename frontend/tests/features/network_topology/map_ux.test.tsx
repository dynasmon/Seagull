import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { TopologyFilterRail } from "@/features/network_topology/components/TopologyFilterRail";
import { DEFAULT_TOPOLOGY_FILTERS } from "@/features/network_topology/lib/filters";
import {
  graphToConnectionView,
  graphToLocationView,
} from "@/features/network_topology/lib/graphTransform";
import {
  nodeImportance,
  type TopologyGroupLayoutPoint,
  type TopologyLayout,
  type TopologyLayoutNode,
} from "@/features/network_topology/lib/topologyLayoutELK";
import type {
  TopologyGraph,
  TopologyGroup,
  TopologyNode,
} from "@/features/network_topology/types";

const now = "2026-05-17T12:00:00.000Z";
const selection = { selectedKey: null, selectedKind: null as null, highlightedKeys: new Set<string>() };

function node(overrides: Partial<TopologyNode>): TopologyNode {
  return {
    node_key: "node",
    node_type: "host",
    agent_id: "agent-1",
    label: "node",
    ip: null,
    cidr: null,
    port: null,
    protocol: null,
    severity: "low",
    risk_score: 0,
    confidence: 80,
    is_stale: false,
    event_count: 0,
    alert_count: 0,
    observation_count: 0,
    first_seen_at: now,
    last_seen_at: now,
    updated_at: now,
    metadata: {},
    ...overrides,
  };
}

function group(overrides: Partial<TopologyGroup>): TopologyGroup {
  return {
    group_key: "agent:agent-1",
    group_type: "agent",
    label: "Agent 1",
    node_keys: [],
    node_count: 0,
    alert_count: 0,
    highest_severity: "low",
    risk_score: 0,
    is_stale: false,
    agent_id: "agent-1",
    cidr: null,
    ...overrides,
  };
}

function graph(): TopologyGraph {
  return {
    nodes: [
      node({ node_key: "agent", node_type: "agent", label: "Agent 1" }),
      node({ node_key: "quiet-1", label: "quiet-1" }),
      node({ node_key: "quiet-2", label: "quiet-2" }),
      node({ node_key: "risky", label: "risky", severity: "high", risk_score: 84, alert_count: 2 }),
    ],
    edges: [],
    graph_health: {
      node_count: 4,
      edge_count: 0,
      nodes_truncated: false,
      edges_truncated: false,
      max_nodes_applied: 350,
      max_edges_applied: 650,
    },
  };
}

function buildLayout(g: TopologyGraph, gs: TopologyGroup[]): TopologyLayout {
  const groupByNode = new Map<string, string>();
  for (const grp of gs) for (const k of grp.node_keys) groupByNode.set(k, grp.group_key);
  const layoutNodes: TopologyLayoutNode[] = g.nodes.map((n, idx) => ({
    ...n,
    x: idx * 200,
    y: 0,
    radius: 12,
    group_key: groupByNode.get(n.node_key) ?? null,
    importance: nodeImportance(n),
  }));
  const nodeByKey = new Map(layoutNodes.map((n) => [n.node_key, n]));
  return {
    width: 1680,
    height: 1040,
    nodes: layoutNodes,
    edges: g.edges.map((e) => ({
      ...e,
      source: nodeByKey.get(e.source_node_key) ?? null,
      target: nodeByKey.get(e.target_node_key) ?? null,
    })),
    areas: gs.map((grp, idx) => ({
      group: grp,
      x: idx * 400,
      y: 0,
      radius: 180,
      ring: 0,
      degree: 0,
      isCentral: idx === 0,
    })),
  };
}

describe("topology map transforms", () => {
  it("generates compact location markers", () => {
    const groups = [group({ node_count: 4, alert_count: 1 })];
    const positions = new Map<string, TopologyGroupLayoutPoint>([
      [groups[0].group_key, { x: 100, y: 100, ring: 0, degree: 0, isCentral: true }],
    ]);
    const { nodes } = graphToLocationView(groups, [], positions, selection);
    expect(nodes[0]).toMatchObject({
      type: "group",
      width: 148,
      height: 52,
    });
  });

  it("creates cluster halos and suppresses labels for dense normal nodes", () => {
    const groups = [group({ node_keys: ["agent", "quiet-1", "quiet-2", "risky"], node_count: 4 })];
    const layout = buildLayout(graph(), groups);
    const { nodes } = graphToConnectionView(graph(), layout, selection);
    expect(nodes.some((item) => item.type === "clusterHalo")).toBe(true);
    expect(nodes.find((item) => item.id === "quiet-1")?.data.showLabel).toBe(false);
    expect(nodes.find((item) => item.id === "quiet-2")?.data.showLabel).toBe(false);
  });

  it("keeps labels visible for important nodes and search matches", () => {
    const groups = [group({ node_keys: ["agent", "quiet-1", "quiet-2", "risky"], node_count: 4 })];
    const layout = buildLayout(graph(), groups);
    const search = {
      matchedNodeKeys: new Set(["quiet-1"]),
      matchedGroupKeys: new Set<string>(),
      activeMatchKey: "quiet-1",
    };
    const { nodes } = graphToConnectionView(graph(), layout, selection, search);
    expect(nodes.find((item) => item.id === "agent")?.data.showLabel).toBe(true);
    expect(nodes.find((item) => item.id === "risky")?.data.showLabel).toBe(true);
    expect(nodes.find((item) => item.id === "quiet-1")?.data.showLabel).toBe(true);
  });
});

describe("TopologyFilterRail", () => {
  it("keeps explicit apply and reset controls while exposing group filtering", () => {
    const markup = renderToStaticMarkup(
      <TopologyFilterRail
        filters={{ ...DEFAULT_TOPOLOGY_FILTERS, group_key: "agent:agent-1" }}
        agentOptions={[]}
        groups={[group({ node_count: 4 })]}
        dirty={true}
        applying={false}
        onChange={() => {}}
        onViewModeChange={() => {}}
        onApply={() => {}}
        onReset={() => {}}
      />,
    );
    expect(markup).toContain("Location / Group");
    expect(markup).toContain("Reset");
    expect(markup).toContain("Apply");
  });
});
