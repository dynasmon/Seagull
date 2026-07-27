import { describe, expect, it } from "vitest";

import { graphToConnectionView } from "@/features/network_topology/lib/graph/graphTransform";
import type { DeviceNodeData } from "@/features/network_topology/lib/graph/graphTransform";
import {
  findLocalAnchor,
  nodeImportance,
  type TopologyLayout,
  type TopologyLayoutNode,
} from "@/features/network_topology/lib/layout/topologyLayout";
import type {
  TopologyEdge,
  TopologyGraph,
  TopologyGroup,
  TopologyNode,
} from "@/features/network_topology/types";

const now = "2026-05-17T12:00:00.000Z";

function node(overrides: Partial<TopologyNode>): TopologyNode {
  return {
    node_key: "node",
    node_type: "host",
    agent_id: null,
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

function edge(overrides: Partial<TopologyEdge>): TopologyEdge {
  return {
    edge_key: "edge",
    source_node_key: "node-a",
    target_node_key: "node-b",
    edge_type: "observed_flow",
    agent_id: null,
    weight: 1,
    confidence: 80,
    severity: "low",
    port: null,
    protocol: null,
    event_count: 1,
    alert_count: 0,
    first_seen_at: now,
    last_seen_at: now,
    updated_at: now,
    metadata: {},
    ...overrides,
  };
}

function group(overrides: Partial<TopologyGroup>): TopologyGroup {
  return {
    group_key: "group",
    group_type: "subnet",
    label: "Group",
    node_keys: [],
    node_count: 0,
    alert_count: 0,
    highest_severity: "low",
    risk_score: 0,
    is_stale: false,
    agent_id: null,
    cidr: null,
    ...overrides,
  };
}

function graph(): TopologyGraph {
  return {
    nodes: [
      node({ node_key: "subnet-a", node_type: "subnet", label: "10.0.0.0/24", cidr: "10.0.0.0/24" }),
      node({ node_key: "risk-a", label: "risk-a", severity: "high", risk_score: 82, alert_count: 1 }),
      node({ node_key: "host-a", label: "host-a" }),
      node({
        node_key: "public-a",
        node_type: "external_ip",
        label: "8.8.8.8",
        ip: "8.8.8.8",
        metadata: { ip_scope: "public_internet" },
      }),
      node({ node_key: "agent-b", node_type: "agent", agent_id: "agent-b", label: "agent-b", event_count: 10 }),
    ],
    edges: [
      edge({ edge_key: "risk-flow", source_node_key: "risk-a", target_node_key: "public-a" }),
      edge({ edge_key: "host-flow", source_node_key: "host-a", target_node_key: "risk-a" }),
    ],
    graph_health: {
      node_count: 5,
      edge_count: 2,
      nodes_truncated: false,
      edges_truncated: false,
      max_nodes_applied: 350,
      max_edges_applied: 650,
    },
  };
}

const groups = [
  group({
    group_key: "a",
    label: "Subnet A",
    node_keys: ["subnet-a", "risk-a", "host-a", "public-a"],
    node_count: 4,
    alert_count: 1,
    risk_score: 82,
    highest_severity: "high",
    cidr: "10.0.0.0/24",
  }),
  group({
    group_key: "b",
    group_type: "agent",
    label: "Agent B",
    node_keys: ["agent-b"],
    node_count: 1,
    agent_id: "agent-b",
  }),
];

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
      w: 320,
      h: 220,
      isCentral: idx === 0,
    })),
  };
}

describe("nodeImportance", () => {
  it("classifies agent, gateway, subnet as anchor", () => {
    expect(nodeImportance(node({ node_key: "a", node_type: "agent" }))).toBe("anchor");
    expect(nodeImportance(node({ node_key: "g", node_type: "gateway" }))).toBe("anchor");
    expect(nodeImportance(node({ node_key: "s", node_type: "subnet" }))).toBe("anchor");
  });

  it("classifies an alerted host as elevated", () => {
    expect(nodeImportance(node({ node_key: "h", alert_count: 1 }))).toBe("elevated");
  });

  it("classifies a high-risk host as elevated", () => {
    expect(nodeImportance(node({ node_key: "h", risk_score: 75 }))).toBe("elevated");
  });

  it("classifies a plain host as normal", () => {
    expect(nodeImportance(node({ node_key: "h" }))).toBe("normal");
  });
});

describe("findLocalAnchor", () => {
  it("picks the live agent with the highest event_count", () => {
    const candidates: TopologyNode[] = [
      node({ node_key: "a1", node_type: "agent", event_count: 4 }),
      node({ node_key: "a2", node_type: "agent", event_count: 20 }),
      node({ node_key: "a3", node_type: "agent", is_stale: true, event_count: 99 }),
      node({ node_key: "h1", node_type: "host", event_count: 999 }),
    ];
    expect(findLocalAnchor(candidates)?.node_key).toBe("a2");
  });

  it("returns null when there are no live agents", () => {
    expect(findLocalAnchor([node({ node_type: "host" })])).toBeNull();
  });
});

describe("label policy in connection view", () => {
  const selNone = {
    selectedKey: null as string | null,
    selectedKind: null as "node" | "edge" | "group" | null,
    highlightedKeys: new Set<string>(),
  };

  it("normal host node shows its label in a group small enough to read", () => {
    const layout = buildLayout(graph(), groups);
    const { nodes } = graphToConnectionView(graph(), layout, selNone);
    const hostNode = nodes.find((n) => n.type === "device" && n.id === "host-a");
    expect((hostNode?.data as unknown as DeviceNodeData).showLabel).toBe(true);
  });

  it("agent node in a small group shows label", () => {
    const layout = buildLayout(graph(), groups);
    const { nodes } = graphToConnectionView(graph(), layout, selNone);
    const agentNode = nodes.find((n) => n.type === "device" && n.id === "agent-b");
    expect((agentNode?.data as unknown as DeviceNodeData).showLabel).toBe(true);
  });

  it("selected node always shows label", () => {
    const layout = buildLayout(graph(), groups);
    const sel = { selectedKey: "host-a", selectedKind: "node" as const, highlightedKeys: new Set(["host-a"]) };
    const { nodes } = graphToConnectionView(graph(), layout, sel);
    const hostNode = nodes.find((n) => n.type === "device" && n.id === "host-a");
    expect((hostNode?.data as unknown as DeviceNodeData).showLabel).toBe(true);
  });

  it("search match node shows label", () => {
    const layout = buildLayout(graph(), groups);
    const { nodes } = graphToConnectionView(
      graph(),
      layout,
      selNone,
      { matchedNodeKeys: new Set(["host-a"]), matchedGroupKeys: new Set(), activeMatchKey: "host-a" },
    );
    const hostNode = nodes.find((n) => n.type === "device" && n.id === "host-a");
    expect((hostNode?.data as unknown as DeviceNodeData).showLabel).toBe(true);
  });

  it("high severity node with alerts shows label", () => {
    const layout = buildLayout(graph(), groups);
    const { nodes } = graphToConnectionView(graph(), layout, selNone);
    const riskNode = nodes.find((n) => n.type === "device" && n.id === "risk-a");
    expect((riskNode?.data as unknown as DeviceNodeData).showLabel).toBe(true);
  });

  it("subnet anchor node shows label in a small group", () => {
    const layout = buildLayout(graph(), groups);
    const { nodes } = graphToConnectionView(graph(), layout, selNone);
    const subnetNode = nodes.find((n) => n.type === "device" && n.id === "subnet-a");
    expect((subnetNode?.data as unknown as DeviceNodeData).showLabel).toBe(true);
  });
});
