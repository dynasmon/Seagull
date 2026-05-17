import { describe, expect, it } from "vitest";

import {
  computeLocationGroupLayout,
  computeTopologyLayout,
} from "@/features/network_topology/lib/topologyLayoutEngine";
import { graphToConnectionView } from "@/features/network_topology/lib/graphTransform";
import type { DeviceNodeData } from "@/features/network_topology/lib/graphTransform";
import type {
  TopologyEdge,
  TopologyGraph,
  TopologyGroup,
  TopologyGroupEdge,
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

function groupEdge(overrides: Partial<TopologyGroupEdge>): TopologyGroupEdge {
  return {
    edge_key: "group-edge",
    source_group_key: "a",
    target_group_key: "b",
    edge_types: ["observed_flow"],
    weight: 1,
    event_count: 1,
    alert_count: 0,
    severity: "low",
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
      node({ node_key: "agent-b", node_type: "agent", agent_id: "agent-b", label: "agent-b" }),
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
  group({
    group_key: "c",
    label: "Isolated",
    node_count: 1,
  }),
];

const groupEdges = [
  groupEdge({ edge_key: "a-b", source_group_key: "a", target_group_key: "b", weight: 4, event_count: 9 }),
];

describe("topology layout engine", () => {
  it("returns stable positions for the same graph input", () => {
    const first = computeTopologyLayout(graph(), groups, groupEdges);
    const second = computeTopologyLayout(graph(), groups, groupEdges);
    expect(first.nodes.map(({ node_key, x, y }) => ({ node_key, x, y }))).toEqual(
      second.nodes.map(({ node_key, x, y }) => ({ node_key, x, y })),
    );
  });

  it("keeps subnet anchors central and public nodes farther toward the perimeter", () => {
    const layout = computeTopologyLayout(graph(), groups, groupEdges);
    const subnet = layout.nodes.find((item) => item.node_key === "subnet-a");
    const host = layout.nodes.find((item) => item.node_key === "host-a");
    const publicNode = layout.nodes.find((item) => item.node_key === "public-a");
    expect(subnet?.importance).toBe("anchor");
    const area = layout.areas.find((item) => item.group.group_key === "a");
    const hostDistance = Math.hypot((host?.x ?? 0) - (area?.x ?? 0), (host?.y ?? 0) - (area?.y ?? 0));
    const publicDistance = Math.hypot((publicNode?.x ?? 0) - (area?.x ?? 0), (publicNode?.y ?? 0) - (area?.y ?? 0));
    expect(publicDistance).toBeGreaterThan(hostDistance);
  });

  it("uses connectivity to place the primary location at the center and isolated groups farther away", () => {
    const positions = computeLocationGroupLayout(groups, groupEdges);
    expect(positions.get("a")?.isCentral).toBe(true);
    expect(positions.get("a")?.ring).toBe(0);
    expect(positions.get("b")?.ring).toBe(1);
    expect(positions.get("c")?.ring).toBeGreaterThan(1);
  });

  it("no two nodes share the exact same position within a group", () => {
    const layout = computeTopologyLayout(graph(), groups, groupEdges);
    const grouped = layout.nodes.filter((n) => n.group_key !== null);
    const coords = grouped.map((n) => `${n.x},${n.y}`);
    const unique = new Set(coords);
    expect(unique.size).toBe(coords.length);
  });

  it("halo radius is bounded by the maximum", () => {
    const layout = computeTopologyLayout(graph(), groups, groupEdges);
    for (const area of layout.areas) {
      expect(area.radius).toBeGreaterThan(0);
      expect(area.radius).toBeLessThanOrEqual(360);
    }
  });

  it("halo radius is at least the minimum for groups with 5 or more nodes", () => {
    const largeGroup = [
      group({
        group_key: "lg",
        group_type: "subnet",
        node_keys: ["subnet-a", "risk-a", "host-a", "public-a", "agent-b"],
        node_count: 5,
        cidr: "10.0.0.0/24",
        alert_count: 1,
        risk_score: 82,
        highest_severity: "high",
      }),
    ];
    const layout = computeTopologyLayout(graph(), largeGroup, []);
    for (const area of layout.areas) {
      expect(area.radius).toBeGreaterThanOrEqual(110);
    }
  });

  it("a group with more members produces a larger or equal halo area than a single-node group", () => {
    const singleGroup = [group({ group_key: "single", node_keys: ["host-a"], node_count: 1, cidr: null })];
    const denseGroup = [
      group({
        group_key: "dense",
        node_keys: ["subnet-a", "risk-a", "host-a", "public-a", "agent-b"],
        node_count: 5,
        cidr: "10.0.0.0/24",
        highest_severity: "high",
        alert_count: 1,
        risk_score: 82,
      }),
    ];
    const singleLayout = computeTopologyLayout(graph(), singleGroup, []);
    const denseLayout = computeTopologyLayout(graph(), denseGroup, []);
    const singleRadius = singleLayout.areas[0]?.radius ?? 0;
    const denseRadius = denseLayout.areas[0]?.radius ?? 0;
    expect(denseRadius).toBeGreaterThanOrEqual(singleRadius);
  });
});

describe("dense group spacing", () => {
  const now = "2026-05-17T12:00:00.000Z";

  function makeHostNode(key: string): import("@/features/network_topology/types").TopologyNode {
    return node({ node_key: key, label: key, node_type: "host", first_seen_at: now, last_seen_at: now, updated_at: now });
  }

  it("non-anchor nodes in a dense group are not placed closer than 64px to each other", () => {
    const anchor = node({ node_key: "subnet-dense", node_type: "subnet", label: "10.0.1.0/24", cidr: "10.0.1.0/24" });
    const members = Array.from({ length: 12 }, (_, i) => makeHostNode(`h${i}`));
    const denseGraph: import("@/features/network_topology/types").TopologyGraph = {
      nodes: [anchor, ...members],
      edges: [],
      graph_health: { node_count: 13, edge_count: 0, nodes_truncated: false, edges_truncated: false, max_nodes_applied: 350, max_edges_applied: 650 },
    };
    const denseGroup = [group({
      group_key: "dg",
      group_type: "subnet",
      node_keys: [anchor.node_key, ...members.map((n) => n.node_key)],
      node_count: 13,
      cidr: "10.0.1.0/24",
    })];
    const layout = computeTopologyLayout(denseGraph, denseGroup, []);
    const placed = layout.nodes.filter((n) => n.group_key === "dg" && n.importance !== "anchor");
    for (let i = 0; i < placed.length; i++) {
      for (let j = i + 1; j < placed.length; j++) {
        const dist = Math.hypot(placed[i].x - placed[j].x, placed[i].y - placed[j].y);
        expect(dist).toBeGreaterThanOrEqual(64);
      }
    }
  });

  it("a larger dense group spreads nodes farther from center than a small group", () => {
    function maxDistFromCenter(count: number): number {
      const members = Array.from({ length: count }, (_, i) => makeHostNode(`n${i}`));
      const g = group({ group_key: "g", node_keys: members.map((n) => n.node_key), node_count: count });
      const gr: import("@/features/network_topology/types").TopologyGraph = {
        nodes: members,
        edges: [],
        graph_health: { node_count: count, edge_count: 0, nodes_truncated: false, edges_truncated: false, max_nodes_applied: 350, max_edges_applied: 650 },
      };
      const layout = computeTopologyLayout(gr, [g], []);
      const placed = layout.nodes.filter((n) => n.group_key === "g");
      return Math.max(...placed.map((n) => Math.hypot(n.x - 840, n.y - 520)));
    }
    expect(maxDistFromCenter(14)).toBeGreaterThan(maxDistFromCenter(4));
  });
});

describe("label policy in connection view", () => {
  const selNone = { selectedKey: null as string | null, selectedKind: null as "node" | "edge" | "group" | null, highlightedKeys: new Set<string>() };

  it("normal host node does not show label by default", () => {
    const { nodes } = graphToConnectionView(graph(), selNone, undefined, undefined, groups, groupEdges);
    const hostNode = nodes.find((n) => n.type === "device" && n.id === "host-a");
    expect((hostNode?.data as unknown as DeviceNodeData).showLabel).toBe(false);
  });

  it("agent node in a small group shows label", () => {
    const { nodes } = graphToConnectionView(graph(), selNone, undefined, undefined, groups, groupEdges);
    const agentNode = nodes.find((n) => n.type === "device" && n.id === "agent-b");
    expect((agentNode?.data as unknown as DeviceNodeData).showLabel).toBe(true);
  });

  it("selected node always shows label", () => {
    const sel = { selectedKey: "host-a", selectedKind: "node" as const, highlightedKeys: new Set(["host-a"]) };
    const { nodes } = graphToConnectionView(graph(), sel, undefined, undefined, groups, groupEdges);
    const hostNode = nodes.find((n) => n.type === "device" && n.id === "host-a");
    expect((hostNode?.data as unknown as DeviceNodeData).showLabel).toBe(true);
  });

  it("search match node shows label", () => {
    const { nodes } = graphToConnectionView(
      graph(),
      selNone,
      { matchedNodeKeys: new Set(["host-a"]), matchedGroupKeys: new Set(), activeMatchKey: "host-a" },
      undefined,
      groups,
      groupEdges,
    );
    const hostNode = nodes.find((n) => n.type === "device" && n.id === "host-a");
    expect((hostNode?.data as unknown as DeviceNodeData).showLabel).toBe(true);
  });

  it("high severity node with alerts shows label", () => {
    const { nodes } = graphToConnectionView(graph(), selNone, undefined, undefined, groups, groupEdges);
    const riskNode = nodes.find((n) => n.type === "device" && n.id === "risk-a");
    expect((riskNode?.data as unknown as DeviceNodeData).showLabel).toBe(true);
  });
});
