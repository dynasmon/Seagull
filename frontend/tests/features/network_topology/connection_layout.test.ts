import { describe, expect, it } from "vitest";

import { graphToConnectionView } from "@/features/network_topology/lib/graphTransform";
import {
  REPRESENTATIVE_LIMIT,
  type Rect,
  pointInRect,
  rectsOverlap,
  regionContainsMember,
} from "@/features/network_topology/lib/layoutContainment";
import {
  AGGREGATE_NODE_PREFIX,
  buildConnectionLayout,
  type TopologyLayoutArea,
} from "@/features/network_topology/lib/topologyLayout";
import type { TopologyEdge, TopologyGraph, TopologyGroup, TopologyNode } from "@/features/network_topology/types";

const now = "2026-05-24T12:00:00.000Z";

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
    source_node_key: "a",
    target_node_key: "b",
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

const GRAPH_HEALTH = {
  node_count: 0,
  edge_count: 0,
  nodes_truncated: false,
  edges_truncated: false,
  max_nodes_applied: 350,
  max_edges_applied: 650,
};

function smallGraph(): TopologyGraph {
  return {
    nodes: [
      node({ node_key: "agent-1", node_type: "agent", agent_id: "a1", label: "web-01", event_count: 25 }),
      node({ node_key: "host-1", agent_id: "a1", label: "host-1" }),
      node({ node_key: "svc-1", node_type: "service", agent_id: "a1", label: "nginx" }),
      node({ node_key: "subnet-1", node_type: "subnet", label: "10.0.0.0/24", cidr: "10.0.0.0/24" }),
      node({ node_key: "host-3", label: "host-3", severity: "high", risk_score: 82, alert_count: 2 }),
      node({ node_key: "pub-1", node_type: "external_ip", label: "8.8.8.8", metadata: { ip_scope: "public_internet" } }),
      node({ node_key: "orphan-1", label: "orphan-1" }),
    ],
    edges: [edge({ edge_key: "e1", source_node_key: "agent-1", target_node_key: "host-1" })],
    graph_health: { ...GRAPH_HEALTH, node_count: 7 },
  };
}

const smallGroups: TopologyGroup[] = [
  group({ group_key: "agent:a1", group_type: "agent", label: "web-01", agent_id: "a1", node_keys: ["agent-1", "host-1", "svc-1"], node_count: 3 }),
  group({ group_key: "subnet:10.0.0.0/24", group_type: "subnet", label: "10.0.0.0/24", cidr: "10.0.0.0/24", node_keys: ["subnet-1", "host-3"], node_count: 2, alert_count: 2 }),
  group({ group_key: "scope:public_internet", group_type: "scope", label: "Public Internet", node_keys: ["pub-1"], node_count: 1 }),
];

function denseGraph(hostCount: number): { graph: TopologyGraph; groups: TopologyGroup[] } {
  const hosts = Array.from({ length: hostCount }, (_, i) => node({ node_key: `host-${i}`, agent_id: "a1", label: `host-${i}` }));
  const nodes = [
    node({ node_key: "agent-1", node_type: "agent", agent_id: "a1", label: "web-01", event_count: 25 }),
    node({ node_key: "alerted", agent_id: "a1", label: "alerted", severity: "high", alert_count: 3 }),
    ...hosts,
  ];
  return {
    graph: {
      nodes,
      edges: [
        edge({ edge_key: "e-alert", source_node_key: "alerted", target_node_key: "agent-1" }),
        edge({ edge_key: "e-hidden", source_node_key: "host-29", target_node_key: "agent-1" }),
      ],
      graph_health: { ...GRAPH_HEALTH, node_count: nodes.length },
    },
    groups: [
      group({ group_key: "agent:a1", group_type: "agent", label: "web-01", agent_id: "a1", node_keys: nodes.map((n) => n.node_key), node_count: nodes.length }),
    ],
  };
}

function areaRect(area: TopologyLayoutArea): Rect {
  return { x: area.x, y: area.y, w: area.w, h: area.h };
}

describe("buildConnectionLayout containment (radial)", () => {
  it("places every rendered node fully inside its own group region", () => {
    const layout = buildConnectionLayout(smallGraph(), smallGroups);
    const areaByGroup = new Map(layout.areas.map((a) => [a.group.group_key, a]));
    for (const ln of layout.nodes) {
      const area = areaByGroup.get(ln.group_key ?? "");
      expect(area, `area for ${ln.node_key}`).toBeTruthy();
      expect(regionContainsMember(areaRect(area!), { x: ln.x, y: ln.y })).toBe(true);
    }
  });

  it("never lets a node fall inside another group's region", () => {
    const layout = buildConnectionLayout(smallGraph(), smallGroups);
    for (const ln of layout.nodes) {
      for (const area of layout.areas) {
        const inside = pointInRect(ln.x, ln.y, areaRect(area));
        if (area.group.group_key === ln.group_key) expect(inside).toBe(true);
        else expect(inside, `${ln.node_key} vs ${area.group.group_key}`).toBe(false);
      }
    }
  });

  it("never overlaps two group regions", () => {
    const { areas } = buildConnectionLayout(smallGraph(), smallGroups);
    for (let i = 0; i < areas.length; i += 1) {
      for (let j = i + 1; j < areas.length; j += 1) {
        expect(rectsOverlap(areaRect(areas[i]), areaRect(areas[j]))).toBe(false);
      }
    }
  });

  it("marks the live-agent group as the central region", () => {
    const { areas } = buildConnectionLayout(smallGraph(), smallGroups);
    const central = areas.filter((a) => a.isCentral);
    expect(central).toHaveLength(1);
    expect(central[0].group.group_key).toBe("agent:a1");
  });

  it("collects ungrouped nodes into a deliberate Unassigned region", () => {
    const layout = buildConnectionLayout(smallGraph(), smallGroups);
    const orphan = layout.nodes.find((n) => n.node_key === "orphan-1");
    expect(orphan?.group_key).toBe("__unassigned__");
    expect(layout.areas.find((a) => a.group.group_key === "__unassigned__")?.group.label).toBe("Unassigned");
  });

  it("is deterministic across runs", () => {
    const a = buildConnectionLayout(smallGraph(), smallGroups);
    const b = buildConnectionLayout(smallGraph(), smallGroups);
    const posA = a.nodes.map((n) => `${n.node_key}:${n.x},${n.y}`).sort();
    const posB = b.nodes.map((n) => `${n.node_key}:${n.x},${n.y}`).sort();
    expect(posB).toEqual(posA);
  });

  it("returns an empty layout for an empty graph", () => {
    const layout = buildConnectionLayout({ ...smallGraph(), nodes: [], edges: [] }, smallGroups);
    expect(layout.nodes).toHaveLength(0);
    expect(layout.areas).toHaveLength(0);
  });
});

describe("buildConnectionLayout density aggregation", () => {
  it("does not dump every node as a rigid full set for a dense group", () => {
    const { graph, groups } = denseGraph(30);
    const layout = buildConnectionLayout(graph, groups);
    const individual = layout.nodes.filter((n) => !n.node_key.startsWith(AGGREGATE_NODE_PREFIX));
    expect(individual.length).toBeLessThan(graph.nodes.length);
  });

  it("emits a single aggregate node carrying the hidden count", () => {
    const { graph, groups } = denseGraph(30);
    const layout = buildConnectionLayout(graph, groups);
    const aggregates = layout.nodes.filter((n) => n.node_key.startsWith(AGGREGATE_NODE_PREFIX));
    expect(aggregates).toHaveLength(1);
    const shownIndividual = 2 + REPRESENTATIVE_LIMIT;
    expect(Number(aggregates[0].metadata._aggregate_count)).toBe(graph.nodes.length - shownIndividual);
  });

  it("always keeps the anchor and alerted nodes individually visible", () => {
    const { graph, groups } = denseGraph(30);
    const layout = buildConnectionLayout(graph, groups);
    const keys = new Set(layout.nodes.map((n) => n.node_key));
    expect(keys.has("agent-1")).toBe(true);
    expect(keys.has("alerted")).toBe(true);
  });

  it("prunes edges that point at aggregated nodes but keeps edges between shown nodes", () => {
    const { graph, groups } = denseGraph(30);
    const layout = buildConnectionLayout(graph, groups);
    const edgeKeys = new Set(layout.edges.map((e) => e.edge_key));
    expect(edgeKeys.has("e-alert")).toBe(true);
    expect(edgeKeys.has("e-hidden")).toBe(false);
  });

  it("expands the focused group so every node is shown individually", () => {
    const { graph, groups } = denseGraph(30);
    const layout = buildConnectionLayout(graph, groups, "agent:a1");
    const aggregates = layout.nodes.filter((n) => n.node_key.startsWith(AGGREGATE_NODE_PREFIX));
    expect(aggregates).toHaveLength(0);
    expect(layout.nodes).toHaveLength(graph.nodes.length);
  });
});

describe("connection view edge aggregation", () => {
  const selNone = {
    selectedKey: null as string | null,
    selectedKind: null as "node" | "edge" | "group" | null,
    highlightedKeys: new Set<string>(),
  };

  function pairGraph(): TopologyGraph {
    return {
      nodes: [node({ node_key: "a", label: "a", node_type: "agent", agent_id: "a1" }), node({ node_key: "b", label: "b" })],
      edges: [
        edge({ edge_key: "flow-weak", source_node_key: "a", target_node_key: "b", edge_type: "observed_flow", confidence: 30 }),
        edge({ edge_key: "flow-strong", source_node_key: "a", target_node_key: "b", edge_type: "observed_flow", confidence: 90 }),
        edge({ edge_key: "alert", source_node_key: "a", target_node_key: "b", edge_type: "alert_related", alert_count: 1 }),
      ],
      graph_health: { ...GRAPH_HEALTH, node_count: 2 },
    };
  }

  const pairGroups: TopologyGroup[] = [
    group({ group_key: "g", group_type: "agent", label: "Pair", agent_id: "a1", node_keys: ["a", "b"], node_count: 2 }),
  ];

  it("collapses repeated same-type edges to one representative per type", () => {
    const graph = pairGraph();
    const layout = buildConnectionLayout(graph, pairGroups);
    const { edges } = graphToConnectionView(graph, layout, selNone);
    expect(edges).toHaveLength(2);
    const types = edges.map((e) => (e.data as { edge: TopologyEdge }).edge.edge_type).sort();
    expect(types).toEqual(["alert_related", "observed_flow"]);
  });

  it("keeps the higher-priority edge as the representative for a bundled type", () => {
    const graph = pairGraph();
    const layout = buildConnectionLayout(graph, pairGroups);
    const { edges } = graphToConnectionView(graph, layout, selNone);
    const flow = edges.find((e) => (e.data as { edge: TopologyEdge }).edge.edge_type === "observed_flow");
    expect(flow?.id).toBe("flow-strong");
  });
});
