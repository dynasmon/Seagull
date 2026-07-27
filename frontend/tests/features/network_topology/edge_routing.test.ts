import { describe, expect, it } from "vitest";

import {
  BUNDLE_EDGE_PREFIX,
  graphToConnectionView,
  type TopologyBundleEdgeData,
  type TopologyEdgeData,
} from "@/features/network_topology/lib/graph/graphTransform";
import {
  anchorDistance,
  bowAroundObstacles,
  bowControlPoint,
  circleAnchor,
  rectAnchor,
  trimToBorders,
  type Obstacle,
} from "@/features/network_topology/lib/layout/edgeAnchors";
import {
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

const now = "2026-07-27T12:00:00.000Z";

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

const selNone = {
  selectedKey: null as string | null,
  selectedKind: null as "node" | "edge" | "group" | null,
  highlightedKeys: new Set<string>(),
};

/** Two groups side by side, each with one member, joined by cross-group edges. */
function twoRegionScene(edges: TopologyEdge[]): { graph: TopologyGraph; layout: TopologyLayout } {
  const nodes = [
    node({ node_key: "left", label: "left", agent_id: "a1" }),
    node({ node_key: "right", label: "right", node_type: "external_ip" }),
  ];
  const groups = [
    group({ group_key: "g-left", group_type: "agent", label: "Left", node_keys: ["left"], node_count: 1 }),
    group({ group_key: "g-right", group_type: "scope", label: "Right", node_keys: ["right"], node_count: 1 }),
  ];
  const layoutNodes: TopologyLayoutNode[] = [
    { ...nodes[0], x: 100, y: 100, radius: 17, group_key: "g-left", importance: nodeImportance(nodes[0]) },
    { ...nodes[1], x: 700, y: 100, radius: 17, group_key: "g-right", importance: nodeImportance(nodes[1]) },
  ];
  const byKey = new Map(layoutNodes.map((n) => [n.node_key, n]));
  const graph: TopologyGraph = {
    nodes,
    edges,
    graph_health: {
      node_count: 2,
      edge_count: edges.length,
      nodes_truncated: false,
      edges_truncated: false,
      max_nodes_applied: 350,
      max_edges_applied: 650,
    },
  };
  return {
    graph,
    layout: {
      width: 900,
      height: 300,
      nodes: layoutNodes,
      edges: edges.map((e) => ({
        ...e,
        source: byKey.get(e.source_node_key) ?? null,
        target: byKey.get(e.target_node_key) ?? null,
      })),
      areas: [
        { group: groups[0], x: 20, y: 20, w: 200, h: 200, isCentral: true },
        { group: groups[1], x: 600, y: 20, w: 200, h: 200, isCentral: false },
      ],
    },
  };
}

describe("anchorDistance", () => {
  it("returns the radius for a circle whatever the direction", () => {
    expect(anchorDistance(circleAnchor(17), 1, 0)).toBe(17);
    expect(anchorDistance(circleAnchor(17), 0.6, 0.8)).toBe(17);
  });

  it("returns the horizontal half-width for a rect crossed sideways", () => {
    expect(anchorDistance(rectAnchor(200, 100), 1, 0)).toBe(100);
  });

  it("returns the vertical half-height for a rect crossed from above", () => {
    expect(anchorDistance(rectAnchor(200, 100), 0, 1)).toBe(50);
  });
});

describe("trimToBorders", () => {
  it("starts the link on the source border rather than at its centre", () => {
    const trimmed = trimToBorders({ x: 0, y: 0 }, { x: 400, y: 0 }, rectAnchor(200, 100), circleAnchor(20));
    expect(trimmed.source.x).toBeCloseTo(100);
    expect(trimmed.target.x).toBeCloseTo(380);
  });

  it("never inverts the segment when the shapes nearly touch", () => {
    const trimmed = trimToBorders({ x: 0, y: 0 }, { x: 30, y: 0 }, rectAnchor(200, 100), rectAnchor(200, 100));
    expect(trimmed.source.x).toBeLessThanOrEqual(trimmed.target.x);
  });
});

describe("bowAroundObstacles", () => {
  const between: Obstacle[] = [{ x: 250, y: 60, w: 200, h: 120 }];

  it("keeps a clear link straight", () => {
    expect(bowAroundObstacles({ x: 0, y: 400 }, { x: 700, y: 400 }, between)).toBe(0);
  });

  it("bows a link that would cut through a box in between", () => {
    expect(bowAroundObstacles({ x: 0, y: 120 }, { x: 700, y: 120 }, between)).not.toBe(0);
  });

  it("bows far enough that the curve clears the obstacle", () => {
    const source = { x: 0, y: 120 };
    const target = { x: 700, y: 120 };
    const bow = bowAroundObstacles(source, target, between);
    const control = bowControlPoint(source, target, bow);
    for (let step = 1; step < 16; step += 1) {
      const t = step / 16;
      const inv = 1 - t;
      const x = inv * inv * source.x + 2 * inv * t * control.x + t * t * target.x;
      const y = inv * inv * source.y + 2 * inv * t * control.y + t * t * target.y;
      const inside =
        x >= between[0].x && x <= between[0].x + between[0].w &&
        y >= between[0].y && y <= between[0].y + between[0].h;
      expect(inside).toBe(false);
    }
  });

  it("is deterministic", () => {
    const first = bowAroundObstacles({ x: 0, y: 120 }, { x: 700, y: 120 }, between);
    const second = bowAroundObstacles({ x: 0, y: 120 }, { x: 700, y: 120 }, between);
    expect(second).toBe(first);
  });
});

describe("cross-group edge bundling", () => {
  const flows = Array.from({ length: 6 }, (_, i) =>
    edge({ edge_key: `flow-${i}`, source_node_key: "left", target_node_key: "right", edge_type: "observed_flow", event_count: i + 1 }),
  );

  it("collapses plain cross-group traffic into one link between the two regions", () => {
    const { graph, layout } = twoRegionScene(flows);
    const { edges } = graphToConnectionView(graph, layout, selNone);
    expect(edges).toHaveLength(1);
    expect(edges[0].id.startsWith(BUNDLE_EDGE_PREFIX)).toBe(true);
    expect(edges[0].source).toBe("halo:g-left");
    expect(edges[0].target).toBe("halo:g-right");
  });

  it("carries the aggregated counts on the bundle", () => {
    const { graph, layout } = twoRegionScene(flows);
    const { edges } = graphToConnectionView(graph, layout, selNone);
    const { bundle } = edges[0].data as unknown as TopologyBundleEdgeData;
    expect(bundle.linkCount).toBe(flows.length);
    expect(bundle.eventCount).toBe(flows.reduce((sum, f) => sum + f.event_count, 0));
    expect(bundle.dominantType).toBe("observed_flow");
  });

  it("never hides an alert or exposure link inside a bundle", () => {
    const { graph, layout } = twoRegionScene([
      ...flows,
      edge({ edge_key: "alerting", source_node_key: "left", target_node_key: "right", edge_type: "alert_related", alert_count: 2 }),
    ]);
    const { edges } = graphToConnectionView(graph, layout, selNone);
    const alerting = edges.find((e) => e.id === "alerting");
    expect(alerting).toBeTruthy();
    expect((alerting!.data as unknown as TopologyEdgeData).edge.edge_type).toBe("alert_related");
  });

  it("expands a bundle back into its individual links on request", () => {
    const { graph, layout } = twoRegionScene(flows);
    const { edges } = graphToConnectionView(
      graph,
      layout,
      selNone,
      undefined,
      undefined,
      undefined,
      0,
      new Set(["g-left|||g-right"]),
    );
    expect(edges.every((e) => !e.id.startsWith(BUNDLE_EDGE_PREFIX))).toBe(true);
    expect(edges.length).toBeGreaterThan(0);
  });

  it("leaves links inside a single group alone", () => {
    const nodes = [node({ node_key: "a", agent_id: "a1" }), node({ node_key: "b", agent_id: "a1" })];
    const only = group({ group_key: "g", group_type: "agent", node_keys: ["a", "b"], node_count: 2 });
    const layoutNodes: TopologyLayoutNode[] = nodes.map((n, i) => ({
      ...n,
      x: 100 + i * 120,
      y: 100,
      radius: 17,
      group_key: "g",
      importance: nodeImportance(n),
    }));
    const edges = [edge({ edge_key: "inside", source_node_key: "a", target_node_key: "b" })];
    const byKey = new Map(layoutNodes.map((n) => [n.node_key, n]));
    const view = graphToConnectionView(
      {
        nodes,
        edges,
        graph_health: {
          node_count: 2,
          edge_count: 1,
          nodes_truncated: false,
          edges_truncated: false,
          max_nodes_applied: 350,
          max_edges_applied: 650,
        },
      },
      {
        width: 400,
        height: 300,
        nodes: layoutNodes,
        edges: edges.map((e) => ({
          ...e,
          source: byKey.get(e.source_node_key) ?? null,
          target: byKey.get(e.target_node_key) ?? null,
        })),
        areas: [{ group: only, x: 20, y: 20, w: 360, h: 260, isCentral: true }],
      },
      selNone,
    );
    expect(view.edges).toHaveLength(1);
    expect(view.edges[0].id).toBe("inside");
  });

  it("anchors every link on a shape so it starts outside its endpoint", () => {
    const { graph, layout } = twoRegionScene(flows);
    const { edges } = graphToConnectionView(graph, layout, selNone);
    const data = edges[0].data as unknown as TopologyBundleEdgeData;
    expect(data.sourceShape.kind).toBe("rect");
    expect(data.targetShape.kind).toBe("rect");
  });
});
