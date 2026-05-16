import { describe, expect, it } from "vitest";

import { buildTopologyGraphPath } from "@/features/network_topology/api";
import { resolveTopologyGraphParams, DEFAULT_TOPOLOGY_FILTERS } from "@/features/network_topology/lib/filters";
import { groupTopologyGraph } from "@/features/network_topology/lib/grouping";
import type {
  TopologyGraph,
  TopologyGroupBackend,
  TopologyGroupEdgeBackend,
} from "@/features/network_topology/types";

const makeNode = (key: string, agentId: string | null = null, overrides: object = {}) => ({
  node_key: key,
  node_type: "host" as const,
  agent_id: agentId,
  label: key,
  ip: "10.0.0.1",
  cidr: null as string | null,
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

const makeEdge = (src: string, tgt: string, edgeType = "observed_flow") => ({
  edge_key: `${src}->${tgt}`,
  source_node_key: src,
  target_node_key: tgt,
  edge_type: edgeType as const,
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

const freshness = {
  generated_at: undefined,
  projected_at: null,
  last_projected_at: null,
  freshness_seconds: null,
  stale: false,
  graph_health: {
    node_count: 0,
    edge_count: 0,
    nodes_truncated: false,
    edges_truncated: false,
    max_nodes_applied: 350,
    max_edges_applied: 650,
  },
};

const backendGroup: TopologyGroupBackend = {
  group_key: "agent:agent-1",
  group_type: "agent",
  label: "Agent One",
  node_count: 2,
  edge_count: 1,
  alert_count: 0,
  highest_severity: "low",
  risk_score: 0,
  confidence: 80,
  is_stale: false,
  first_seen: "2026-01-01T00:00:00Z",
  last_seen: "2026-01-01T00:00:00Z",
  child_node_keys: ["node-1", "node-2"],
  child_node_keys_truncated: false,
  metadata: { agent_id: "agent-1", cidr: null },
};

const backendGroupEdge: TopologyGroupEdgeBackend = {
  edge_key: "agent:agent-1|||agent:agent-2",
  source_group_key: "agent:agent-1",
  target_group_key: "agent:agent-2",
  edge_type: "observed_flow",
  weight: 1.5,
  alert_count: 0,
  confidence: 80,
  highest_severity: "low",
  edge_count: 1,
  first_seen: "2026-01-01T00:00:00Z",
  last_seen: "2026-01-01T00:00:00Z",
  metadata: {},
};

describe("backend groups used when present in graph response", () => {
  it("groupTopologyGraph client-side produces groups from nodes", () => {
    const graph: TopologyGraph = {
      nodes: [makeNode("node-1", "agent-1"), makeNode("node-2", "agent-1")],
      edges: [],
      ...freshness,
    };
    const { groups } = groupTopologyGraph(graph);
    expect(groups.some((g) => g.group_key === "agent:agent-1")).toBe(true);
  });

  it("detects backend groups presence via graph.groups field", () => {
    const graphWithBackendGroups: TopologyGraph = {
      nodes: [makeNode("node-1", "agent-1")],
      edges: [],
      groups: [backendGroup],
      group_edges: [backendGroupEdge],
      group_strategy: "auto",
      ...freshness,
    };
    expect(graphWithBackendGroups.groups?.length).toBe(1);
    expect(graphWithBackendGroups.groups?.[0].group_key).toBe("agent:agent-1");
    expect(graphWithBackendGroups.groups?.[0].child_node_keys).toEqual(["node-1", "node-2"]);
  });

  it("falls back to client-side grouping when graph.groups is absent", () => {
    const graphNoBackend: TopologyGraph = {
      nodes: [makeNode("node-1", "agent-1")],
      edges: [],
      ...freshness,
    };
    expect(graphNoBackend.groups).toBeUndefined();
    const { groups } = groupTopologyGraph(graphNoBackend);
    expect(groups.length).toBeGreaterThan(0);
  });

  it("falls back to client-side grouping when graph.groups is empty array", () => {
    const graphEmptyGroups: TopologyGraph = {
      nodes: [makeNode("node-1", "agent-1")],
      edges: [],
      groups: [],
      group_edges: [],
      ...freshness,
    };
    const { groups } = groupTopologyGraph(graphEmptyGroups);
    expect(groups.length).toBeGreaterThan(0);
  });
});

describe("resolveTopologyGraphParams includes grouping params", () => {
  it("includes view_mode in params", () => {
    const params = resolveTopologyGraphParams({ ...DEFAULT_TOPOLOGY_FILTERS, view_mode: "location" });
    expect(params.view_mode).toBe("location");
  });

  it("sends group_by=auto when view_mode=location", () => {
    const params = resolveTopologyGraphParams({ ...DEFAULT_TOPOLOGY_FILTERS, view_mode: "location" });
    expect(params.group_by).toBe("auto");
  });

  it("does not send group_by when view_mode=connection", () => {
    const params = resolveTopologyGraphParams({ ...DEFAULT_TOPOLOGY_FILTERS, view_mode: "connection" });
    expect(params.group_by).toBeUndefined();
  });

  it("includes focused_group_key when provided via opts", () => {
    const params = resolveTopologyGraphParams(
      { ...DEFAULT_TOPOLOGY_FILTERS, view_mode: "connection" },
      new Date(),
      { focused_group_key: "agent:my-agent" },
    );
    expect(params.focused_group_key).toBe("agent:my-agent");
  });

  it("sets exclusive_focus=true when focused_group_key and connection mode", () => {
    const params = resolveTopologyGraphParams(
      { ...DEFAULT_TOPOLOGY_FILTERS, view_mode: "connection" },
      new Date(),
      { focused_group_key: "agent:my-agent" },
    );
    expect(params.exclusive_focus).toBe(true);
  });

  it("sets exclusive_focus=false when in location mode", () => {
    const params = resolveTopologyGraphParams(
      { ...DEFAULT_TOPOLOGY_FILTERS, view_mode: "location" },
      new Date(),
      { focused_group_key: "agent:my-agent" },
    );
    expect(params.exclusive_focus).toBe(false);
  });

  it("omits focused_group_key and exclusive_focus when no focus key", () => {
    const params = resolveTopologyGraphParams({ ...DEFAULT_TOPOLOGY_FILTERS, view_mode: "connection" });
    expect(params.focused_group_key).toBeUndefined();
    expect(params.exclusive_focus).toBeUndefined();
  });
});

describe("buildTopologyGraphPath includes backend grouping params", () => {
  it("includes view_mode in query string", () => {
    const path = buildTopologyGraphPath({ view_mode: "location" });
    expect(path).toContain("view_mode=location");
  });

  it("includes group_by in query string", () => {
    const path = buildTopologyGraphPath({ group_by: "auto" });
    expect(path).toContain("group_by=auto");
  });

  it("includes focused_group_key in query string", () => {
    const path = buildTopologyGraphPath({ focused_group_key: "agent:abc" });
    expect(path).toContain("focused_group_key=agent%3Aabc");
  });

  it("includes exclusive_focus in query string", () => {
    const path = buildTopologyGraphPath({ exclusive_focus: true });
    expect(path).toContain("exclusive_focus=true");
  });

  it("omits falsy optional params", () => {
    const path = buildTopologyGraphPath({});
    expect(path).not.toContain("view_mode");
    expect(path).not.toContain("group_by");
    expect(path).not.toContain("focused_group_key");
  });
});

describe("facets type structure", () => {
  it("graph with facets has expected fields", () => {
    const graph: TopologyGraph = {
      nodes: [],
      edges: [],
      facets: {
        node_types: { host: 2, agent: 1 },
        edge_types: { observed_flow: 3 },
        severities: { low: 2, unknown: 1 },
        ip_scopes: { private_address: 2 },
        agents: { "agent-1": 2 },
        group_count: 1,
        has_alerts_count: 0,
        stale_count: 0,
        total_nodes: 3,
        total_edges: 3,
      },
      ...freshness,
    };
    expect(graph.facets?.total_nodes).toBe(3);
    expect(graph.facets?.node_types["host"]).toBe(2);
    expect(graph.facets?.group_count).toBe(1);
  });
});
