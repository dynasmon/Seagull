import { describe, expect, it } from "vitest";

import {
  DEFAULT_TOPOLOGY_FILTERS,
  filterTopologyGraph,
  parseTopologyFilters,
  resolveTopologyGraphParams,
  serializeTopologyFilters,
} from "@/features/network_topology/lib/filters";
import type { TopologyGraph } from "@/features/network_topology/types";

describe("network topology filter serialization", () => {
  it("round-trips URL filters using new plural params and omits defaults", () => {
    const filters = parseTopologyFilters(
      new URLSearchParams(
        "agent=agent-1&window=60&node_types=host&edge_types=observed_flow&ip_scopes=private_address&min_confidence=55&severities=high&q=ssh",
      ),
    );

    expect(filters).toMatchObject({
      agent_id: "agent-1",
      window_minutes: 60,
      node_types: ["host"],
      edge_types: ["observed_flow"],
      ip_scopes: ["private_address"],
      min_confidence: 55,
      severities: ["high"],
      q: "ssh",
    });
    expect(serializeTopologyFilters(filters).toString()).toBe(
      "agent=agent-1&window=60&node_types=host&edge_types=observed_flow&ip_scopes=private_address&min_confidence=55&severities=high&q=ssh",
    );
    expect(serializeTopologyFilters(DEFAULT_TOPOLOGY_FILTERS).toString()).toBe("");
  });

  it("round-trips location group filters through the URL", () => {
    const filters = parseTopologyFilters(new URLSearchParams("group=agent%3Aagent-1"));
    expect(filters.group_key).toBe("agent:agent-1");
    expect(serializeTopologyFilters(filters).toString()).toBe("group=agent%3Aagent-1");
  });

  it("parses legacy single-value URL params for backward compatibility", () => {
    const filters = parseTopologyFilters(
      new URLSearchParams(
        "agent=agent-2&node_type=host&edge_type=observed_flow&ip_scope=private_address&severity=high",
      ),
    );

    expect(filters).toMatchObject({
      agent_id: "agent-2",
      node_types: ["host"],
      edge_types: ["observed_flow"],
      ip_scopes: ["private_address"],
      severities: ["high"],
    });
  });

  it("parses multiple values per filter from repeated params", () => {
    const filters = parseTopologyFilters(
      new URLSearchParams("node_types=host&node_types=service&severities=critical&severities=high"),
    );

    expect(filters.node_types).toEqual(["host", "service"]);
    expect(filters.severities).toEqual(["critical", "high"]);
  });

  it("parses view_mode, boolean flags, and window", () => {
    const filters = parseTopologyFilters(
      new URLSearchParams("mode=connection&include_stale=1&has_alerts=1&has_exposure=1&window=360"),
    );

    expect(filters.view_mode).toBe("connection");
    expect(filters.include_stale).toBe(true);
    expect(filters.has_alerts).toBe(true);
    expect(filters.has_exposure).toBe(true);
    expect(filters.window_minutes).toBe(360);
  });

  it("converts time window filters into backend graph bounds", () => {
    const params = resolveTopologyGraphParams(
      { ...DEFAULT_TOPOLOGY_FILTERS, window_minutes: 60, agent_id: "agent-7", node_types: ["service"] },
      new Date("2026-05-12T12:00:00.000Z"),
    );

    expect(params).toMatchObject({
      agent_id: "agent-7",
      node_types: ["service"],
      min_confidence: 30,
      since: "2026-05-12T11:00:00.000Z",
      until: "2026-05-12T12:00:00.000Z",
    });
  });

  it("keeps group filtering scoped to the selected location", () => {
    const graph: TopologyGraph = {
      nodes: [
        {
          node_key: "inside",
          node_type: "host",
          agent_id: "agent-1",
          label: "inside",
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
          first_seen_at: "2026-05-17T12:00:00.000Z",
          last_seen_at: "2026-05-17T12:00:00.000Z",
          updated_at: "2026-05-17T12:00:00.000Z",
          metadata: {},
        },
        {
          node_key: "outside",
          node_type: "host",
          agent_id: "agent-2",
          label: "outside",
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
          first_seen_at: "2026-05-17T12:00:00.000Z",
          last_seen_at: "2026-05-17T12:00:00.000Z",
          updated_at: "2026-05-17T12:00:00.000Z",
          metadata: {},
        },
      ],
      edges: [
        {
          edge_key: "inside-outside",
          source_node_key: "inside",
          target_node_key: "outside",
          edge_type: "observed_flow",
          agent_id: null,
          weight: 1,
          confidence: 80,
          severity: "low",
          port: null,
          protocol: null,
          event_count: 1,
          alert_count: 0,
          first_seen_at: "2026-05-17T12:00:00.000Z",
          last_seen_at: "2026-05-17T12:00:00.000Z",
          updated_at: "2026-05-17T12:00:00.000Z",
          metadata: {},
        },
      ],
      groups: [
        {
          group_key: "agent:agent-1",
          group_type: "agent",
          label: "Agent 1",
          node_count: 1,
          edge_count: 0,
          alert_count: 0,
          highest_severity: "low",
          risk_score: 0,
          confidence: 80,
          is_stale: false,
          first_seen: null,
          last_seen: null,
          child_node_keys: ["inside"],
          child_node_keys_truncated: false,
          metadata: { agent_id: "agent-1" },
        },
        {
          group_key: "agent:agent-2",
          group_type: "agent",
          label: "Agent 2",
          node_count: 1,
          edge_count: 0,
          alert_count: 0,
          highest_severity: "low",
          risk_score: 0,
          confidence: 80,
          is_stale: false,
          first_seen: null,
          last_seen: null,
          child_node_keys: ["outside"],
          child_node_keys_truncated: false,
          metadata: { agent_id: "agent-2" },
        },
      ],
      graph_health: {
        node_count: 2,
        edge_count: 1,
        nodes_truncated: false,
        edges_truncated: false,
        max_nodes_applied: 350,
        max_edges_applied: 650,
      },
    };
    const filtered = filterTopologyGraph(graph, {
      ...DEFAULT_TOPOLOGY_FILTERS,
      group_key: "agent:agent-1",
    });
    expect(filtered?.nodes.map((node) => node.node_key)).toEqual(["inside"]);
    expect(filtered?.edges).toHaveLength(0);
    expect(filtered?.groups?.map((group) => group.group_key)).toEqual(["agent:agent-1"]);
  });
});
