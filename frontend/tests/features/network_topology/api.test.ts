import { describe, expect, it } from "vitest";

import {
  buildTopologyGraphPath,
  buildTopologyObservationsPath,
  buildTopologySubnetsPath,
} from "@/features/network_topology/api";

describe("network topology API URL builders", () => {
  it("builds graph query params with repeated type filters", () => {
    const path = buildTopologyGraphPath({
      max_nodes: 100,
      max_edges: 200,
      min_confidence: 40,
      agent_id: "agent-1",
      node_types: ["host", "service"],
      edge_types: ["observed_flow"],
      ip_scope: "internal_network",
      since: "2026-05-12T10:00:00.000Z",
      until: "2026-05-12T11:00:00.000Z",
      include_stale: false,
    });

    expect(path).toBe(
      "/api/network-topology/graph?max_nodes=100&max_edges=200&min_confidence=40&agent_id=agent-1&node_types=host&node_types=service&edge_types=observed_flow&ip_scope=internal_network&since=2026-05-12T10%3A00%3A00.000Z&until=2026-05-12T11%3A00%3A00.000Z&include_stale=false",
    );
  });

  it("builds subnets and observations URLs with stable defaults", () => {
    expect(buildTopologySubnetsPath({ agent_id: "agent-2" })).toBe(
      "/api/network-topology/subnets?page_size=50&agent_id=agent-2",
    );
    expect(buildTopologyObservationsPath({ node_key: "topo:host:agent-1:10.0.0.5", source_type: "flow" })).toBe(
      "/api/network-topology/observations?page_size=50&node_key=topo%3Ahost%3Aagent-1%3A10.0.0.5&source_type=flow",
    );
  });
});
