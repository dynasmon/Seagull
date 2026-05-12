import { describe, expect, it } from "vitest";

import {
  DEFAULT_TOPOLOGY_FILTERS,
  parseTopologyFilters,
  resolveTopologyGraphParams,
  serializeTopologyFilters,
} from "@/features/network_topology/lib/filters";

describe("network topology filter serialization", () => {
  it("round-trips URL filters and omits defaults", () => {
    const filters = parseTopologyFilters(
      new URLSearchParams("agent=agent-1&window=60&node_type=host&edge_type=observed_flow&ip_scope=private_address&min_confidence=55&severity=high&q=ssh"),
    );

    expect(filters).toMatchObject({
      agent_id: "agent-1",
      window_minutes: 60,
      node_type: "host",
      edge_type: "observed_flow",
      ip_scope: "private_address",
      min_confidence: 55,
      severity: "high",
      q: "ssh",
    });
    expect(serializeTopologyFilters(filters).toString()).toBe(
      "agent=agent-1&window=60&node_type=host&edge_type=observed_flow&ip_scope=private_address&min_confidence=55&severity=high&q=ssh",
    );
    expect(serializeTopologyFilters(DEFAULT_TOPOLOGY_FILTERS).toString()).toBe("");
  });

  it("converts time window filters into backend graph bounds", () => {
    const params = resolveTopologyGraphParams(
      { ...DEFAULT_TOPOLOGY_FILTERS, window_minutes: 60, agent_id: "agent-7", node_type: "service" },
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
});
