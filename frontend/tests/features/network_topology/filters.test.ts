import { describe, expect, it } from "vitest";

import {
  DEFAULT_TOPOLOGY_FILTERS,
  parseTopologyFilters,
  resolveTopologyGraphParams,
  serializeTopologyFilters,
} from "@/features/network_topology/lib/filters";

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
});
