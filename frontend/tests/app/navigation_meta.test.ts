import { describe, expect, it } from "vitest";

import { resolveRouteMeta, SOC_NAV_GROUPS } from "@/layout/navigation";

describe("shell navigation metadata", () => {
  it("resolves most specific metadata for nested governance routes", () => {
    const audit = resolveRouteMeta("/audit/timeline");
    const internal = resolveRouteMeta("/internal/agents");

    expect(audit.title).toBe("Audit Timeline");
    expect(internal.title).toBe("Internal Agents");
  });

  it("falls back to default metadata for unknown routes", () => {
    const meta = resolveRouteMeta("/does-not-exist");
    expect(meta.title).toBe("Seagull");
  });

  it("keeps governance and assets nav groups available in shell", () => {
    const groupIds = SOC_NAV_GROUPS.map((group) => group.id);
    expect(groupIds).toContain("assets-exposure");
    expect(groupIds).toContain("governance-platform");
  });

  it("registers Network Topology metadata and assets navigation", () => {
    const meta = resolveRouteMeta("/network-topology");
    const assets = SOC_NAV_GROUPS.find((group) => group.id === "assets-exposure");

    expect(meta.title).toBe("Network Topology");
    expect(meta.subtitle).toBe("Internal network map, observed flows, services, and security context.");
    expect(assets?.items.some((item) => item.to === "/network-topology" && item.icon === "network_topology")).toBe(true);
  });
});
