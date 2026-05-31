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

  it("exposes the mature SOC nav groups in the shell", () => {
    const groupIds = SOC_NAV_GROUPS.map((group) => group.id);
    expect(groupIds).toEqual([
      "security-overview",
      "alerts-triage",
      "events-hunt",
      "entities",
      "network",
      "exposure-vulnerabilities",
      "investigations-cases",
      "governance-platform",
      "settings",
    ]);
  });

  it("registers Network Topology metadata under the Network nav group", () => {
    const meta = resolveRouteMeta("/network-topology");
    const network = SOC_NAV_GROUPS.find((group) => group.id === "network");

    expect(meta.title).toBe("Network Topology");
    expect(meta.subtitle).toBe("Internal network map, observed flows, services, and security context.");
    expect(network?.items.some((item) => item.to === "/network-topology" && item.icon === "network_topology")).toBe(true);
  });

  it("does not expose DDoS, SSH, or Protocol as primary nav items", () => {
    const targets = SOC_NAV_GROUPS.flatMap((group) => group.items.map((item) => item.to));
    expect(targets).toContain("/events");
    expect(targets).not.toContain("/events/ddos");
    expect(targets).not.toContain("/events/ssh");
    expect(targets).not.toContain("/events/network");
  });
});
