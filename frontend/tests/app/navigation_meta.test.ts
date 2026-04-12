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
    expect(meta.title).toBe("NetWatch");
  });

  it("keeps governance and assets nav groups available in shell", () => {
    const groupIds = SOC_NAV_GROUPS.map((group) => group.id);
    expect(groupIds).toContain("assets-exposure");
    expect(groupIds).toContain("governance-platform");
  });
});

