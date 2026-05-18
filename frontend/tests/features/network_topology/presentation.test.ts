import { describe, expect, it } from "vitest";

import {
  deviceNodeBoundingBox,
  edgePriorityRank,
  edgeRoutingHint,
  groupCardSize,
  groupEdgePriorityRank,
  groupNodeBoundingBox,
  nodeBoundingRadius,
  shouldShowLabel,
} from "@/features/network_topology/lib/presentation";
import type { TopologyEdge } from "@/features/network_topology/types";

function edge(overrides: Partial<Pick<TopologyEdge, "edge_type" | "confidence" | "alert_count">>): Pick<TopologyEdge, "edge_type" | "confidence" | "alert_count"> {
  return { edge_type: "observed_flow", confidence: 80, alert_count: 0, ...overrides };
}

describe("groupCardSize", () => {
  it("returns the minimum width for a short label", () => {
    expect(groupCardSize("A").w).toBe(148);
  });

  it("grows beyond minimum for a longer label", () => {
    const medium = groupCardSize("Internal Network");
    expect(medium.w).toBeGreaterThan(148);
    expect(medium.w).toBeLessThanOrEqual(240);
  });

  it("caps width at maximum for a very long label", () => {
    expect(groupCardSize("Kubernetes Production Cluster Node Network").w).toBe(240);
  });

  it("height is always constant", () => {
    expect(groupCardSize("A").h).toBe(52);
    expect(groupCardSize("Kubernetes Production Cluster Node Network").h).toBe(52);
  });
});

describe("edgePriorityRank", () => {
  it("alert_related ranks highest", () => {
    expect(edgePriorityRank(edge({ edge_type: "alert_related" }))).toBeGreaterThan(
      edgePriorityRank(edge({ edge_type: "exposure_related" })),
    );
  });

  it("exposure_related ranks above listens_on", () => {
    expect(edgePriorityRank(edge({ edge_type: "exposure_related" }))).toBeGreaterThan(
      edgePriorityRank(edge({ edge_type: "listens_on" })),
    );
  });

  it("observed_flow ranks above member_of_subnet", () => {
    expect(edgePriorityRank(edge({ edge_type: "observed_flow" }))).toBeGreaterThan(
      edgePriorityRank(edge({ edge_type: "member_of_subnet" })),
    );
  });

  it("alert_related with alerts ranks above alert_related without", () => {
    expect(edgePriorityRank(edge({ edge_type: "alert_related", alert_count: 5 }))).toBeGreaterThan(
      edgePriorityRank(edge({ edge_type: "alert_related", alert_count: 0 })),
    );
  });

  it("high-confidence observed_flow ranks above low-confidence observed_flow", () => {
    expect(edgePriorityRank(edge({ edge_type: "observed_flow", confidence: 80 }))).toBeGreaterThan(
      edgePriorityRank(edge({ edge_type: "observed_flow", confidence: 30 })),
    );
  });

  it("unknown edge type returns a minimal rank", () => {
    expect(edgePriorityRank(edge({ edge_type: "some_future_type" }))).toBeGreaterThanOrEqual(1);
    expect(edgePriorityRank(edge({ edge_type: "some_future_type" }))).toBeLessThan(
      edgePriorityRank(edge({ edge_type: "observed_flow" })),
    );
  });
});

describe("groupEdgePriorityRank", () => {
  it("alert_count > 0 returns high priority", () => {
    expect(groupEdgePriorityRank(2, ["observed_flow"])).toBeGreaterThan(
      groupEdgePriorityRank(0, ["observed_flow"]),
    );
  });

  it("alert-type edges without alert_count still rank above plain observed flows", () => {
    expect(groupEdgePriorityRank(0, ["alert_related"])).toBeGreaterThan(
      groupEdgePriorityRank(0, ["observed_flow"]),
    );
  });
});

describe("shouldShowLabel", () => {
  const baseNode = { node_type: "host", alert_count: 0, severity: "low" } as const;

  it("returns false for a plain normal host with no alerts", () => {
    expect(shouldShowLabel(baseNode, false, false, "normal", 5)).toBe(false);
  });

  it("returns true when selected", () => {
    expect(shouldShowLabel(baseNode, true, false, "normal", 5)).toBe(true);
  });

  it("returns true when search match", () => {
    expect(shouldShowLabel(baseNode, false, true, "normal", 5)).toBe(true);
  });

  it("returns true for an anchor node in a small group", () => {
    expect(shouldShowLabel({ node_type: "subnet", alert_count: 0, severity: "unknown" }, false, false, "anchor", 4)).toBe(true);
    expect(shouldShowLabel({ node_type: "gateway", alert_count: 0, severity: "unknown" }, false, false, "anchor", 10)).toBe(true);
  });

  it("returns false for an anchor node in a very large group", () => {
    expect(shouldShowLabel({ node_type: "subnet", alert_count: 0, severity: "unknown" }, false, false, "anchor", 30)).toBe(false);
  });

  it("returns true for a high-severity node with alerts", () => {
    expect(shouldShowLabel({ node_type: "host", alert_count: 1, severity: "high" }, false, false, "elevated", 50)).toBe(true);
  });

  it("returns true for a critical-severity node with alerts", () => {
    expect(shouldShowLabel({ node_type: "host", alert_count: 2, severity: "critical" }, false, false, "elevated", 50)).toBe(true);
  });

  it("returns false for an alerted node with only medium severity", () => {
    expect(shouldShowLabel({ node_type: "host", alert_count: 1, severity: "medium" }, false, false, "elevated", 5)).toBe(false);
  });
});

describe("nodeBoundingRadius", () => {
  it("anchor > elevated > normal", () => {
    expect(nodeBoundingRadius("anchor")).toBeGreaterThan(nodeBoundingRadius("elevated"));
    expect(nodeBoundingRadius("elevated")).toBeGreaterThan(nodeBoundingRadius("normal"));
  });
});

describe("edgeRoutingHint", () => {
  it("alert_related has high visual priority", () => {
    expect(edgeRoutingHint(edge({ edge_type: "alert_related" })).visualPriority).toBe("high");
  });

  it("member_of_subnet has low visual priority", () => {
    expect(edgeRoutingHint(edge({ edge_type: "member_of_subnet" })).visualPriority).toBe("low");
  });

  it("alert edges have higher curve strength than low-signal edges", () => {
    const alertHint = edgeRoutingHint(edge({ edge_type: "alert_related" }));
    const flowHint = edgeRoutingHint(edge({ edge_type: "member_of_subnet" }));
    expect(alertHint.curveStrength).toBeGreaterThan(flowHint.curveStrength);
  });
});

describe("bounding box helpers", () => {
  it("groupNodeBoundingBox is centered on given coordinates", () => {
    const box = groupNodeBoundingBox(100, 200, "Short");
    expect(box.x + box.w / 2).toBeCloseTo(100);
    expect(box.y + box.h / 2).toBeCloseTo(200);
  });

  it("deviceNodeBoundingBox is centered on given coordinates", () => {
    const box = deviceNodeBoundingBox(50, 80, "elevated");
    expect(box.x + box.w / 2).toBe(50);
    expect(box.y + box.h / 2).toBe(80);
  });

  it("anchor device bounding box is larger than normal", () => {
    const anchor = deviceNodeBoundingBox(0, 0, "anchor");
    const normal = deviceNodeBoundingBox(0, 0, "normal");
    expect(anchor.w).toBeGreaterThan(normal.w);
  });
});
