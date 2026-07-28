import { describe, expect, it } from "vitest";

import {
  MARKER_FOOTPRINT,
  REGION_HEADER,
  REPRESENTATIVE_LIMIT,
  SMALL_GROUP_LIMIT,
  type ClusterMember,
  type ClusterSatellite,
  type Rect,
  type RegionInput,
  arrangeGroupCluster,
  classifyGroupMembers,
  packRegions,
  pointInRect,
  rectsOverlap,
  regionContainsMember,
} from "@/features/network_topology/lib/layout/layoutContainment";

function member(key: string, overrides: Partial<ClusterMember> = {}): ClusterMember {
  return { key, importance: "normal", risk_score: 0, alert_count: 0, alwaysShow: false, ...overrides };
}

function satellite(key: string, overrides: Partial<ClusterSatellite> = {}): ClusterSatellite {
  return { key, importance: "normal", risk_score: 0, alert_count: 0, isAggregate: false, ...overrides };
}

describe("classifyGroupMembers density aggregation", () => {
  it("shows every member for a small group", () => {
    const members = Array.from({ length: SMALL_GROUP_LIMIT }, (_, i) => member(`n-${i}`));
    const result = classifyGroupMembers(members, false);
    expect(result.aggregatedCount).toBe(0);
    expect(result.shownKeys.size).toBe(SMALL_GROUP_LIMIT);
  });

  it("aggregates low-signal nodes beyond the representative limit in a dense group", () => {
    const members = [
      member("anchor", { importance: "anchor", alwaysShow: true }),
      member("alerted", { importance: "elevated", alert_count: 3, alwaysShow: true }),
      ...Array.from({ length: 30 }, (_, i) => member(`host-${i}`)),
    ];
    const result = classifyGroupMembers(members, false);
    expect(result.aggregatedCount).toBe(30 - REPRESENTATIVE_LIMIT);
    expect(result.shownKeys.has("anchor")).toBe(true);
    expect(result.shownKeys.has("alerted")).toBe(true);
    expect(result.shownKeys.size).toBe(2 + REPRESENTATIVE_LIMIT);
  });

  it("never aggregates an always-show node", () => {
    const members = [
      member("anchor", { importance: "anchor", alwaysShow: true }),
      ...Array.from({ length: 40 }, (_, i) => member(`host-${i}`, { alert_count: i === 0 ? 5 : 0, alwaysShow: i === 0 })),
    ];
    const result = classifyGroupMembers(members, false);
    expect(result.aggregatedKeys).not.toContain("anchor");
    expect(result.aggregatedKeys).not.toContain("host-0");
  });

  it("expands fully when the group is focused", () => {
    const members = Array.from({ length: 40 }, (_, i) => member(`n-${i}`));
    const result = classifyGroupMembers(members, true);
    expect(result.aggregatedCount).toBe(0);
    expect(result.shownKeys.size).toBe(40);
  });

  it("keeps the riskiest low-signal nodes as representatives", () => {
    const members = [
      member("hot", { risk_score: 90 }),
      ...Array.from({ length: 20 }, (_, i) => member(`cold-${i}`, { risk_score: 1 })),
    ];
    const result = classifyGroupMembers(members, false);
    expect(result.shownKeys.has("hot")).toBe(true);
  });
});

describe("arrangeGroupCluster grid layout", () => {
  function cluster(satelliteCount: number) {
    const sats = Array.from({ length: satelliteCount }, (_, i) => satellite(`s-${i}`));
    return arrangeGroupCluster("hub", sats, "Agent web-01");
  }

  it("centers the hub horizontally on its own row under the header band", () => {
    const arrangement = cluster(8);
    const hub = arrangement.centers.get("hub")!;
    const satellites = [...arrangement.centers.entries()].filter(([key]) => key !== "hub");
    expect(hub.x).toBeCloseTo(arrangement.width / 2);
    expect(hub.y).toBeGreaterThan(REGION_HEADER);
    for (const [, center] of satellites) expect(center.y).toBeGreaterThan(hub.y);
  });

  it("packs the group tightly enough to stay readable when fitted", () => {
    const arrangement = cluster(8);
    expect(arrangement.width).toBeLessThanOrEqual(560);
    expect(arrangement.height).toBeLessThanOrEqual(560);
  });

  it("keeps every member inside the region bounds", () => {
    const arrangement = cluster(16);
    const bounds: Rect = { x: 0, y: 0, w: arrangement.width, h: arrangement.height };
    for (const center of arrangement.centers.values()) {
      expect(regionContainsMember(bounds, center)).toBe(true);
    }
  });

  it("keeps every member clear of the header band", () => {
    const arrangement = cluster(12);
    for (const center of arrangement.centers.values()) {
      expect(center.y - 48).toBeGreaterThanOrEqual(REGION_HEADER);
    }
  });

  it("never overlaps two member markers", () => {
    const arrangement = cluster(24);
    const centers = [...arrangement.centers.values()];
    for (let i = 0; i < centers.length; i += 1) {
      for (let j = i + 1; j < centers.length; j += 1) {
        const a: Rect = { x: centers[i].x - MARKER_FOOTPRINT / 2, y: centers[i].y - MARKER_FOOTPRINT / 2, w: MARKER_FOOTPRINT, h: MARKER_FOOTPRINT };
        const b: Rect = { x: centers[j].x - MARKER_FOOTPRINT / 2, y: centers[j].y - MARKER_FOOTPRINT / 2, w: MARKER_FOOTPRINT, h: MARKER_FOOTPRINT };
        expect(rectsOverlap(a, b)).toBe(false);
      }
    }
  });

  it("wraps members across a grid instead of one long row", () => {
    const arrangement = cluster(10);
    const sats = [...arrangement.centers.entries()].filter(([key]) => key !== "hub").map(([, c]) => c);
    const distinctX = new Set(sats.map((c) => Math.round(c.x)));
    const distinctY = new Set(sats.map((c) => Math.round(c.y)));
    expect(distinctX.size).toBeGreaterThan(1);
    expect(distinctY.size).toBeGreaterThan(1);
  });

  it("orders the aggregate satellite after the real members", () => {
    const sats: ClusterSatellite[] = [
      satellite("near", { importance: "elevated" }),
      satellite("agg", { isAggregate: true }),
    ];
    const arrangement = arrangeGroupCluster("hub", sats, "Group");
    const near = arrangement.centers.get("near")!;
    const agg = arrangement.centers.get("agg")!;
    expect(agg.y > near.y || (agg.y === near.y && agg.x > near.x)).toBe(true);
  });

  it("is deterministic", () => {
    const a = cluster(14);
    const b = cluster(14);
    for (const [key, center] of a.centers) {
      expect(b.centers.get(key)).toEqual(center);
    }
  });
});

describe("packRegions", () => {
  function region(key: string, overrides: Partial<RegionInput> = {}): RegionInput {
    return { key, width: 300, height: 260, isCentral: false, priority: 0, ...overrides };
  }

  it("never overlaps two regions", () => {
    const regions = [
      region("core", { isCentral: true, width: 520, height: 420 }),
      region("b", { width: 260, height: 240, priority: 80 }),
      region("c", { width: 320, height: 300, priority: 60 }),
      region("d", { width: 200, height: 200, priority: 40 }),
      region("e", { width: 360, height: 280, priority: 20 }),
      region("f", { width: 240, height: 240, priority: 10 }),
    ];
    const { origins } = packRegions(regions);
    const rects = regions.map((r): Rect => {
      const o = origins.get(r.key)!;
      return { x: o.x, y: o.y, w: r.width, h: r.height };
    });
    for (let i = 0; i < rects.length; i += 1) {
      for (let j = i + 1; j < rects.length; j += 1) {
        expect(rectsOverlap(rects[i], rects[j])).toBe(false);
      }
    }
  });

  it("puts the primary region first in reading order", () => {
    const regions = [
      region("b", { priority: 80 }),
      region("core", { isCentral: true, width: 420, height: 360 }),
      region("c", { priority: 60 }),
      region("d", { priority: 40 }),
      region("e", { priority: 20 }),
    ];
    const placement = packRegions(regions);
    const core = placement.origins.get("core")!;
    for (const key of ["b", "c", "d", "e"]) {
      const other = placement.origins.get(key)!;
      expect(other.y > core.y || (other.y === core.y && other.x > core.x)).toBe(true);
    }
  });

  it("packs regions into a canvas that is not absurdly wider than it is tall", () => {
    const regions = Array.from({ length: 9 }, (_, i) => region(`r-${i}`, { priority: 9 - i }));
    const placement = packRegions(regions);
    expect(placement.width / Math.max(1, placement.height)).toBeLessThan(4);
  });

  it("is deterministic", () => {
    const regions = [region("core", { isCentral: true }), region("b", { priority: 9 }), region("c", { priority: 4 })];
    const first = packRegions(regions);
    const second = packRegions(regions);
    for (const r of regions) {
      expect(second.origins.get(r.key)).toEqual(first.origins.get(r.key));
    }
  });

  it("returns an empty placement for no regions", () => {
    const placement = packRegions([]);
    expect(placement.origins.size).toBe(0);
  });
});

describe("rectangle geometry", () => {
  it("detects overlap and separation", () => {
    expect(rectsOverlap({ x: 0, y: 0, w: 10, h: 10 }, { x: 5, y: 5, w: 10, h: 10 })).toBe(true);
    expect(rectsOverlap({ x: 0, y: 0, w: 10, h: 10 }, { x: 20, y: 20, w: 10, h: 10 })).toBe(false);
  });

  it("tests point containment", () => {
    expect(pointInRect(50, 25, { x: 0, y: 0, w: 100, h: 50 })).toBe(true);
    expect(pointInRect(120, 25, { x: 0, y: 0, w: 100, h: 50 })).toBe(false);
  });
});
