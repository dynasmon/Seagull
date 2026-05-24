import type { TopologyNodeImportance } from "./presentation";

export const MEMBER_W = 96;
export const MEMBER_H = 96;
const MEMBER_HALF = MEMBER_W / 2;

export const REGION_HEADER = 38;
export const REGION_PADDING = 30;
export const REGION_GAP = 96;

const SATELLITE_SPACING = 132;
const RING_BASE = 124;
const RING_STEP = 124;
const GOLDEN_ANGLE = Math.PI * (3 - Math.sqrt(5));

export const MARKER_FOOTPRINT = 72;

const HEADER_CHAR_PX = 6.6;
const HEADER_OVERHEAD = 104;
const HEADER_MIN_W = 196;
const HEADER_MAX_W = 360;

export const SMALL_GROUP_LIMIT = 9;
export const REPRESENTATIVE_LIMIT = 4;

export type Rect = { x: number; y: number; w: number; h: number };

export type ClusterMember = {
  key: string;
  importance: TopologyNodeImportance;
  risk_score: number;
  alert_count: number;
  alwaysShow: boolean;
};

export type ClusterSatellite = {
  key: string;
  importance: TopologyNodeImportance;
  risk_score: number;
  alert_count: number;
  isAggregate: boolean;
};

export type ClusterArrangement = {
  centers: Map<string, { x: number; y: number }>;
  width: number;
  height: number;
};

export type ClassifiedMembers = {
  shownKeys: Set<string>;
  aggregatedKeys: string[];
  aggregatedCount: number;
};

export type RegionInput = {
  key: string;
  width: number;
  height: number;
  isCentral: boolean;
  priority: number;
};

export type RegionPlacement = {
  origins: Map<string, { x: number; y: number }>;
  width: number;
  height: number;
};

function importanceOrder(importance: TopologyNodeImportance): number {
  if (importance === "anchor") return 0;
  if (importance === "elevated") return 1;
  return 2;
}

function compareSignal(a: ClusterMember, b: ClusterMember): number {
  const byAlerts = (b.alert_count || 0) - (a.alert_count || 0);
  if (byAlerts !== 0) return byAlerts;
  const byRisk = (b.risk_score || 0) - (a.risk_score || 0);
  if (byRisk !== 0) return byRisk;
  return a.key < b.key ? -1 : a.key > b.key ? 1 : 0;
}

export function headerMinWidth(label: string): number {
  const raw = Math.ceil(label.length * HEADER_CHAR_PX) + HEADER_OVERHEAD;
  return Math.max(HEADER_MIN_W, Math.min(HEADER_MAX_W, raw));
}

export function classifyGroupMembers(members: ClusterMember[], expanded: boolean): ClassifiedMembers {
  const lowSignal = members.filter((member) => !member.alwaysShow).sort(compareSignal);
  const fullyShown =
    expanded || members.length <= SMALL_GROUP_LIMIT || lowSignal.length <= REPRESENTATIVE_LIMIT;

  if (fullyShown) {
    return { shownKeys: new Set(members.map((m) => m.key)), aggregatedKeys: [], aggregatedCount: 0 };
  }

  const representatives = lowSignal.slice(0, REPRESENTATIVE_LIMIT);
  const aggregated = lowSignal.slice(REPRESENTATIVE_LIMIT);
  const shownKeys = new Set<string>([
    ...members.filter((m) => m.alwaysShow).map((m) => m.key),
    ...representatives.map((m) => m.key),
  ]);
  return {
    shownKeys,
    aggregatedKeys: aggregated.map((m) => m.key),
    aggregatedCount: aggregated.length,
  };
}

function orderSatellites(satellites: ClusterSatellite[]): ClusterSatellite[] {
  return [...satellites].sort((a, b) => {
    if (a.isAggregate !== b.isAggregate) return a.isAggregate ? 1 : -1;
    const byImportance = importanceOrder(a.importance) - importanceOrder(b.importance);
    if (byImportance !== 0) return byImportance;
    const byAlerts = (b.alert_count || 0) - (a.alert_count || 0);
    if (byAlerts !== 0) return byAlerts;
    const byRisk = (b.risk_score || 0) - (a.risk_score || 0);
    if (byRisk !== 0) return byRisk;
    return a.key < b.key ? -1 : a.key > b.key ? 1 : 0;
  });
}

function ringCapacity(radius: number): number {
  return Math.max(1, Math.floor((2 * Math.PI * radius) / SATELLITE_SPACING));
}

export function arrangeGroupCluster(
  hubKey: string,
  satellites: ClusterSatellite[],
  label: string,
): ClusterArrangement {
  const ordered = orderSatellites(satellites);
  const placements: Array<{ key: string; radius: number; angle: number }> = [];

  let index = 0;
  let ringIndex = 0;
  while (index < ordered.length) {
    const radius = RING_BASE + ringIndex * RING_STEP;
    const capacity = ringCapacity(radius);
    const onThisRing = Math.min(capacity, ordered.length - index);
    const rotation = ringIndex * GOLDEN_ANGLE - Math.PI / 2;
    for (let slot = 0; slot < onThisRing; slot += 1) {
      const angle = rotation + (2 * Math.PI * slot) / onThisRing;
      placements.push({ key: ordered[index + slot].key, radius, angle });
    }
    index += onThisRing;
    ringIndex += 1;
  }

  const maxRadius = placements.reduce((max, p) => Math.max(max, p.radius), 0);
  const contentRadius = maxRadius + MEMBER_HALF + REGION_PADDING;
  const contentDiameter = Math.max(contentRadius * 2, MEMBER_H + REGION_PADDING * 2);
  const width = Math.max(contentDiameter, headerMinWidth(label));
  const height = REGION_HEADER + contentDiameter;

  const hubX = width / 2;
  const hubY = REGION_HEADER + contentDiameter / 2;
  const centers = new Map<string, { x: number; y: number }>();
  centers.set(hubKey, { x: hubX, y: hubY });
  for (const placement of placements) {
    centers.set(placement.key, {
      x: hubX + placement.radius * Math.cos(placement.angle),
      y: hubY + placement.radius * Math.sin(placement.angle),
    });
  }

  return { centers, width, height };
}

export function orderRegions(regions: RegionInput[]): RegionInput[] {
  return [...regions].sort((a, b) => {
    if (a.isCentral !== b.isCentral) return a.isCentral ? -1 : 1;
    if (b.priority !== a.priority) return b.priority - a.priority;
    return a.key < b.key ? -1 : a.key > b.key ? 1 : 0;
  });
}

function reach(width: number, height: number): number {
  return Math.hypot(width / 2, height / 2);
}

function separateRegions(
  ordered: RegionInput[],
  centers: Map<string, { x: number; y: number }>,
): void {
  const coreKey = ordered[0]?.key;
  const sizeByKey = new Map(ordered.map((r) => [r.key, r]));
  for (let iter = 0; iter < 80; iter += 1) {
    let moved = false;
    for (let i = 0; i < ordered.length; i += 1) {
      for (let j = i + 1; j < ordered.length; j += 1) {
        const a = ordered[i];
        const b = ordered[j];
        const ca = centers.get(a.key)!;
        const cb = centers.get(b.key)!;
        const ra = sizeByKey.get(a.key)!;
        const rb = sizeByKey.get(b.key)!;
        const dx = cb.x - ca.x;
        const dy = cb.y - ca.y;
        const penX = ra.width / 2 + rb.width / 2 + REGION_GAP - Math.abs(dx);
        const penY = ra.height / 2 + rb.height / 2 + REGION_GAP - Math.abs(dy);
        if (penX <= 0 || penY <= 0) continue;
        let shiftX = 0;
        let shiftY = 0;
        if (penX < penY) shiftX = (dx >= 0 ? 1 : -1) * penX;
        else shiftY = (dy >= 0 ? 1 : -1) * penY;
        const aPinned = a.key === coreKey;
        const bPinned = b.key === coreKey;
        if (aPinned && !bPinned) {
          cb.x += shiftX;
          cb.y += shiftY;
        } else if (bPinned && !aPinned) {
          ca.x -= shiftX;
          ca.y -= shiftY;
        } else {
          ca.x -= shiftX / 2;
          ca.y -= shiftY / 2;
          cb.x += shiftX / 2;
          cb.y += shiftY / 2;
        }
        moved = true;
      }
    }
    if (!moved) break;
  }
}

export function placeRegionsOrbital(regions: RegionInput[]): RegionPlacement {
  if (regions.length === 0) return { origins: new Map(), width: 0, height: 0 };

  const ordered = orderRegions(regions);
  const centers = new Map<string, { x: number; y: number }>();
  const core = ordered[0];
  centers.set(core.key, { x: 0, y: 0 });

  const rest = ordered.slice(1);
  const maxReach = ordered.reduce((max, r) => Math.max(max, reach(r.width, r.height)), 0);
  const seedSpacing = maxReach + REGION_GAP;
  rest.forEach((region, i) => {
    const radius = seedSpacing * Math.sqrt(i + 1);
    const angle = i * GOLDEN_ANGLE;
    centers.set(region.key, { x: radius * Math.cos(angle), y: radius * Math.sin(angle) });
  });

  separateRegions(ordered, centers);

  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  for (const region of ordered) {
    const center = centers.get(region.key)!;
    minX = Math.min(minX, center.x - region.width / 2);
    minY = Math.min(minY, center.y - region.height / 2);
    maxX = Math.max(maxX, center.x + region.width / 2);
    maxY = Math.max(maxY, center.y + region.height / 2);
  }

  const origins = new Map<string, { x: number; y: number }>();
  for (const region of ordered) {
    const center = centers.get(region.key)!;
    origins.set(region.key, { x: center.x - region.width / 2 - minX, y: center.y - region.height / 2 - minY });
  }

  return { origins, width: maxX - minX, height: maxY - minY };
}

export function rectsOverlap(a: Rect, b: Rect, gap = 0): boolean {
  return (
    a.x < b.x + b.w + gap &&
    a.x + a.w + gap > b.x &&
    a.y < b.y + b.h + gap &&
    a.y + a.h + gap > b.y
  );
}

export function pointInRect(px: number, py: number, rect: Rect): boolean {
  return px >= rect.x && px <= rect.x + rect.w && py >= rect.y && py <= rect.y + rect.h;
}

export function regionContainsMember(
  region: Rect,
  center: { x: number; y: number },
  half = MEMBER_HALF,
): boolean {
  return (
    center.x - half >= region.x &&
    center.x + half <= region.x + region.w &&
    center.y - half >= region.y &&
    center.y + half <= region.y + region.h
  );
}
