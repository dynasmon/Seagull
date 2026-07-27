import type { TopologyNodeImportance } from "./presentation";

export const MEMBER_W = 92;
export const MEMBER_H = 84;
const MEMBER_HALF = MEMBER_W / 2;

export const REGION_HEADER = 34;
export const REGION_PADDING = 18;
export const REGION_GAP = 44;

export const MARKER_FOOTPRINT = 76;

const CELL_W = 104;
const CELL_H = 96;
const MAX_GRID_COLUMNS = 8;
const GRID_ASPECT_BIAS = 1.6;
const REGION_ROW_ASPECT = 1.9;

const HEADER_CHAR_PX = 6.9;
const HEADER_OVERHEAD = 116;
const HEADER_MIN_W = 208;
const HEADER_MAX_W = 380;

export const SMALL_GROUP_LIMIT = 24;
export const REPRESENTATIVE_LIMIT = 12;

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

export function gridColumns(count: number): number {
  if (count <= 1) return 1;
  return Math.min(MAX_GRID_COLUMNS, Math.max(1, Math.ceil(Math.sqrt(count * GRID_ASPECT_BIAS))));
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

export function arrangeGroupCluster(
  hubKey: string,
  satellites: ClusterSatellite[],
  label: string,
): ClusterArrangement {
  const ordered = orderSatellites(satellites);
  const columns = gridColumns(ordered.length);
  const rows = ordered.length === 0 ? 0 : Math.ceil(ordered.length / columns);

  const contentWidth = Math.max(columns * CELL_W, CELL_W);
  const width = Math.max(contentWidth + REGION_PADDING * 2, headerMinWidth(label));
  const height = REGION_HEADER + REGION_PADDING + CELL_H * (rows + 1) + REGION_PADDING;

  const hubY = REGION_HEADER + REGION_PADDING + CELL_H / 2;
  const centers = new Map<string, { x: number; y: number }>();
  centers.set(hubKey, { x: width / 2, y: hubY });

  ordered.forEach((satellite, index) => {
    const row = Math.floor(index / columns);
    const column = index % columns;
    const inRow = Math.min(columns, ordered.length - row * columns);
    const rowStartX = (width - inRow * CELL_W) / 2;
    centers.set(satellite.key, {
      x: rowStartX + column * CELL_W + CELL_W / 2,
      y: hubY + CELL_H * (row + 1),
    });
  });

  return { centers, width, height };
}

export type RegionLinks = Map<string, number>;

export function regionLinkKey(a: string, b: string): string {
  return a < b ? `${a}|||${b}` : `${b}|||${a}`;
}

export function orderRegions(regions: RegionInput[]): RegionInput[] {
  return [...regions].sort((a, b) => {
    if (a.isCentral !== b.isCentral) return a.isCentral ? -1 : 1;
    if (b.priority !== a.priority) return b.priority - a.priority;
    return a.key < b.key ? -1 : a.key > b.key ? 1 : 0;
  });
}

/**
 * Priority alone scatters heavily linked regions across the canvas, which is what turns the
 * inter-region traffic into long crossing lines. Walk the regions greedily instead: after the
 * primary one, always take whichever unplaced region is most strongly tied to what is already
 * down, falling back to priority when nothing links.
 */
export function orderRegionsByAdjacency(regions: RegionInput[], links: RegionLinks): RegionInput[] {
  const byPriority = orderRegions(regions);
  if (links.size === 0 || byPriority.length < 3) return byPriority;

  const remaining = new Map(byPriority.map((region) => [region.key, region]));
  const placed: RegionInput[] = [];
  const first = byPriority[0];
  placed.push(first);
  remaining.delete(first.key);

  while (remaining.size > 0) {
    let best: RegionInput | null = null;
    let bestWeight = -1;
    for (const region of byPriority) {
      if (!remaining.has(region.key)) continue;
      let weight = 0;
      for (const done of placed) {
        weight += links.get(regionLinkKey(region.key, done.key)) ?? 0;
      }
      if (weight > bestWeight) {
        bestWeight = weight;
        best = region;
      }
    }
    const next = best ?? remaining.values().next().value!;
    placed.push(next);
    remaining.delete(next.key);
  }

  return placed;
}

type Shelf = { members: RegionInput[]; width: number; height: number };

function shelveRegions(ordered: RegionInput[], targetWidth: number): Shelf[] {
  const shelves: Shelf[] = [];
  let shelf: Shelf = { members: [], width: 0, height: 0 };

  for (const region of ordered) {
    const nextWidth = shelf.members.length === 0 ? region.width : shelf.width + REGION_GAP + region.width;
    if (shelf.members.length > 0 && nextWidth > targetWidth) {
      shelves.push(shelf);
      shelf = { members: [], width: 0, height: 0 };
    }
    shelf.width = shelf.members.length === 0 ? region.width : shelf.width + REGION_GAP + region.width;
    shelf.height = Math.max(shelf.height, region.height);
    shelf.members.push(region);
  }
  if (shelf.members.length > 0) shelves.push(shelf);
  return shelves;
}

function shelfCanvas(shelves: Shelf[]): { width: number; height: number } {
  const width = shelves.reduce((max, shelf) => Math.max(max, shelf.width), 0);
  const height = shelves.reduce((sum, shelf) => sum + shelf.height + REGION_GAP, 0) - REGION_GAP;
  return { width, height: Math.max(0, height) };
}

/**
 * Shelf packing off a single estimated row width leaves ragged rows and a canvas that ends up
 * roughly square, so fitting it into a wide viewport wastes most of the horizontal space. Try
 * every row width where the packing actually changes and keep the one whose canvas comes out
 * closest to the viewport's shape.
 */
function bestShelves(ordered: RegionInput[]): Shelf[] {
  const widest = ordered.reduce((max, region) => Math.max(max, region.width), 0);
  const candidates: number[] = [widest];
  for (let start = 0; start < ordered.length; start += 1) {
    let run = 0;
    for (let end = start; end < ordered.length; end += 1) {
      run += (end > start ? REGION_GAP : 0) + ordered[end].width;
      if (run > widest) candidates.push(run);
    }
  }

  let best: Shelf[] | null = null;
  let bestScore = Number.POSITIVE_INFINITY;
  for (const candidate of candidates) {
    const shelves = shelveRegions(ordered, candidate);
    const { width, height } = shelfCanvas(shelves);
    if (height <= 0) continue;
    const score = Math.abs(Math.log(width / height / REGION_ROW_ASPECT));
    if (score < bestScore) {
      bestScore = score;
      best = shelves;
    }
  }
  return best ?? shelveRegions(ordered, widest);
}

export function packRegions(regions: RegionInput[], links: RegionLinks = new Map()): RegionPlacement {
  if (regions.length === 0) return { origins: new Map(), width: 0, height: 0 };

  const ordered = orderRegionsByAdjacency(regions, links);
  const shelves = bestShelves(ordered);
  const { width: canvasWidth, height: canvasHeight } = shelfCanvas(shelves);

  const origins = new Map<string, { x: number; y: number }>();
  let cursorY = 0;

  for (const shelf of shelves) {
    let cursorX = Math.round((canvasWidth - shelf.width) / 2);
    for (const region of shelf.members) {
      origins.set(region.key, {
        x: cursorX,
        y: Math.round(cursorY + (shelf.height - region.height) / 2),
      });
      cursorX += region.width + REGION_GAP;
    }
    cursorY += shelf.height + REGION_GAP;
  }

  return { origins, width: canvasWidth, height: canvasHeight };
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
