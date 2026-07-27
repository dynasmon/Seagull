export type EdgeAnchorShape =
  | { kind: "circle"; radius: number }
  | { kind: "rect"; halfWidth: number; halfHeight: number };

export type Point = { x: number; y: number };

const EPSILON = 1e-6;

/**
 * Distance from a shape's centre to its border along a unit direction. Anchoring on the border
 * instead of the centre keeps a link from being drawn across whatever it starts inside.
 */
export function anchorDistance(shape: EdgeAnchorShape, nx: number, ny: number): number {
  if (shape.kind === "circle") return shape.radius;
  const byX = Math.abs(nx) < EPSILON ? Number.POSITIVE_INFINITY : shape.halfWidth / Math.abs(nx);
  const byY = Math.abs(ny) < EPSILON ? Number.POSITIVE_INFINITY : shape.halfHeight / Math.abs(ny);
  const distance = Math.min(byX, byY);
  return Number.isFinite(distance) ? distance : Math.max(shape.halfWidth, shape.halfHeight);
}

/**
 * Trim a centre-to-centre segment back to both borders, plus an optional gap so the line stops
 * just short of the shape rather than touching it.
 */
export function trimToBorders(
  source: Point,
  target: Point,
  sourceShape: EdgeAnchorShape,
  targetShape: EdgeAnchorShape,
  gap = 0,
): { source: Point; target: Point; nx: number; ny: number; length: number } {
  const dx = target.x - source.x;
  const dy = target.y - source.y;
  const length = Math.hypot(dx, dy) || 1;
  const nx = dx / length;
  const ny = dy / length;

  const sourceOffset = anchorDistance(sourceShape, nx, ny) + gap;
  const targetOffset = anchorDistance(targetShape, nx, ny) + gap;

  // Overlapping or touching shapes leave no room to trim; keep a hairline instead of inverting.
  const room = Math.max(0, length - 2);
  const scale = sourceOffset + targetOffset > room ? room / (sourceOffset + targetOffset || 1) : 1;

  return {
    source: { x: source.x + nx * sourceOffset * scale, y: source.y + ny * sourceOffset * scale },
    target: { x: target.x - nx * targetOffset * scale, y: target.y - ny * targetOffset * scale },
    nx,
    ny,
    length,
  };
}

export type Obstacle = { x: number; y: number; w: number; h: number };

const BOW_STEPS = [0, 55, -55, 95, -95, 140, -140, 190, -190, 250, -250];
const BOW_SAMPLES = 16;
const OBSTACLE_MARGIN = 10;

function quadraticPoint(source: Point, control: Point, target: Point, t: number): Point {
  const inv = 1 - t;
  return {
    x: inv * inv * source.x + 2 * inv * t * control.x + t * t * target.x,
    y: inv * inv * source.y + 2 * inv * t * control.y + t * t * target.y,
  };
}

function hitsObstacle(point: Point, obstacles: Obstacle[]): boolean {
  for (const box of obstacles) {
    if (
      point.x >= box.x - OBSTACLE_MARGIN &&
      point.x <= box.x + box.w + OBSTACLE_MARGIN &&
      point.y >= box.y - OBSTACLE_MARGIN &&
      point.y <= box.y + box.h + OBSTACLE_MARGIN
    ) {
      return true;
    }
  }
  return false;
}

/**
 * A straight link between two regions runs through whatever sits between them. Bow the link
 * sideways by the smallest amount that clears every other region, so links pass around the
 * boxes instead of over them. Returns the displacement of the curve's midpoint.
 */
export function bowAroundObstacles(
  source: Point,
  target: Point,
  obstacles: Obstacle[],
): number {
  if (obstacles.length === 0) return 0;
  const dx = target.x - source.x;
  const dy = target.y - source.y;
  const length = Math.hypot(dx, dy) || 1;
  const px = -dy / length;
  const py = dx / length;
  const mid = { x: (source.x + target.x) / 2, y: (source.y + target.y) / 2 };

  for (const bow of BOW_STEPS) {
    const control = { x: mid.x + px * bow * 2, y: mid.y + py * bow * 2 };
    let clear = true;
    for (let step = 1; step < BOW_SAMPLES; step += 1) {
      if (hitsObstacle(quadraticPoint(source, control, target, step / BOW_SAMPLES), obstacles)) {
        clear = false;
        break;
      }
    }
    if (clear) return bow;
  }
  return BOW_STEPS[BOW_STEPS.length - 1];
}

export function bowControlPoint(source: Point, target: Point, bow: number): Point {
  const dx = target.x - source.x;
  const dy = target.y - source.y;
  const length = Math.hypot(dx, dy) || 1;
  return {
    x: (source.x + target.x) / 2 + (-dy / length) * bow * 2,
    y: (source.y + target.y) / 2 + (dx / length) * bow * 2,
  };
}

/**
 * Trim both ends of a bowed link. A bowed curve leaves its endpoint towards the control point,
 * not towards the other endpoint, so anchoring on the straight line would kink the link where it
 * meets the box.
 */
export function trimBowedToBorders(
  source: Point,
  target: Point,
  control: Point,
  sourceShape: EdgeAnchorShape,
  targetShape: EdgeAnchorShape,
  gap = 0,
): { source: Point; target: Point } {
  function shift(from: Point, towards: Point, shape: EdgeAnchorShape): Point {
    const dx = towards.x - from.x;
    const dy = towards.y - from.y;
    const length = Math.hypot(dx, dy) || 1;
    const nx = dx / length;
    const ny = dy / length;
    const offset = Math.min(anchorDistance(shape, nx, ny) + gap, length - 1);
    return { x: from.x + nx * offset, y: from.y + ny * offset };
  }
  return {
    source: shift(source, control, sourceShape),
    target: shift(target, control, targetShape),
  };
}

export function bowedPath(
  source: Point,
  target: Point,
  control: Point,
): { path: string; labelX: number; labelY: number } {
  return {
    path: `M ${source.x},${source.y} Q ${control.x},${control.y} ${target.x},${target.y}`,
    labelX: 0.25 * source.x + 0.5 * control.x + 0.25 * target.x,
    labelY: 0.25 * source.y + 0.5 * control.y + 0.25 * target.y,
  };
}

export function circleAnchor(radius: number): EdgeAnchorShape {
  return { kind: "circle", radius };
}

export function rectAnchor(width: number, height: number): EdgeAnchorShape {
  return { kind: "rect", halfWidth: width / 2, halfHeight: height / 2 };
}
