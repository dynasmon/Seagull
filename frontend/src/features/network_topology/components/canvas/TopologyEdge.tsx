import { useState } from "react";
import { BaseEdge, type EdgeProps, Position, getBezierPath, useStore } from "@xyflow/react";

import {
  bowControlPoint,
  bowedPath,
  circleAnchor,
  trimBowedToBorders,
  trimToBorders,
  type EdgeAnchorShape,
} from "../../lib/layout/edgeAnchors";
import { stableTopologyHash } from "../../lib/layout/topologyLayoutEngine";
import { EDGE_TYPE_SHORT_LABELS, edgeVisual, severityColor } from "../../lib/presentation/visuals";
import type { TopologyBundleEdgeData, TopologyEdgeData } from "../../lib/graph/graphTransform";
import type { TopologyEdge, TopologyGroupEdge } from "../../types";

const PILL_SUPPRESSED_EDGE_TYPES = new Set(["same_agent", "owns_interface", "member_of_subnet"]);
const BORDER_GAP = 3;

function prefersReducedMotion(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return false;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function handlePositions(nx: number, ny: number): { sp: Position; tp: Position } {
  if (Math.abs(nx) >= Math.abs(ny) * 0.7) {
    return nx >= 0
      ? { sp: Position.Right, tp: Position.Left }
      : { sp: Position.Left, tp: Position.Right };
  }
  return ny >= 0
    ? { sp: Position.Bottom, tp: Position.Top }
    : { sp: Position.Top, tp: Position.Bottom };
}

function volumeBoost(eventCount: number): number {
  if (eventCount <= 0) return 0;
  return Math.min(2.2, Math.log10(eventCount + 1) * 0.85);
}

function Pill({
  x,
  y,
  label,
  color,
  opacity,
  onHoverChange,
}: {
  x: number;
  y: number;
  label: string;
  color: string;
  opacity: number;
  onHoverChange: (hovered: boolean) => void;
}) {
  const width = Math.max(34, label.length * 5.4 + 12);
  return (
    <foreignObject
      x={x - width / 2}
      y={y - 8}
      width={width}
      height={16}
      style={{ overflow: "visible", pointerEvents: "auto" }}
    >
      <div
        onMouseEnter={() => onHoverChange(true)}
        onMouseLeave={() => onHoverChange(false)}
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          height: 14,
          background: "rgba(7,17,31,0.94)",
          border: `1px solid ${color}55`,
          borderRadius: 3,
          fontSize: 8,
          fontWeight: 700,
          color,
          whiteSpace: "nowrap",
          letterSpacing: "0.02em",
          opacity,
          transition: "opacity 150ms ease",
          cursor: "pointer",
        }}
      >
        {label}
      </div>
    </foreignObject>
  );
}

export function TopologyBundleEdge(props: EdgeProps) {
  const { sourceX, sourceY, targetX, targetY, data } = props;
  const [hovered, setHovered] = useState(false);
  const zoom = useStore((state) => state.transform[2]);
  const bundleData = data as unknown as TopologyBundleEdgeData;
  const { bundle } = bundleData;

  const centres = { source: { x: sourceX, y: sourceY }, target: { x: targetX, y: targetY } };
  const control = bowControlPoint(centres.source, centres.target, Number(bundleData.bow ?? 0));
  const trimmed = trimBowedToBorders(
    centres.source,
    centres.target,
    control,
    bundleData.sourceShape,
    bundleData.targetShape,
    BORDER_GAP,
  );

  const stroke =
    bundle.alertCount > 0
      ? severityColor(bundle.severity)
      : edgeVisual({ edge_type: bundle.dominantType, confidence: 90 }).stroke;
  const width = 1.4 + Math.min(4.6, Math.log10(bundle.linkCount + 1) * 2.6);
  const isDimmed = Boolean(bundleData.isDimmed);
  const opacity = isDimmed ? 0.12 : hovered ? 0.95 : 0.52;

  const { path, labelX, labelY } = bowedPath(trimmed.source, trimmed.target, control);

  const label = `${bundle.linkCount} ${EDGE_TYPE_SHORT_LABELS[bundle.dominantType] ?? bundle.dominantType}`;

  return (
    <>
      <BaseEdge
        path={path}
        style={{
          stroke,
          strokeWidth: hovered ? width + 1.4 : width,
          strokeLinecap: "round",
          opacity,
          transition: "stroke-width 150ms ease, opacity 150ms ease",
        }}
      />
      <path
        d={path}
        fill="none"
        stroke="transparent"
        strokeWidth={16}
        pointerEvents="stroke"
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => setHovered(false)}
      />
      {!isDimmed && zoom >= 0.32 && (
        <Pill
          x={labelX}
          y={labelY}
          label={label}
          color={stroke}
          opacity={hovered ? 1 : 0.82}
          onHoverChange={setHovered}
        />
      )}
    </>
  );
}

export function TopologyFlowEdge(props: EdgeProps) {
  const { id, sourceX, sourceY, targetX, targetY, data } = props;
  const [hovered, setHovered] = useState(false);
  const zoom = useStore((state) => state.transform[2]);
  const labelsVisible = zoom >= 0.5;

  const record = (data ?? {}) as Record<string, unknown>;
  const isGroupEdge = "groupEdge" in record;
  const groupEdge = isGroupEdge ? (record.groupEdge as TopologyGroupEdge) : null;
  const flowEdge = !isGroupEdge ? (record.edge as TopologyEdge) : null;

  const edgeType = groupEdge ? (groupEdge.edge_types[0] ?? "observed_flow") : flowEdge!.edge_type;
  const confidence = groupEdge ? 80 : flowEdge!.confidence;
  const eventCount = Number((groupEdge ?? flowEdge)!.event_count || 0);
  const alertCount = Number((groupEdge ?? flowEdge)!.alert_count || 0);

  const visual = edgeVisual({ edge_type: edgeType, confidence });
  const isSelected = Boolean(record.isSelected);
  const isDimmed = Boolean(record.isDimmed);

  const edgeData = data as unknown as TopologyEdgeData;
  const fallbackShape: EdgeAnchorShape = circleAnchor(17);
  const sourceShape = edgeData.sourceShape ?? fallbackShape;
  const targetShape = edgeData.targetShape ?? fallbackShape;
  const parallelIndex = isGroupEdge ? (stableTopologyHash(id) % 5) - 2 : (edgeData.parallelIndex ?? 0);
  const parallelTotal = isGroupEdge ? 1 : (edgeData.parallelTotal ?? 1);
  const isBidirectional = Boolean(edgeData.isBidirectional);

  const straight = trimToBorders(
    { x: sourceX, y: sourceY },
    { x: targetX, y: targetY },
    sourceShape,
    targetShape,
    BORDER_GAP,
  );

  const routedBow = Number(edgeData.bow ?? 0);
  const spread =
    parallelTotal > 1 ? (parallelIndex - (parallelTotal - 1) / 2) * Math.min(26, straight.length * 0.12) : 0;
  const totalBow = routedBow + spread;
  let trimmed = straight;
  let tipX = straight.nx;
  let tipY = straight.ny;
  let edgePath: string;
  let labelX: number;
  let labelY: number;
  if (totalBow !== 0) {
    const centres = { source: { x: sourceX, y: sourceY }, target: { x: targetX, y: targetY } };
    const control = bowControlPoint(centres.source, centres.target, totalBow);
    const ends = trimBowedToBorders(
      centres.source,
      centres.target,
      control,
      sourceShape,
      targetShape,
      BORDER_GAP,
    );
    trimmed = { ...straight, source: ends.source, target: ends.target };
    const tipLength = Math.hypot(ends.target.x - control.x, ends.target.y - control.y) || 1;
    tipX = (ends.target.x - control.x) / tipLength;
    tipY = (ends.target.y - control.y) / tipLength;
    const routed = bowedPath(ends.source, ends.target, control);
    edgePath = routed.path;
    labelX = routed.labelX;
    labelY = routed.labelY;
  } else {
    const { sp, tp } = handlePositions(trimmed.nx, trimmed.ny);
    const [bezier, bx, by] = getBezierPath({
      sourceX: trimmed.source.x,
      sourceY: trimmed.source.y,
      sourcePosition: sp,
      targetX: trimmed.target.x,
      targetY: trimmed.target.y,
      targetPosition: tp,
      curvature: 0.2,
    });
    edgePath = bezier;
    labelX = bx;
    labelY = by;
  }

  const stroke = alertCount > 0 ? severityColor(groupEdge?.severity ?? flowEdge?.severity) : visual.stroke;
  const boost = volumeBoost(eventCount);
  const strokeWidth = isSelected || hovered ? visual.width + boost + 1.4 : visual.width + boost;
  const opacity = isDimmed
    ? 0.12
    : isSelected || hovered
      ? 1
      : Math.min(1, visual.opacity + (alertCount > 0 ? 0.25 : 0) + boost * 0.08);

  const showPulse =
    !isDimmed && edgeType === "observed_flow" && eventCount > 200 && !prefersReducedMotion();

  const showPill =
    !isDimmed && !PILL_SUPPRESSED_EDGE_TYPES.has(edgeType) && (labelsVisible || isSelected || hovered);
  const pillLabel = EDGE_TYPE_SHORT_LABELS[edgeType] ?? edgeType;

  return (
    <>
      <BaseEdge
        id={id}
        path={edgePath}
        style={{
          stroke,
          strokeWidth,
          strokeDasharray: visual.dashArray,
          strokeLinecap: "round",
          opacity,
          transition: "stroke-width 150ms ease, opacity 150ms ease",
        }}
      />
      <path
        d={edgePath}
        fill="none"
        stroke="transparent"
        strokeWidth={14}
        pointerEvents="stroke"
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => setHovered(false)}
      />
      {showPulse && (
        <path
          d={edgePath}
          fill="none"
          stroke={stroke}
          strokeWidth={strokeWidth + 0.6}
          strokeDasharray="10 14"
          strokeLinecap="round"
          opacity={Math.min(0.85, opacity + 0.3)}
          pointerEvents="none"
        >
          <animate attributeName="stroke-dashoffset" from="0" to="-24" dur="2.4s" repeatCount="indefinite" />
        </path>
      )}
      {!isDimmed && !isBidirectional && trimmed.length > 60 && (
        <polygon
          points="0,-3.4 6.4,0 0,3.4"
          fill={stroke}
          opacity={Math.min(1, opacity + 0.2)}
          pointerEvents="none"
          transform={`translate(${trimmed.target.x - tipX * 6} ${trimmed.target.y - tipY * 6}) rotate(${(Math.atan2(tipY, tipX) * 180) / Math.PI})`}
        />
      )}
      {showPill && (
        <Pill
          x={labelX}
          y={labelY}
          label={pillLabel}
          color={stroke}
          opacity={isSelected || hovered ? 1 : 0.62}
          onHoverChange={setHovered}
        />
      )}
      {parallelTotal > 1 && parallelIndex === 0 && !isDimmed && !isSelected && labelsVisible && (
        <foreignObject
          x={(trimmed.source.x + trimmed.target.x) / 2 - 10}
          y={(trimmed.source.y + trimmed.target.y) / 2 - 8}
          width={20}
          height={16}
          style={{ overflow: "visible", pointerEvents: "none" }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              background: "rgba(7,17,31,0.9)",
              border: `1px solid ${stroke}4d`,
              borderRadius: 8,
              width: 20,
              height: 16,
              fontSize: 8,
              fontWeight: 700,
              color: stroke,
              lineHeight: 1,
            }}
            title={`${parallelTotal} relationship types between these nodes`}
          >
            {parallelTotal}
          </div>
        </foreignObject>
      )}
    </>
  );
}
