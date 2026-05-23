import { useEffect, useMemo, useRef } from "react";
import { useSigma } from "@react-sigma/core";
import type { Node } from "@xyflow/react";

import type { DeviceNodeData } from "../lib/graphTransform";
import { severityColor } from "../lib/visuals";
import type { TopologyGroup } from "../types";

type Props = {
  nodes: Node[];
  groups: TopologyGroup[];
};

function computeBoundingCircle(
  points: Array<{ x: number; y: number }>,
  padding: number,
): { cx: number; cy: number; r: number } | null {
  if (points.length === 0) return null;
  if (points.length === 1) {
    return { cx: points[0].x, cy: points[0].y, r: padding };
  }

  let cx = 0;
  let cy = 0;
  for (const point of points) {
    cx += point.x;
    cy += point.y;
  }
  cx /= points.length;
  cy /= points.length;

  let r = 0;
  for (const point of points) {
    const d = Math.sqrt((point.x - cx) ** 2 + (point.y - cy) ** 2);
    if (d > r) r = d;
  }

  return { cx, cy, r: Math.max(r + padding, padding * 1.5) };
}

function roundedRectPath(
  ctx: CanvasRenderingContext2D,
  x: number,
  y: number,
  width: number,
  height: number,
  radius: number,
) {
  const r = Math.min(radius, width / 2, height / 2);
  ctx.moveTo(x + r, y);
  ctx.lineTo(x + width - r, y);
  ctx.quadraticCurveTo(x + width, y, x + width, y + r);
  ctx.lineTo(x + width, y + height - r);
  ctx.quadraticCurveTo(x + width, y + height, x + width - r, y + height);
  ctx.lineTo(x + r, y + height);
  ctx.quadraticCurveTo(x, y + height, x, y + height - r);
  ctx.lineTo(x, y + r);
  ctx.quadraticCurveTo(x, y, x + r, y);
}

export function SigmaHaloLayer({ nodes, groups }: Props) {
  const sigma = useSigma();
  const canvasRef = useRef<HTMLCanvasElement>(null);

  const groupMap = useMemo(() => {
    const next = new Map<string, { group: TopologyGroup; nodeIds: string[] }>();
    for (const group of groups) {
      next.set(group.group_key, { group, nodeIds: [] });
    }
    for (const node of nodes) {
      if (node.type !== "device") continue;
      const data = node.data as unknown as DeviceNodeData;
      if (!data.groupKey) continue;
      const entry = next.get(data.groupKey);
      if (entry) entry.nodeIds.push(node.id);
    }
    return next;
  }, [groups, nodes]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const overlay = canvas;

    function draw() {
      const container = sigma.getContainer();
      const containerRect = container.getBoundingClientRect();
      const width = Math.max(1, Math.floor(containerRect.width));
      const height = Math.max(1, Math.floor(containerRect.height));
      const dpr = window.devicePixelRatio || 1;

      overlay.style.width = `${width}px`;
      overlay.style.height = `${height}px`;
      overlay.width = Math.floor(width * dpr);
      overlay.height = Math.floor(height * dpr);

      const ctx = overlay.getContext("2d");
      if (!ctx) return;

      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, width, height);

      for (const { group, nodeIds } of groupMap.values()) {
        if (nodeIds.length === 0) continue;

        const screenPoints: Array<{ x: number; y: number }> = [];
        for (const nodeId of nodeIds) {
          const display = sigma.getNodeDisplayData(nodeId);
          if (!display) continue;
          screenPoints.push({ x: display.x, y: display.y });
        }

        const circle = computeBoundingCircle(
          screenPoints,
          36 + Math.log1p(nodeIds.length) * 8,
        );
        if (!circle) continue;

        const { cx, cy, r } = circle;
        const risky = group.alert_count > 0 || group.risk_score >= 70;
        const accent = risky
          ? severityColor(group.highest_severity)
          : "#60A5FA";

        ctx.save();

        ctx.beginPath();
        ctx.arc(cx, cy, r, 0, Math.PI * 2);
        const grad = ctx.createRadialGradient(cx, cy, r * 0.3, cx, cy, r);
        grad.addColorStop(0, risky ? `${accent}08` : "rgba(96,165,250,0.04)");
        grad.addColorStop(1, "transparent");
        ctx.fillStyle = grad;
        ctx.fill();

        ctx.beginPath();
        ctx.arc(cx, cy, r, 0, Math.PI * 2);
        ctx.strokeStyle = risky ? `${accent}55` : "rgba(96,165,250,0.22)";
        ctx.lineWidth = 1.5;
        ctx.stroke();

        ctx.beginPath();
        ctx.arc(cx, cy, r * 0.88, 0, Math.PI * 2);
        ctx.setLineDash([4, 6]);
        ctx.strokeStyle = risky ? `${accent}25` : "rgba(96,165,250,0.10)";
        ctx.lineWidth = 1;
        ctx.stroke();
        ctx.setLineDash([]);

        const labelX = cx;
        const labelY = cy - r + 14;
        const badgeText = group.label;
        const countText = String(group.node_count);

        ctx.font = "600 11px Inter, system-ui, sans-serif";
        const textW =
          ctx.measureText(badgeText).width +
          ctx.measureText(`  ${countText}`).width +
          (group.alert_count > 0
            ? ctx.measureText(` ${String(group.alert_count)}`).width + 18
            : 0) +
          20;
        const badgeH = 18;
        const badgeX = labelX - textW / 2;
        const badgeY = labelY - badgeH / 2;

        ctx.beginPath();
        roundedRectPath(
          ctx,
          badgeX - 6,
          badgeY - 2,
          textW + 12,
          badgeH + 4,
          10,
        );
        ctx.fillStyle = "rgba(7,14,25,0.88)";
        ctx.fill();
        ctx.strokeStyle = risky ? `${accent}40` : "rgba(148,163,184,0.15)";
        ctx.lineWidth = 1;
        ctx.stroke();

        ctx.fillStyle = risky ? accent : "rgba(148,163,184,0.85)";
        ctx.textAlign = "left";
        ctx.textBaseline = "middle";
        ctx.fillText(badgeText, badgeX, labelY + 1);

        const badgeTextW = ctx.measureText(badgeText).width;
        ctx.fillStyle = risky ? accent : "#60A5FA";
        ctx.font = "700 10px Inter, system-ui, sans-serif";
        ctx.fillText(` ${countText}`, badgeX + badgeTextW + 4, labelY + 1);

        if (group.alert_count > 0) {
          ctx.fillStyle = accent;
          ctx.font = "700 9px Inter, system-ui, sans-serif";
          ctx.fillText(
            ` ${String(group.alert_count)}!`,
            badgeX + badgeTextW + ctx.measureText(` ${countText}`).width + 8,
            labelY + 1,
          );
        }

        ctx.restore();
      }
    }

    sigma.on("afterRender", draw);
    draw();

    return () => {
      sigma.removeListener("afterRender", draw);
    };
  }, [sigma, groupMap]);

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: "absolute",
        inset: 0,
        pointerEvents: "none",
        zIndex: 0,
      }}
    />
  );
}
