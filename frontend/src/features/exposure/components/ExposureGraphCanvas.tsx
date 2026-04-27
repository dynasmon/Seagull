import { useCallback, useEffect, useRef, useState } from "react";
import { computeGraphLayout, severityColor } from "../graphLayout";
import { ExposureGraph, ExposureGraphNode } from "../types";

type Props = {
  graph: ExposureGraph;
  onNodeClick?: (node: ExposureGraphNode) => void;
};

export function ExposureGraphCanvas({ graph, onNodeClick }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [containerWidth, setContainerWidth] = useState(900);
  const [hovered, setHovered] = useState<string | null>(null);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const obs = new ResizeObserver((entries) => {
      const w = entries[0]?.contentRect.width;
      if (w && w > 0) setContainerWidth(w);
    });
    obs.observe(el);
    const initial = el.getBoundingClientRect().width;
    if (initial > 0) setContainerWidth(initial);
    return () => obs.disconnect();
  }, []);

  const layout = computeGraphLayout(graph.root_node_key, graph.nodes, graph.edges, containerWidth);

  const handleNodeClick = useCallback(
    (nodeKey: string) => {
      const node = graph.nodes.find((n) => n.node_key === nodeKey);
      if (node) onNodeClick?.(node);
    },
    [graph.nodes, onNodeClick],
  );

  const isFocused = (key: string) => graph.recommended_focus_node_keys.includes(key);

  return (
    <div ref={containerRef} className="w-full overflow-x-auto rounded-lg border border-border/60 bg-background/40 p-2">
      <svg
        width={layout.width}
        height={Math.max(layout.height, 200)}
        className="block"
        aria-label="Exposure attack graph"
      >
        <defs>
          <marker id="exp-arrow" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
            <polygon points="0 0, 8 3, 0 6" fill="#6b7280" fillOpacity="0.7" />
          </marker>
        </defs>

        {layout.edges.map((edge) => (
          <line
            key={edge.edge_key}
            x1={edge.x1}
            y1={edge.y1}
            x2={edge.x2}
            y2={edge.y2}
            stroke="#4b5563"
            strokeWidth={1.5}
            strokeOpacity={0.5}
            markerEnd="url(#exp-arrow)"
          />
        ))}

        {layout.nodes.map((node) => {
          const color = severityColor(node.severity);
          const isRoot = node.node_key === graph.root_node_key;
          const isFocus = isFocused(node.node_key);
          const isHov = hovered === node.node_key;

          return (
            <g
              key={node.node_key}
              transform={`translate(${node.x},${node.y})`}
              onClick={() => handleNodeClick(node.node_key)}
              onMouseEnter={() => setHovered(node.node_key)}
              onMouseLeave={() => setHovered(null)}
              style={{ cursor: onNodeClick ? "pointer" : "default" }}
              role={onNodeClick ? "button" : undefined}
              aria-label={node.label}
            >
              {isRoot && (
                <circle
                  r={node.radius + 8}
                  fill="none"
                  stroke={color}
                  strokeWidth={1}
                  strokeOpacity={0.35}
                  strokeDasharray="4 3"
                />
              )}
              <circle
                r={node.radius + (isRoot ? 3 : isFocus ? 2 : 0)}
                fill={color}
                fillOpacity={isHov ? 0.35 : 0.15}
                stroke={color}
                strokeWidth={isRoot ? 2.5 : isFocus ? 2 : 1.5}
                strokeOpacity={0.8}
              />
              <text
                textAnchor="middle"
                dominantBaseline="middle"
                fontSize={9}
                className="select-none fill-foreground"
              >
                {node.label.length > 12 ? `${node.label.slice(0, 11)}…` : node.label}
              </text>
              <text
                y={node.radius + 13}
                textAnchor="middle"
                fontSize={8}
                className="select-none fill-muted-foreground"
              >
                {node.node_type}
              </text>
            </g>
          );
        })}
      </svg>

      {graph.graph_health.nodes_truncated && (
        <p className="mt-2 px-2 font-mono text-[11px] text-warning">
          Truncated — showing {graph.graph_health.node_count} nodes / {graph.graph_health.edge_count} edges.
        </p>
      )}
    </div>
  );
}
