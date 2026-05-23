import { memo, useState } from "react";

import { NODE_TYPE_LABELS, SEVERITY_COLORS, edgeVisual, nodeVisualByType } from "../lib/visuals";
import type { TopologyViewMode } from "../types";

const EDGE_LEGEND_ROWS: Array<{ key: string; label: string }> = [
  { key: "alert_related",       label: "Alert context" },
  { key: "exposure_related",    label: "Exposure context" },
  { key: "observed_flow",       label: "Observed flow" },
  { key: "listens_on",          label: "Listening service" },
  { key: "resolved_dns",        label: "DNS" },
  { key: "member_of_subnet",    label: "Subnet member" },
  { key: "route_next_hop",      label: "Route / next hop" },
  { key: "inferred_relationship", label: "Inferred" },
];

const SEVERITY_KEYS = ["critical", "high", "medium", "low", "informational", "unknown"] as const;
const NODE_LEGEND_KEYS = Object.keys(NODE_TYPE_LABELS);

function EdgeSample({ edgeKey, dim }: { edgeKey: string; dim: boolean }) {
  const v = edgeVisual({ edge_type: edgeKey, confidence: 80 });
  return (
    <svg width="28" height="8" style={{ overflow: "visible", flexShrink: 0 }}>
      <line
        x1="0" y1="4" x2="24" y2="4"
        stroke={v.stroke}
        strokeWidth={v.width + 0.3}
        strokeDasharray={v.dashArray}
        opacity={dim ? 0.25 : Math.min(1, v.opacity * 2.5 + 0.2)}
      />
    </svg>
  );
}

function LegendSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="mb-1.5 text-[9px] font-semibold uppercase tracking-wider text-muted-foreground/45">
        {title}
      </div>
      <div className="space-y-1">{children}</div>
    </div>
  );
}

function LegendRow({
  label,
  active,
  dimmed,
  onClick,
  children,
}: {
  label: string;
  active?: boolean;
  dimmed?: boolean;
  onClick?: () => void;
  children: React.ReactNode;
}) {
  const interactive = Boolean(onClick);
  return (
    <button
      type="button"
      disabled={!interactive}
      onClick={onClick}
      className="flex w-full items-center gap-2 rounded text-left text-[10px]"
      style={{
        opacity: dimmed ? 0.4 : 1,
        cursor: interactive ? "pointer" : "default",
        background: active ? "rgba(96,165,250,0.10)" : "transparent",
        padding: interactive ? "2px 4px" : "0",
        transition: "opacity 140ms ease, background 140ms ease",
      }}
    >
      <span className="flex w-7 shrink-0 items-center">{children}</span>
      <span
        className={active ? "text-foreground/95" : "text-muted-foreground/70"}
        style={{ fontWeight: active ? 700 : 400 }}
      >
        {label}
      </span>
    </button>
  );
}

type Props = {
  viewMode: TopologyViewMode;
  onFilterToggle?: (edgeType: string) => void;
};

function TopologyLegend({ viewMode, onFilterToggle }: Props) {
  const [expanded, setExpanded] = useState(false);
  const [activeEdgeType, setActiveEdgeType] = useState<string | null>(null);

  const handleEdgeRowClick = (edgeKey: string) => {
    setActiveEdgeType((prev) => (prev === edgeKey ? null : edgeKey));
    onFilterToggle?.(edgeKey);
  };

  const resetActive = () => {
    setActiveEdgeType(null);
  };

  return (
    <div className="absolute bottom-[68px] left-2 z-20 select-none" style={{ pointerEvents: "all" }}>
      <div
        className="rounded-xl border border-border/35"
        style={{
          background: "rgba(10,16,28,0.94)",
          backdropFilter: "blur(10px)",
          minWidth: 164,
        }}
      >
        <div className="flex items-center justify-between px-2.5 py-1.5">
          <span className="text-[9px] font-semibold uppercase tracking-[0.14em] text-muted-foreground/50">
            Legend
          </span>
          <div className="flex items-center gap-1">
            {activeEdgeType && (
              <button
                type="button"
                className="rounded px-1.5 text-[9px] font-medium text-muted-foreground/70 transition-colors hover:text-foreground/95"
                onClick={resetActive}
                title="Reset legend filter"
              >
                Reset
              </button>
            )}
            <button
              type="button"
              className="flex h-4 w-4 items-center justify-center rounded text-[11px] text-muted-foreground/45 transition-colors hover:text-foreground/80"
              onClick={() => setExpanded((p) => !p)}
              title={expanded ? "Collapse legend" : "Expand legend"}
            >
              {expanded ? "−" : "+"}
            </button>
          </div>
        </div>

        <div className="flex items-center gap-1.5 border-t border-border/20 px-2.5 py-1.5">
          {SEVERITY_KEYS.slice(0, 5).map((sev) => (
            <span
              key={sev}
              className="h-[8px] w-[8px] shrink-0 rounded-full"
              style={{ background: SEVERITY_COLORS[sev] }}
              title={sev}
            />
          ))}
          <span className="ml-0.5 text-[9px] text-muted-foreground/38">severity</span>
        </div>

        {expanded && (
          <div
            className="flex flex-col gap-3 border-t border-border/20 px-2.5 py-2.5"
            style={{ maxHeight: 360, overflowY: "auto" }}
          >
            {viewMode === "connection" && (
              <LegendSection title="Node types">
                {NODE_LEGEND_KEYS.map((key) => {
                  const v = nodeVisualByType(key);
                  return (
                    <LegendRow key={key} label={NODE_TYPE_LABELS[key] ?? key}>
                      <span
                        className="inline-block h-[9px] w-[9px] rounded-full"
                        style={{ background: v.fill, border: `1px solid ${v.stroke}` }}
                      />
                    </LegendRow>
                  );
                })}
              </LegendSection>
            )}

            {viewMode === "location" && (
              <LegendSection title="Group types">
                <LegendRow label="Agent (observed host)"><span className="text-[13px] text-[#60A5FA]">◎</span></LegendRow>
                <LegendRow label="Subnet (CIDR block)"><span className="text-[13px] text-[#FBBF24]">⌁</span></LegendRow>
                <LegendRow label="Scope (IP class)"><span className="text-[13px] text-muted-foreground/60">◌</span></LegendRow>
              </LegendSection>
            )}

            <LegendSection title="Edge types">
              {EDGE_LEGEND_ROWS.map(({ key, label }) => {
                const isActive = activeEdgeType === key;
                const isDim = activeEdgeType !== null && !isActive;
                return (
                  <LegendRow
                    key={key}
                    label={label}
                    active={isActive}
                    dimmed={isDim}
                    onClick={() => handleEdgeRowClick(key)}
                  >
                    <EdgeSample edgeKey={key} dim={isDim} />
                  </LegendRow>
                );
              })}
            </LegendSection>

            <LegendSection title="Severity">
              {SEVERITY_KEYS.map((sev) => (
                <LegendRow key={sev} label={sev.charAt(0).toUpperCase() + sev.slice(1)}>
                  <span
                    className="inline-block h-[8px] w-[8px] rounded-full"
                    style={{ background: SEVERITY_COLORS[sev] }}
                  />
                </LegendRow>
              ))}
            </LegendSection>

            <LegendSection title="State">
              <LegendRow label="Alert badge">
                <span className="inline-block h-[7px] w-[7px] rounded-full" style={{ background: "#F87171" }} />
              </LegendRow>
              <LegendRow label="Stale / offline">
                <span className="inline-block h-[9px] w-[9px] rounded-full border border-muted-foreground/30 opacity-45" />
              </LegendRow>
              <LegendRow label="Low confidence">
                <svg width="28" height="8" style={{ flexShrink: 0 }}>
                  <line x1="0" y1="4" x2="24" y2="4" stroke="#60A5FA" strokeWidth="1.2" strokeDasharray="4 3" opacity="0.55" />
                </svg>
              </LegendRow>
              <LegendRow label="Focused group">
                <span className="inline-block h-[7px] w-[7px] rounded-full" style={{ background: "#4ADE80" }} />
              </LegendRow>
            </LegendSection>
          </div>
        )}
      </div>
    </div>
  );
}

export default memo(TopologyLegend);
