import { memo, useState } from "react";

import { NODE_TYPE_LABELS, SEVERITY_COLORS, edgeVisual, nodeVisualByType } from "../lib/visuals";
import type { TopologyViewMode } from "../types";

const EDGE_LEGEND_ROWS: Array<{ key: string; label: string }> = [
  { key: "observed_flow",       label: "Observed flow" },
  { key: "listens_on",          label: "Listening service" },
  { key: "resolved_dns",        label: "DNS" },
  { key: "alert_related",       label: "Alert context" },
  { key: "exposure_related",    label: "Exposure context" },
  { key: "member_of_subnet",    label: "Subnet member" },
  { key: "route_next_hop",      label: "Route / next hop" },
  { key: "inferred_relationship", label: "Inferred" },
];

const SEVERITY_LEGEND_ROWS: Array<keyof typeof SEVERITY_COLORS> = [
  "critical", "high", "medium", "low", "informational", "unknown",
];

const NODE_LEGEND_KEYS = Object.keys(NODE_TYPE_LABELS);

function EdgeSample({ edgeKey }: { edgeKey: string }) {
  const v = edgeVisual({ edge_type: edgeKey, confidence: 80 });
  return (
    <svg width="32" height="8" style={{ overflow: "visible", flexShrink: 0 }}>
      <line
        x1="0" y1="4" x2="28" y2="4"
        stroke={v.stroke}
        strokeWidth={v.width + 0.2}
        strokeDasharray={v.dashArray}
        opacity={v.opacity + 0.1}
      />
    </svg>
  );
}

function LegendSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="mb-1 text-[9px] font-semibold uppercase tracking-wider text-muted-foreground/50">
        {title}
      </div>
      <div className="space-y-1">{children}</div>
    </div>
  );
}

function LegendRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2 text-[10px]">
      <span className="flex w-8 shrink-0 items-center justify-start">{children}</span>
      <span className="text-muted-foreground/75">{label}</span>
    </div>
  );
}

type Props = {
  viewMode: TopologyViewMode;
};

function TopologyLegend({ viewMode }: Props) {
  const [open, setOpen] = useState(false);

  return (
    <div className="absolute bottom-10 left-2 z-20" style={{ pointerEvents: "all" }}>
      {open ? (
        <div
          className="flex flex-col gap-3 rounded-lg border border-border/40 p-3"
          style={{
            background: "rgba(10,15,26,0.95)",
            width: 176,
            maxHeight: 380,
            overflowY: "auto",
          }}
        >
          <div className="flex items-center justify-between">
            <span className="text-[9px] font-semibold uppercase tracking-widest text-muted-foreground/60">
              Legend
            </span>
            <button
              type="button"
              className="text-[11px] text-muted-foreground/50 hover:text-foreground"
              onClick={() => setOpen(false)}
            >
              ✕
            </button>
          </div>

          {viewMode === "connection" && (
            <LegendSection title="Node types">
              {NODE_LEGEND_KEYS.map((key) => {
                const v = nodeVisualByType(key);
                return (
                  <LegendRow key={key} label={NODE_TYPE_LABELS[key] ?? key}>
                    <span
                      className="inline-block h-[9px] w-[9px] shrink-0 rounded-full"
                      style={{ background: v.fill, border: `1px solid ${v.stroke}` }}
                    />
                  </LegendRow>
                );
              })}
            </LegendSection>
          )}

          <LegendSection title="Edge types">
            {EDGE_LEGEND_ROWS.map(({ key, label }) => (
              <LegendRow key={key} label={label}>
                <EdgeSample edgeKey={key} />
              </LegendRow>
            ))}
          </LegendSection>

          <LegendSection title="Severity">
            {SEVERITY_LEGEND_ROWS.map((sev) => (
              <LegendRow key={sev} label={sev.charAt(0).toUpperCase() + sev.slice(1)}>
                <span
                  className="inline-block h-[8px] w-[8px] shrink-0 rounded-full"
                  style={{ background: SEVERITY_COLORS[sev] }}
                />
              </LegendRow>
            ))}
          </LegendSection>

          <LegendSection title="State">
            <LegendRow label="Stale node">
              <span className="inline-block h-[9px] w-[9px] shrink-0 rounded-full border border-muted-foreground/30 opacity-50" />
            </LegendRow>
            <LegendRow label="Low confidence">
              <svg width="32" height="8" style={{ flexShrink: 0 }}>
                <line x1="0" y1="4" x2="28" y2="4" stroke="#60A5FA" strokeWidth="1.2" strokeDasharray="4 3" opacity="0.55" />
              </svg>
            </LegendRow>
            <LegendRow label="Alert badge">
              <span className="inline-block h-[7px] w-[7px] shrink-0 rounded-full" style={{ background: "#F87171" }} />
            </LegendRow>
            <LegendRow label="Group focus">
              <span className="inline-block h-[7px] w-[7px] shrink-0 rounded-full" style={{ background: "#4ADE80" }} />
            </LegendRow>
          </LegendSection>
        </div>
      ) : (
        <button
          type="button"
          className="flex h-7 w-7 items-center justify-center rounded-lg border border-border/40 text-[13px] text-muted-foreground/55 transition-colors hover:bg-muted/25 hover:text-foreground"
          style={{ background: "rgba(10,15,26,0.92)" }}
          onClick={() => setOpen(true)}
          title="Show legend"
        >
          ≡
        </button>
      )}
    </div>
  );
}

export default memo(TopologyLegend);
