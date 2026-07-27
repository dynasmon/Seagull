import { memo, useState } from "react";

import { cx } from "@/shared/lib/cx";

import { groupTypeMeta } from "../../lib/presentation/groups";
import {
  EDGE_TYPE_LABELS,
  NODE_TYPE_LABELS,
  SEVERITY_COLORS,
  edgeVisual,
  nodeVisualByType,
} from "../../lib/presentation/visuals";
import type { TopologyViewMode } from "../../types";

const EDGE_LEGEND_KEYS = [
  "alert_related",
  "exposure_related",
  "observed_flow",
  "listens_on",
  "resolved_dns",
  "route_next_hop",
  "member_of_subnet",
  "owns_interface",
  "same_agent",
  "inferred_relationship",
];

const NODE_LEGEND_KEYS = [
  "agent",
  "gateway",
  "subnet",
  "host",
  "interface",
  "service",
  "docker_network",
  "external_ip",
  "unknown",
];

const SEVERITY_KEYS = ["critical", "high", "medium", "low", "informational", "unknown"] as const;

function EdgeSample({ edgeKey, dim }: { edgeKey: string; dim: boolean }) {
  const visual = edgeVisual({ edge_type: edgeKey, confidence: 80 });
  return (
    <svg width="26" height="8" style={{ overflow: "visible", flexShrink: 0 }}>
      <line
        x1="0"
        y1="4"
        x2="24"
        y2="4"
        stroke={visual.stroke}
        strokeWidth={visual.width + 0.4}
        strokeDasharray={visual.dashArray}
        opacity={dim ? 0.25 : Math.min(1, visual.opacity * 1.6 + 0.25)}
      />
    </svg>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="mb-1.5 text-[9px] font-semibold uppercase tracking-[0.12em] text-muted-foreground/45">
        {title}
      </div>
      <div className="space-y-0.5">{children}</div>
    </div>
  );
}

function Row({
  label,
  title,
  active,
  dimmed,
  onClick,
  children,
}: {
  label: string;
  title?: string;
  active?: boolean;
  dimmed?: boolean;
  onClick?: () => void;
  children: React.ReactNode;
}) {
  const interactive = Boolean(onClick);
  return (
    <button
      type="button"
      title={title}
      disabled={!interactive}
      onClick={onClick}
      aria-pressed={interactive ? Boolean(active) : undefined}
      className={cx(
        "flex w-full items-center gap-2 rounded text-left text-[10px] transition-colors",
        interactive && "hover:bg-white/5",
      )}
      style={{
        opacity: dimmed ? 0.35 : 1,
        cursor: interactive ? "pointer" : "default",
        background: active ? "rgba(34,211,238,0.12)" : "transparent",
        padding: "2px 4px",
      }}
    >
      <span className="flex w-7 shrink-0 items-center">{children}</span>
      <span
        className={active ? "text-foreground/95" : "text-muted-foreground/75"}
        style={{ fontWeight: active ? 600 : 400 }}
      >
        {label}
      </span>
    </button>
  );
}

type Props = {
  viewMode: TopologyViewMode;
  activeEdgeTypes: string[];
  onEdgeTypeToggle: (edgeType: string) => void;
  onEdgeTypeReset: () => void;
};

function TopologyLegend({ viewMode, activeEdgeTypes, onEdgeTypeToggle, onEdgeTypeReset }: Props) {
  const [expanded, setExpanded] = useState(false);
  const hasEdgeFilter = activeEdgeTypes.length > 0;

  return (
    <div className="absolute bottom-[68px] left-2 z-20 select-none" style={{ pointerEvents: "all" }}>
      <div
        className="rounded-xl border border-border/35"
        style={{ background: "rgba(10,16,28,0.95)", backdropFilter: "blur(10px)", minWidth: 178 }}
      >
        <button
          type="button"
          className="flex w-full items-center justify-between gap-2 px-2.5 py-1.5"
          onClick={() => setExpanded((prev) => !prev)}
          aria-expanded={expanded}
        >
          <span className="text-[9px] font-semibold uppercase tracking-[0.14em] text-muted-foreground/55">
            Legend
          </span>
          <span className="flex items-center gap-1.5">
            {hasEdgeFilter && (
              <span
                className="rounded-[3px] px-1 text-[9px] font-semibold"
                style={{ color: "#22D3EE", background: "rgba(34,211,238,0.14)" }}
              >
                {activeEdgeTypes.length}
              </span>
            )}
            <span className="text-[11px] text-muted-foreground/50">{expanded ? "−" : "+"}</span>
          </span>
        </button>

        <div className="flex items-center gap-1.5 border-t border-border/20 px-2.5 py-1.5">
          {SEVERITY_KEYS.slice(0, 5).map((severity) => (
            <span
              key={severity}
              className="h-[8px] w-[8px] shrink-0 rounded-full"
              style={{ background: SEVERITY_COLORS[severity] }}
              title={severity}
            />
          ))}
          <span className="ml-0.5 text-[9px] text-muted-foreground/45">severity</span>
        </div>

        {expanded && (
          <div
            className="flex w-[212px] flex-col gap-3 border-t border-border/20 px-2.5 py-2.5"
            style={{ maxHeight: 380, overflowY: "auto" }}
          >
            {viewMode === "connection" ? (
              <Section title="Node types">
                {NODE_LEGEND_KEYS.map((key) => {
                  const visual = nodeVisualByType(key);
                  return (
                    <Row key={key} label={NODE_TYPE_LABELS[key] ?? key}>
                      <span
                        className="inline-block h-[10px] w-[10px] rounded-full"
                        style={{
                          background: visual.fill,
                          border: `1px ${key === "external_ip" ? "dashed" : "solid"} ${visual.stroke}`,
                        }}
                      />
                    </Row>
                  );
                })}
              </Section>
            ) : (
              <Section title="Group types">
                {["agent", "subnet", "ip_scope", "ungrouped"].map((key) => {
                  const meta = groupTypeMeta(key);
                  return (
                    <Row key={key} label={meta.label} title={meta.description}>
                      <span
                        className="inline-block h-[10px] w-[10px] rounded-[3px]"
                        style={{ background: `${meta.color}30`, border: `1px solid ${meta.color}` }}
                      />
                    </Row>
                  );
                })}
              </Section>
            )}

            <Section title={hasEdgeFilter ? "Relationships · filtering" : "Relationships · click to filter"}>
              {EDGE_LEGEND_KEYS.map((key) => {
                const isActive = activeEdgeTypes.includes(key);
                return (
                  <Row
                    key={key}
                    label={EDGE_TYPE_LABELS[key] ?? key}
                    active={isActive}
                    dimmed={hasEdgeFilter && !isActive}
                    onClick={() => onEdgeTypeToggle(key)}
                  >
                    <EdgeSample edgeKey={key} dim={hasEdgeFilter && !isActive} />
                  </Row>
                );
              })}
              {hasEdgeFilter && (
                <button
                  type="button"
                  className="mt-1 w-full rounded px-1.5 py-1 text-left text-[10px] text-muted-foreground/75 hover:bg-white/5 hover:text-foreground/95"
                  onClick={onEdgeTypeReset}
                >
                  Show all relationships
                </button>
              )}
            </Section>

            <Section title="Severity">
              {SEVERITY_KEYS.map((severity) => (
                <Row key={severity} label={severity.charAt(0).toUpperCase() + severity.slice(1)}>
                  <span
                    className="inline-block h-[8px] w-[8px] rounded-full"
                    style={{ background: SEVERITY_COLORS[severity] }}
                  />
                </Row>
              ))}
            </Section>

            <Section title="Markers">
              <Row label="Security signal" title="Ring drawn around nodes with alerts, exposure, or high risk">
                <span
                  className="inline-block h-[11px] w-[11px] rounded-full"
                  style={{ border: "1.5px solid #F87171" }}
                />
              </Row>
              <Row label="Part of this host" title="Assets reported by the local Seagull agent">
                <span className="inline-block h-[8px] w-[8px] rounded-full" style={{ background: "#22D3EE" }} />
              </Row>
              <Row label="Outside your network" title="Public internet endpoints use a dashed outline">
                <span
                  className="inline-block h-[10px] w-[10px] rounded-full"
                  style={{ border: "1px dashed #94A3B8" }}
                />
              </Row>
              <Row label="Stale / not seen recently">
                <span
                  className="inline-block h-[10px] w-[10px] rounded-full border border-muted-foreground/30"
                  style={{ opacity: 0.45 }}
                />
              </Row>
            </Section>
          </div>
        )}
      </div>
    </div>
  );
}

export default memo(TopologyLegend);
