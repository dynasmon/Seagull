import { memo } from "react";

import { activeFilterCount } from "../../lib/filtering/filters";
import { compactNumber, formatFreshness } from "../../lib/presentation/labels";
import type { TopologyFilters, TopologyGraph, TopologySummary } from "../../types";

type Props = {
  viewMode: "location" | "connection";
  nodeCount: number;
  edgeCount: number;
  groupCount: number;
  hiddenCount: number;
  alertNodeCount: number;
  externalCount: number;
  onShowHidden?: () => void;
  filters: TopologyFilters;
  searchQuery: string;
  searchTotal: number;
  searchMatchTotal: number;
  focusedGroupLabel?: string | null;
  graph: TopologyGraph | null;
  summary: TopologySummary | null;
  realtimeStatus: string;
  isRefreshing: boolean;
};

function Divider() {
  return <span className="select-none text-muted-foreground/25">·</span>;
}

function Pill({
  children,
  color,
  title,
}: {
  children: React.ReactNode;
  color: string;
  title?: string;
}) {
  return (
    <span
      className="rounded-[4px] px-1.5 py-0.5 text-[10px]"
      title={title}
      style={{ color, background: `${color}14`, border: `1px solid ${color}38` }}
    >
      {children}
    </span>
  );
}

function Stat({ value, label, title }: { value: number; label: string; title?: string }) {
  return (
    <span className="text-[10px] text-muted-foreground/70" title={title}>
      <span className="font-semibold tabular-nums text-foreground/85">{compactNumber(value)}</span>{" "}
      <span className="text-muted-foreground/55">{label}</span>
    </span>
  );
}

function TopologyStatusStrip({
  viewMode,
  nodeCount,
  edgeCount,
  groupCount,
  hiddenCount,
  alertNodeCount,
  externalCount,
  onShowHidden,
  filters,
  searchQuery,
  searchTotal,
  searchMatchTotal,
  focusedGroupLabel,
  graph,
  summary,
  realtimeStatus,
  isRefreshing,
}: Props) {
  const filterCount = activeFilterCount(filters);
  const health = graph?.graph_health;
  const isTruncated = Boolean(health?.nodes_truncated || health?.edges_truncated);
  const freshness = health?.freshness_seconds ?? graph?.freshness_seconds ?? null;
  const projectedNodes = Number(summary?.total_nodes ?? 0);
  const projectedStale = Number(summary?.stale_node_count ?? 0);
  const realtimeConnected = realtimeStatus === "connected";

  return (
    <div
      className="pointer-events-none absolute bottom-3 left-[44px] z-10 flex flex-wrap items-center gap-1.5 rounded-lg border border-border/25 px-2.5 py-1"
      style={{ background: "rgba(10,15,26,0.86)", maxWidth: "calc(100% - 168px)" }}
    >
      <Pill color="#22D3EE" title={viewMode === "location" ? "Groups and the links between them" : "Individual nodes inside each group"}>
        {viewMode === "location" ? "Location" : "Connection"}
      </Pill>

      <Divider />
      <Stat value={nodeCount} label={viewMode === "location" ? "groups" : "nodes"} title="Drawn on the canvas right now" />
      <Divider />
      <Stat value={edgeCount} label="links" title="Relationships drawn on the canvas" />
      {viewMode === "connection" && groupCount > 0 && (
        <>
          <Divider />
          <Stat value={groupCount} label="groups" />
        </>
      )}

      {alertNodeCount > 0 && (
        <>
          <Divider />
          <Pill color="#F87171" title="Nodes on the canvas that carry at least one alert">
            {alertNodeCount} with alerts
          </Pill>
        </>
      )}

      {externalCount > 0 && (
        <>
          <Divider />
          <Pill color="#94A3B8" title="Public internet endpoints seen in observed traffic — external peers, not hosts you own">
            {externalCount} internet
          </Pill>
        </>
      )}

      {filterCount > 0 && (
        <>
          <Divider />
          <Pill color="#FACC15" title="Active filters narrowing this view">
            {filterCount} filter{filterCount !== 1 ? "s" : ""}
          </Pill>
        </>
      )}

      {searchQuery && (
        <>
          <Divider />
          <Pill
            color="#C084FC"
            title={
              searchMatchTotal > searchTotal
                ? `${searchMatchTotal} nodes match; ${searchTotal} are drawn. Use the filter rail to keep only matches.`
                : undefined
            }
          >
            {searchMatchTotal > searchTotal
              ? `${searchTotal} of ${searchMatchTotal} matches`
              : `${searchTotal} match${searchTotal !== 1 ? "es" : ""}`}
          </Pill>
        </>
      )}

      {focusedGroupLabel && (
        <>
          <Divider />
          <Pill color="#4ADE80" title={`Focused on ${focusedGroupLabel}`}>
            {focusedGroupLabel.length > 22 ? `${focusedGroupLabel.slice(0, 20)}…` : focusedGroupLabel}
          </Pill>
        </>
      )}

      {hiddenCount > 0 && (
        <>
          <Divider />
          <button
            type="button"
            onClick={onShowHidden}
            disabled={!onShowHidden}
            className="rounded-[4px] px-1.5 py-0.5 text-[10px] transition-colors hover:brightness-125"
            style={{
              color: "#94A3B8",
              background: "rgba(148,163,184,0.10)",
              border: "1px solid rgba(148,163,184,0.30)",
              pointerEvents: "auto",
              cursor: onShowHidden ? "pointer" : "default",
            }}
            title="Nodes with no observed relationship in this window — click to draw them"
          >
            {hiddenCount} unlinked
          </button>
        </>
      )}

      <Divider />
      <span
        className="text-[10px] text-muted-foreground/45"
        title={
          projectedNodes > 0
            ? `Projection holds ${compactNumber(projectedNodes)} nodes, ${compactNumber(projectedStale)} not refreshed in the last run`
            : undefined
        }
      >
        {formatFreshness(freshness)}
      </span>

      {isTruncated && (
        <>
          <Divider />
          <span
            className="text-[10px]"
            style={{ color: "#FACC15" }}
            title={`Query capped at ${health?.max_nodes_applied ?? 0} nodes / ${health?.max_edges_applied ?? 0} links — narrow the filters to see the rest`}
          >
            capped
          </span>
        </>
      )}

      <Divider />
      <span
        className="h-[6px] w-[6px] shrink-0 rounded-full"
        style={{ background: realtimeConnected ? "#4ADE80" : "#6B7280" }}
        title={`Realtime: ${realtimeStatus}`}
      />
      {isRefreshing && <span className="text-[10px] text-muted-foreground/45">refreshing…</span>}
    </div>
  );
}

export default memo(TopologyStatusStrip);
