import { memo } from "react";

import { activeFilterCount } from "../../lib/filtering/filters";
import { formatFreshness } from "../../lib/presentation/labels";
import type { TopologyFilters, TopologyGraph, TopologySummary } from "../../types";

type Props = {
  viewMode: "location" | "connection";
  nodeCount: number;
  edgeCount: number;
  groupCount: number;
  agentNodeCount: number;
  isolatedCount: number;
  onShowIsolated?: () => void;
  filters: TopologyFilters;
  searchQuery: string;
  searchTotal: number;
  focusedGroupLabel?: string | null;
  graph: TopologyGraph | null;
  summary: TopologySummary | null;
  realtimeStatus: string;
  isRefreshing: boolean;
};

function Dot() {
  return <span className="text-muted-foreground/30 select-none">·</span>;
}

function Pill({
  children,
  color,
  bg,
  border,
}: {
  children: React.ReactNode;
  color: string;
  bg: string;
  border: string;
}) {
  return (
    <span
      className="rounded-[4px] px-1.5 py-0.5 text-[10px]"
      style={{ color, background: bg, border }}
    >
      {children}
    </span>
  );
}

function TopologyStatusStrip({
  viewMode,
  nodeCount,
  edgeCount,
  groupCount,
  agentNodeCount,
  isolatedCount,
  onShowIsolated,
  filters,
  searchQuery,
  searchTotal,
  focusedGroupLabel,
  graph,
  summary,
  realtimeStatus,
  isRefreshing,
}: Props) {
  const filterCount = activeFilterCount(filters);
  const health = graph?.graph_health;
  const isTruncated = health?.nodes_truncated || health?.edges_truncated;
  const freshness = health?.freshness_seconds ?? graph?.freshness_seconds ?? null;
  const staleCount = summary?.stale_node_count ?? 0;
  const alertCount = summary?.alert_edge_count ?? 0;
  const realtimeConnected = realtimeStatus === "connected";

  const healthScore = 100 - Math.min(
    100,
    Math.round((staleCount / Math.max(1, nodeCount)) * 100 + (alertCount > 0 ? 20 : 0)),
  );
  const healthColor = healthScore >= 80 ? "#4ADE80" : healthScore >= 50 ? "#FBBF24" : "#F87171";

  return (
    <div
      className="pointer-events-none absolute bottom-3 left-[44px] z-10 flex flex-wrap items-center gap-1.5 rounded-lg border border-border/20 px-2.5 py-1"
      style={{ background: "rgba(10,15,26,0.80)", maxWidth: "calc(100% - 168px)" }}
    >
      <Pill
        color="#60A5FA"
        bg="rgba(96,165,250,0.1)"
        border="1px solid rgba(96,165,250,0.22)"
      >
        {viewMode === "location" ? "Location" : "Connection"}
      </Pill>

      <Dot />

      <span className="text-[10px] text-muted-foreground/70">
        <span className="font-semibold tabular-nums text-foreground/85">{nodeCount}</span>{" "}
        <span className="text-muted-foreground/55">nodes</span>
        {" · "}
        <span className="font-semibold tabular-nums text-foreground/85">{edgeCount}</span>{" "}
        <span className="text-muted-foreground/55">edges</span>
        {viewMode === "location" && groupCount > 0 && (
          <>
            {" · "}
            <span className="font-semibold tabular-nums text-foreground/85">{groupCount}</span>{" "}
            <span className="text-muted-foreground/55">groups</span>
          </>
        )}
      </span>

      <Dot />
      <Pill
        color={healthColor}
        bg={`${healthColor}15`}
        border={`1px solid ${healthColor}38`}
      >
        Health {healthScore}%
      </Pill>

      <Dot />
      <Pill
        color="#60A5FA"
        bg="rgba(96,165,250,0.10)"
        border="1px solid rgba(96,165,250,0.28)"
      >
        {agentNodeCount} agent{agentNodeCount === 1 ? "" : "s"}
      </Pill>

      {filterCount > 0 && (
        <>
          <Dot />
          <Pill
            color="#FBBF24"
            bg="rgba(251,191,36,0.08)"
            border="1px solid rgba(251,191,36,0.22)"
          >
            {filterCount} filter{filterCount !== 1 ? "s" : ""}
          </Pill>
        </>
      )}

      {alertCount > 0 && (
        <>
          <Dot />
          <Pill
            color="#F87171"
            bg="rgba(248,113,113,0.08)"
            border="1px solid rgba(248,113,113,0.22)"
          >
            {alertCount} alert edge{alertCount === 1 ? "" : "s"}
          </Pill>
        </>
      )}

      {searchQuery && (
        <>
          <Dot />
          <Pill
            color="#C084FC"
            bg="rgba(192,132,252,0.08)"
            border="1px solid rgba(192,132,252,0.22)"
          >
            {searchTotal} match{searchTotal !== 1 ? "es" : ""}
          </Pill>
        </>
      )}

      {focusedGroupLabel && (
        <>
          <Dot />
          <Pill
            color="#4ADE80"
            bg="rgba(74,222,128,0.08)"
            border="1px solid rgba(74,222,128,0.22)"
          >
            {focusedGroupLabel.length > 22
              ? `${focusedGroupLabel.slice(0, 20)}…`
              : focusedGroupLabel}
          </Pill>
        </>
      )}

      {freshness !== null && (
        <>
          <Dot />
          <span className="text-[10px] text-muted-foreground/45">{formatFreshness(freshness)}</span>
        </>
      )}

      {staleCount > 0 && (
        <>
          <Dot />
          <span className="text-[10px]" style={{ color: "#F97316" }}>
            {staleCount} stale
          </span>
        </>
      )}

      {isTruncated && (
        <>
          <Dot />
          <span className="text-[10px]" style={{ color: "#FBBF24" }}>truncated</span>
        </>
      )}

      <Dot />

      <span
        className="h-[6px] w-[6px] shrink-0 rounded-full"
        style={{ background: realtimeConnected ? "#4ADE80" : "#6B7280" }}
        title={`Realtime: ${realtimeStatus}`}
      />

      {isRefreshing && (
        <span className="text-[10px] text-muted-foreground/45">refreshing…</span>
      )}

      {isolatedCount > 0 && (
        <>
          <Dot />
          <button
            type="button"
            onClick={onShowIsolated}
            disabled={!onShowIsolated}
            className="rounded-[4px] px-1.5 py-0.5 text-[10px] transition-colors hover:brightness-125"
            style={{
              color: "#94A3B8",
              background: "rgba(148,163,184,0.10)",
              border: "1px solid rgba(148,163,184,0.30)",
              pointerEvents: "auto",
              cursor: onShowIsolated ? "pointer" : "default",
            }}
            title="Show isolated nodes on canvas"
          >
            {isolatedCount} isolated
          </button>
        </>
      )}
    </div>
  );
}

export default memo(TopologyStatusStrip);
