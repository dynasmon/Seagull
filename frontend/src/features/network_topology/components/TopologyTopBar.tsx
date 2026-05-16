import { useRef } from "react";

import { Button } from "@/shared/components/Button";
import { cx } from "@/shared/lib/cx";

import { activeFilterCount } from "../lib/filters";
import { formatFreshness } from "../lib/labels";
import { severityColor } from "../lib/visuals";
import type { TopologyFilters, TopologyGraph, TopologySummary } from "../types";

type LiveState = {
  isRefreshing: boolean;
  realtimeStatus: string;
  lastUpdatedAt: Date | null;
};

type Props = {
  summary: TopologySummary | null;
  graph: TopologyGraph | null;
  filters: TopologyFilters;
  liveState: LiveState;
  isAdmin: boolean;
  filterRailOpen: boolean;
  recalculateBusy: boolean;
  isFullscreen: boolean;
  searchQuery: string;
  searchTotal: number;
  searchMatchIndex: number;
  focusedGroupLabel?: string | null;
  onRefresh: () => void;
  onRecalculate: () => void;
  onToggleFilterRail: () => void;
  onToggleFullscreen: () => void;
  onSearchChange: (q: string) => void;
  onPrevMatch: () => void;
  onNextMatch: () => void;
  onClearFocus?: () => void;
};

export function TopologyTopBar({
  summary,
  graph,
  filters,
  liveState,
  isAdmin,
  filterRailOpen,
  recalculateBusy,
  isFullscreen,
  searchQuery,
  searchTotal,
  searchMatchIndex,
  focusedGroupLabel,
  onRefresh,
  onRecalculate,
  onToggleFilterRail,
  onToggleFullscreen,
  onSearchChange,
  onPrevMatch,
  onNextMatch,
  onClearFocus,
}: Props) {
  const searchInputRef = useRef<HTMLInputElement>(null);
  const health = graph?.graph_health;
  const nodeCount = health?.node_count ?? 0;
  const edgeCount = health?.edge_count ?? 0;
  const truncated = health?.nodes_truncated || health?.edges_truncated;
  const freshness = health?.freshness_seconds ?? graph?.freshness_seconds ?? null;
  const alertEdges = summary?.alert_edge_count ?? 0;
  const staleNodes = summary?.stale_node_count ?? 0;
  const highestSev = summary?.node_type_breakdown?.length
    ? (() => {
        const severities = ["critical", "high", "medium", "low", "informational"];
        for (const sev of severities) {
          const hasNodes = graph?.nodes.some((n) => String(n.severity).toLowerCase() === sev);
          if (hasNodes) return sev;
        }
        return null;
      })()
    : null;

  const filterCount = activeFilterCount(filters);
  const projected = health?.projected_at ?? graph?.projected_at ?? summary?.projected_at ?? null;
  const realtimeConnected = liveState.realtimeStatus === "connected";
  const hasSearchResults = searchTotal > 0;
  const displayMatchIndex = hasSearchResults ? searchMatchIndex + 1 : 0;

  return (
    <div
      className={cx(
        "flex shrink-0 items-center gap-2 border-b border-border/30 bg-[#0a0f1a]/80 px-3 py-1.5",
        "flex-wrap",
      )}
    >
      <button
        type="button"
        className={cx(
          "mr-1 flex h-7 w-7 shrink-0 items-center justify-center rounded-[5px] text-[14px] transition-all",
          filterRailOpen
            ? "bg-primary/15 text-primary"
            : "text-muted-foreground hover:bg-muted/40",
        )}
        onClick={onToggleFilterRail}
        title={filterRailOpen ? "Collapse filter rail" : "Expand filter rail"}
      >
        ☰
      </button>

      <div className="flex items-center gap-1 text-[11px]">
        <span className="font-bold text-foreground">{nodeCount}</span>
        <span className="text-muted-foreground/60">nodes</span>
        <span className="text-muted-foreground/40">·</span>
        <span className="font-bold text-foreground">{edgeCount}</span>
        <span className="text-muted-foreground/60">edges</span>
      </div>

      {alertEdges > 0 && (
        <div
          className="flex items-center gap-1 rounded-[4px] px-1.5 py-0.5 text-[11px]"
          style={{ background: "rgba(248,113,113,0.12)", border: "1px solid rgba(248,113,113,0.3)", color: "#F87171" }}
        >
          <span>⚠</span>
          <span className="font-semibold">{alertEdges} alert edges</span>
        </div>
      )}

      {highestSev && (
        <div
          className="flex items-center gap-1 rounded-[4px] px-1.5 py-0.5 text-[11px]"
          style={{
            background: `${severityColor(highestSev)}18`,
            border: `1px solid ${severityColor(highestSev)}44`,
            color: severityColor(highestSev),
          }}
        >
          <span className="h-[6px] w-[6px] rounded-full" style={{ background: severityColor(highestSev) }} />
          <span className="capitalize">{highestSev}</span>
        </div>
      )}

      {staleNodes > 0 && (
        <div
          className="rounded-[4px] px-1.5 py-0.5 text-[11px]"
          style={{ background: "rgba(249,115,22,0.12)", border: "1px solid rgba(249,115,22,0.3)", color: "#F97316" }}
        >
          {staleNodes} stale
        </div>
      )}

      {truncated && (
        <div
          className="rounded-[4px] px-1.5 py-0.5 text-[11px]"
          style={{ background: "rgba(251,191,36,0.1)", border: "1px solid rgba(251,191,36,0.3)", color: "#FBBF24" }}
        >
          ⚡ truncated
        </div>
      )}

      {filterCount > 0 && (
        <div
          className="rounded-[4px] px-1.5 py-0.5 text-[11px]"
          style={{ background: "rgba(96,165,250,0.1)", border: "1px solid rgba(96,165,250,0.25)", color: "#60A5FA" }}
        >
          {filterCount} filter{filterCount !== 1 ? "s" : ""}
        </div>
      )}

      {focusedGroupLabel && (
        <div
          className="flex items-center gap-1 rounded-[4px] px-1.5 py-0.5 text-[11px]"
          style={{ background: "rgba(74,222,128,0.1)", border: "1px solid rgba(74,222,128,0.28)", color: "#4ADE80", maxWidth: 160 }}
        >
          <span className="truncate">{focusedGroupLabel}</span>
          <button
            type="button"
            className="shrink-0 opacity-60 hover:opacity-100"
            onClick={onClearFocus}
            title="Exit group focus"
          >
            ✕
          </button>
        </div>
      )}

      <div className="ml-auto flex items-center gap-2">
        <div className="flex items-center gap-1">
          <div
            className="flex h-7 items-center rounded-[5px] border border-border/40 bg-background/40 px-2"
            style={{ minWidth: 160 }}
          >
            <span className="mr-1.5 text-[11px] text-muted-foreground/50">⌕</span>
            <input
              ref={searchInputRef}
              type="text"
              placeholder="Search nodes, IPs…"
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  onNextMatch();
                }
              }}
              className="w-full bg-transparent text-[11px] text-foreground placeholder:text-muted-foreground/40 outline-none"
            />
            {searchQuery && (
              <button
                type="button"
                className="ml-1 text-[11px] text-muted-foreground/50 hover:text-muted-foreground"
                onClick={() => onSearchChange("")}
                title="Clear search"
              >
                ✕
              </button>
            )}
          </div>

          {searchQuery && (
            <div className="flex items-center gap-1">
              <span className="text-[10px] text-muted-foreground/60 tabular-nums">
                {hasSearchResults ? `${displayMatchIndex}/${searchTotal}` : "0"}
              </span>
              <button
                type="button"
                className="flex h-6 w-6 items-center justify-center rounded text-[11px] text-muted-foreground/60 hover:bg-muted/40 hover:text-foreground disabled:opacity-30"
                onClick={onPrevMatch}
                disabled={!hasSearchResults}
                title="Previous match"
              >
                ‹
              </button>
              <button
                type="button"
                className="flex h-6 w-6 items-center justify-center rounded text-[11px] text-muted-foreground/60 hover:bg-muted/40 hover:text-foreground disabled:opacity-30"
                onClick={onNextMatch}
                disabled={!hasSearchResults}
                title="Next match"
              >
                ›
              </button>
            </div>
          )}
        </div>

        {projected && (
          <span className="text-[10px] text-muted-foreground/40">
            {formatFreshness(freshness)}
          </span>
        )}

        <span
          className="h-[7px] w-[7px] rounded-full"
          style={{ background: realtimeConnected ? "#4ADE80" : "#6B7280" }}
          title={`Realtime: ${liveState.realtimeStatus}`}
        />

        <button
          type="button"
          className={cx(
            "flex h-7 w-7 shrink-0 items-center justify-center rounded-[5px] text-[13px] transition-all",
            isFullscreen
              ? "bg-primary/15 text-primary"
              : "text-muted-foreground/60 hover:bg-muted/40 hover:text-foreground",
          )}
          onClick={onToggleFullscreen}
          title={isFullscreen ? "Exit fullscreen" : "Fullscreen"}
        >
          {isFullscreen ? "⊡" : "⊞"}
        </button>

        <Button
          variant="ghost"
          size="sm"
          className="h-7 text-[11px]"
          onClick={onRefresh}
          disabled={liveState.isRefreshing}
        >
          {liveState.isRefreshing ? "Refreshing…" : "Refresh"}
        </Button>

        {isAdmin && (
          <Button
            variant="ghost"
            size="sm"
            className="h-7 text-[11px]"
            onClick={onRecalculate}
            disabled={recalculateBusy}
          >
            {recalculateBusy ? "Recalculating…" : "Recalculate"}
          </Button>
        )}
      </div>
    </div>
  );
}
