import { memo } from "react";
import { Panel, useReactFlow, useStore } from "@xyflow/react";

import { cx } from "@/shared/lib/cx";

import type { TopologyViewMode } from "../../types";

type Props = {
  viewMode: TopologyViewMode;
  filterRailOpen: boolean;
  showMinimap: boolean;
  isFullscreen: boolean;
  isRefreshing: boolean;
  hasCustomPositions: boolean;
  focusedGroupLabel?: string | null;
  searchQuery: string;
  searchMatchIndex: number;
  searchTotal: number;
  onViewModeChange: (mode: TopologyViewMode) => void;
  onToggleFilterRail: () => void;
  onToggleMinimap: () => void;
  onToggleFullscreen: () => void;
  onRefresh: () => void;
  onResetLayout: () => void;
  onFitView: () => void;
  onClearFocus?: () => void;
  onSearchChange: (query: string) => void;
  onPrevMatch: () => void;
  onNextMatch: () => void;
};

function IconButton({
  children,
  onClick,
  title,
  active,
  disabled,
}: {
  children: React.ReactNode;
  onClick?: () => void;
  title?: string;
  active?: boolean;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      title={title}
      aria-label={title}
      aria-pressed={active}
      onClick={onClick}
      disabled={disabled}
      className={cx(
        "flex h-8 w-8 items-center justify-center rounded-md text-[13px] transition-colors disabled:cursor-not-allowed disabled:opacity-45",
        active ? "bg-[#22D3EE]/18 text-[#67E8F9]" : "text-muted-foreground/75 hover:bg-white/6 hover:text-foreground",
      )}
    >
      {children}
    </button>
  );
}

function TopologyCanvasControls({
  viewMode,
  filterRailOpen,
  showMinimap,
  isFullscreen,
  isRefreshing,
  hasCustomPositions,
  focusedGroupLabel,
  searchQuery,
  searchMatchIndex,
  searchTotal,
  onViewModeChange,
  onToggleFilterRail,
  onToggleMinimap,
  onToggleFullscreen,
  onRefresh,
  onResetLayout,
  onFitView,
  onClearFocus,
  onSearchChange,
  onPrevMatch,
  onNextMatch,
}: Props) {
  const { zoomIn, zoomOut } = useReactFlow();
  const zoom = useStore((state) => Math.round(state.transform[2] * 100));
  const hasSearch = Boolean(searchQuery.trim());
  const hasMatches = hasSearch && searchTotal > 0;

  return (
    <>
      {(!filterRailOpen || isFullscreen) && (
        <Panel position="top-left" style={{ marginLeft: 12, marginTop: 12 }}>
          <div
            className="flex items-center gap-2 rounded-xl border border-white/10 px-2.5 py-2 shadow-[0_16px_48px_rgba(0,0,0,0.28)]"
            style={{ background: "rgba(7,17,31,0.9)", backdropFilter: "blur(12px)" }}
          >
            <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground/60">
              View
            </span>
            <div className="flex rounded-md border border-white/10 bg-black/20 p-0.5">
              {(["location", "connection"] as TopologyViewMode[]).map((mode) => (
                <button
                  key={mode}
                  type="button"
                  onClick={() => onViewModeChange(mode)}
                  className={cx(
                    "rounded-[4px] px-2.5 py-1 text-[11px] font-medium transition-colors",
                    viewMode === mode
                      ? "bg-[#22D3EE] text-[#062231]"
                      : "text-muted-foreground hover:bg-white/5",
                  )}
                >
                  {mode === "location" ? "Location" : "Connection"}
                </button>
              ))}
            </div>
          </div>
        </Panel>
      )}

      <Panel position="top-right" style={{ marginRight: 12, marginTop: 12 }}>
        <div
          className="flex max-w-[calc(100vw-2rem)] flex-wrap items-center gap-1.5 rounded-xl border border-white/10 p-1.5 shadow-[0_16px_48px_rgba(0,0,0,0.28)]"
          style={{ background: "rgba(7,17,31,0.9)", backdropFilter: "blur(12px)" }}
        >
          <div className="flex h-8 min-w-[196px] items-center rounded-md border border-white/10 bg-black/20 px-2">
            <span className="mr-1.5 text-[12px] text-muted-foreground/45">⌕</span>
            <input
              type="text"
              placeholder="Find host, IP, port…"
              value={searchQuery}
              onChange={(event) => onSearchChange(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  event.preventDefault();
                  onNextMatch();
                }
              }}
              className="w-full bg-transparent text-[11px] text-foreground placeholder:text-muted-foreground/35 outline-none"
            />
            {searchQuery && (
              <button
                type="button"
                className="ml-1 text-[11px] text-muted-foreground/55 hover:text-foreground"
                onClick={() => onSearchChange("")}
                title="Clear search"
              >
                ✕
              </button>
            )}
          </div>

          {hasSearch && (
            <div className="flex h-8 items-center gap-0.5 rounded-md border border-white/10 bg-black/15 px-1">
              <span className="min-w-8 px-1 text-center font-mono text-[10px] text-muted-foreground/60 tabular-nums">
                {hasMatches ? `${searchMatchIndex + 1}/${searchTotal}` : "0"}
              </span>
              <IconButton onClick={onPrevMatch} title="Previous match" disabled={!hasMatches}>‹</IconButton>
              <IconButton onClick={onNextMatch} title="Next match" disabled={!hasMatches}>›</IconButton>
            </div>
          )}

          <div className="mx-0.5 h-6 w-px bg-white/10" />

          <IconButton onClick={onToggleFilterRail} title={filterRailOpen ? "Hide filters" : "Show filters"} active={filterRailOpen}>
            ☰
          </IconButton>
          <IconButton onClick={onFitView} title="Fit graph to view">⊞</IconButton>
          <IconButton onClick={onToggleMinimap} title={showMinimap ? "Hide minimap" : "Show minimap"} active={showMinimap}>
            ◫
          </IconButton>
          <IconButton onClick={onToggleFullscreen} title={isFullscreen ? "Exit fullscreen" : "Fullscreen"} active={isFullscreen}>
            {isFullscreen ? "⊡" : "⛶"}
          </IconButton>
          <IconButton onClick={onRefresh} title="Refresh data" disabled={isRefreshing}>↻</IconButton>
          {hasCustomPositions && (
            <>
              <div className="mx-0.5 h-6 w-px bg-white/10" />
              <IconButton onClick={onResetLayout} title="Reset dragged nodes to the auto layout">⟳</IconButton>
            </>
          )}
        </div>

        {focusedGroupLabel && (
          <div
            className="ml-auto mt-2 flex w-fit max-w-[280px] items-center gap-2 rounded-lg border border-[#4ADE80]/30 px-2.5 py-1.5 text-[11px] text-[#4ADE80]"
            style={{ background: "rgba(7,17,31,0.88)", backdropFilter: "blur(12px)" }}
          >
            <span className="text-[9px] uppercase tracking-[0.1em] opacity-70">Focused</span>
            <span className="truncate">{focusedGroupLabel}</span>
            <button
              type="button"
              className="text-[#4ADE80]/65 hover:text-[#4ADE80]"
              onClick={onClearFocus}
              title="Exit group focus (Esc)"
            >
              ✕
            </button>
          </div>
        )}
      </Panel>

      <Panel position="bottom-right" style={{ marginBottom: 12, marginRight: 12 }}>
        <div
          className="flex items-center gap-1 rounded-xl border border-white/10 p-1.5 shadow-[0_16px_48px_rgba(0,0,0,0.28)]"
          style={{ background: "rgba(7,17,31,0.9)", backdropFilter: "blur(12px)" }}
        >
          <IconButton onClick={() => zoomOut({ duration: 180 })} title="Zoom out">−</IconButton>
          <span className="min-w-11 select-none text-center font-mono text-[10px] text-muted-foreground/65 tabular-nums">
            {zoom}%
          </span>
          <IconButton onClick={() => zoomIn({ duration: 180 })} title="Zoom in">+</IconButton>
        </div>
      </Panel>
    </>
  );
}

export default memo(TopologyCanvasControls);
