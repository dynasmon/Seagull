import { memo } from "react";
import { Panel, useReactFlow, useStore } from "@xyflow/react";

import { cx } from "@/shared/lib/cx";

type Props = {
  showMinimap: boolean;
  onToggleMinimap: () => void;
  focusedGroupLabel?: string | null;
  onClearFocus?: () => void;
  searchQuery: string;
  searchMatchIndex: number;
  searchTotal: number;
  onPrevMatch: () => void;
  onNextMatch: () => void;
};

function ControlBtn({
  children,
  onClick,
  title,
  active,
  tone,
}: {
  children: React.ReactNode;
  onClick?: () => void;
  title?: string;
  active?: boolean;
  tone?: "focus";
}) {
  return (
    <button
      type="button"
      title={title}
      onClick={onClick}
      className={cx(
        "flex h-6 w-6 items-center justify-center rounded-[4px] text-[12px] transition-colors",
        active
          ? "bg-primary/20 text-primary"
          : tone === "focus"
            ? "text-[#4ADE80]/80 hover:bg-[#4ADE80]/12 hover:text-[#4ADE80]"
            : "text-muted-foreground/70 hover:bg-muted/30 hover:text-foreground",
      )}
    >
      {children}
    </button>
  );
}

function TopologyCanvasControls({
  showMinimap,
  onToggleMinimap,
  focusedGroupLabel,
  onClearFocus,
  searchQuery,
  searchMatchIndex,
  searchTotal,
  onPrevMatch,
  onNextMatch,
}: Props) {
  const { zoomIn, zoomOut, fitView } = useReactFlow();
  const zoom = useStore((s) => Math.round(s.transform[2] * 100));
  const hasSearch = Boolean(searchQuery.trim()) && searchTotal > 0;
  const displayIndex = hasSearch ? searchMatchIndex + 1 : 0;

  return (
    <Panel position="bottom-right" style={{ marginBottom: 8, marginRight: 8 }}>
      <div
        className="flex flex-col items-center gap-0.5 rounded-lg border border-border/40 p-1"
        style={{ background: "rgba(10,15,26,0.92)" }}
      >
        <span className="mb-0.5 select-none font-mono text-[9px] text-muted-foreground/45 tabular-nums">
          {zoom}%
        </span>

        <ControlBtn onClick={() => zoomIn({ duration: 180 })} title="Zoom in">+</ControlBtn>
        <ControlBtn onClick={() => zoomOut({ duration: 180 })} title="Zoom out">−</ControlBtn>
        <ControlBtn onClick={() => fitView({ padding: 0.12, duration: 300 })} title="Fit view">⊞</ControlBtn>

        <div className="my-0.5 h-px w-full bg-border/30" />

        <ControlBtn
          onClick={onToggleMinimap}
          active={showMinimap}
          title={showMinimap ? "Hide minimap" : "Show minimap"}
        >
          ⊡
        </ControlBtn>

        {focusedGroupLabel && (
          <>
            <div className="my-0.5 h-px w-full bg-border/30" />
            <ControlBtn onClick={onClearFocus} title={`Exit focus: ${focusedGroupLabel}`} tone="focus">
              ✕
            </ControlBtn>
          </>
        )}

        {hasSearch && (
          <>
            <div className="my-0.5 h-px w-full bg-border/30" />
            <span className="select-none font-mono text-[9px] text-muted-foreground/45 tabular-nums">
              {displayIndex}/{searchTotal}
            </span>
            <ControlBtn title="Previous match" onClick={onPrevMatch}>‹</ControlBtn>
            <ControlBtn title="Next match" onClick={onNextMatch}>›</ControlBtn>
          </>
        )}
      </div>
    </Panel>
  );
}

export default memo(TopologyCanvasControls);
