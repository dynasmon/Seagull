import { Button } from "@/shared/components/Button";

import { FilterChip } from "./FilterChip";
import type { OverviewQueryState } from "../query";

function fmtDurationCompact(totalMinutes: number): string {
  const minutes = Math.max(1, Math.trunc(Number(totalMinutes) || 0));
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  const mins = minutes % 60;
  if (hours < 24) return mins === 0 ? `${hours}h` : `${hours}h ${mins}m`;
  const days = Math.floor(hours / 24);
  const remHours = hours % 24;
  return remHours === 0 ? `${days}d` : `${days}d ${remHours}h`;
}

export function OverviewRangeControls({
  label = "Range",
  query,
  draft,
  onDraftChange,
  onApplyRange,
  onSetLiveWindow,
  onResetToLive,
  applyDisabled,
}: {
  label?: string;
  query: OverviewQueryState;
  draft: { from: string; to: string };
  onDraftChange: (field: "from" | "to", value: string) => void;
  onApplyRange: () => void;
  onSetLiveWindow: (minutes: number) => void;
  onResetToLive: () => void;
  applyDisabled: boolean;
}) {
  const historical = Boolean(query.from || query.to);

  return (
    <div className="rounded-md border border-border bg-surface-2/50 px-3 py-2">
      <div className="flex flex-col gap-2 2xl:flex-row 2xl:items-end 2xl:justify-between">
        <div className="flex flex-wrap items-center gap-1.5">
          <div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
            {label}
          </div>
          <div className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground/85">
            {historical ? "Historical paused" : `Live · ${fmtDurationCompact(query.windowMinutes)}`}
          </div>
          <div className="ml-1 flex items-center gap-1">
            <FilterChip active={!historical && query.windowMinutes === 60} onClick={() => onSetLiveWindow(60)}>60m</FilterChip>
            <FilterChip active={!historical && query.windowMinutes === 360} onClick={() => onSetLiveWindow(360)}>6h</FilterChip>
            <FilterChip active={!historical && query.windowMinutes === 1440} onClick={() => onSetLiveWindow(1440)}>24h</FilterChip>
          </div>
        </div>

        <div className="flex flex-wrap items-end gap-2">
          <label className="flex flex-col gap-1">
            <div className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground">From</div>
            <input
              type="datetime-local"
              value={draft.from}
              onChange={(e) => onDraftChange("from", e.target.value)}
              className="h-8 rounded-md border border-border bg-card px-2 text-[11.5px] text-foreground outline-none transition-colors focus:border-primary focus:ring-2 focus:ring-primary/25 sm:w-[11rem]"
            />
          </label>

          <label className="flex flex-col gap-1">
            <div className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground">To</div>
            <input
              type="datetime-local"
              value={draft.to}
              onChange={(e) => onDraftChange("to", e.target.value)}
              className="h-8 rounded-md border border-border bg-card px-2 text-[11.5px] text-foreground outline-none transition-colors focus:border-primary focus:ring-2 focus:ring-primary/25 sm:w-[11rem]"
            />
          </label>

          <Button variant={applyDisabled ? "subtle" : "primary"} size="md" disabled={applyDisabled} onClick={onApplyRange}>
            Apply
          </Button>
          <Button variant="subtle" size="md" onClick={onResetToLive}>
            Live
          </Button>
        </div>
      </div>
    </div>
  );
}
