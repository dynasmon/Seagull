import { EuiButtonGroup, EuiPanel } from "@elastic/eui";

import { Button } from "@/shared/components/Button";
import { TextInput } from "@/shared/components/TextInput";

import type { OverviewQueryState } from "../query";

const WINDOW_OPTIONS: Array<{ id: string; label: string; minutes: number }> = [
  { id: "w60", label: "60m", minutes: 60 },
  { id: "w360", label: "6h", minutes: 360 },
  { id: "w1440", label: "24h", minutes: 1440 },
];

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
  const selectedWindowId = historical
    ? ""
    : WINDOW_OPTIONS.find((o) => o.minutes === query.windowMinutes)?.id ?? "";

  return (
    <EuiPanel hasBorder hasShadow={false} paddingSize="none" borderRadius="m">
      <div className="flex flex-wrap items-end justify-between gap-x-4 gap-y-2 px-3 py-2.5">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">{label}</span>
          <EuiButtonGroup
            legend="Live time window"
            type="single"
            buttonSize="compressed"
            options={WINDOW_OPTIONS.map((o) => ({ id: o.id, label: o.label }))}
            idSelected={selectedWindowId}
            onChange={(id) => {
              const opt = WINDOW_OPTIONS.find((o) => o.id === id);
              if (opt) onSetLiveWindow(opt.minutes);
            }}
          />
          <span className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground/85">
            {historical ? "Historical · paused" : `Live · ${fmtDurationCompact(query.windowMinutes)}`}
          </span>
        </div>

        <div className="flex flex-wrap items-end gap-2">
          <label className="flex flex-col gap-1">
            <span className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground">From</span>
            <TextInput
              type="datetime-local"
              className="font-mono sm:w-[12rem]"
              value={draft.from}
              onChange={(e) => onDraftChange("from", e.target.value)}
            />
          </label>

          <label className="flex flex-col gap-1">
            <span className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground">To</span>
            <TextInput
              type="datetime-local"
              className="font-mono sm:w-[12rem]"
              value={draft.to}
              onChange={(e) => onDraftChange("to", e.target.value)}
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
    </EuiPanel>
  );
}
