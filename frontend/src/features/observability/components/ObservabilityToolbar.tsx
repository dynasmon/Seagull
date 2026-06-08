import { EuiButtonGroup, EuiHealth, EuiIcon } from "@elastic/eui";

import { Button } from "@/shared/components/Button";
import { cx } from "@/shared/lib/cx";

import { clockLabel } from "../lib/format";
import { RANGE_PRESETS } from "../lib/panels";
import type { ObservabilityStatus } from "../types";

function statusView(status: ObservabilityStatus | null): { color: "success" | "danger" | "subdued"; label: string } {
  if (!status) return { color: "subdued", label: "Checking" };
  if (!status.enabled) return { color: "subdued", label: "Disabled" };
  if (!status.available) return { color: "danger", label: "Unreachable" };
  return { color: "success", label: "Connected" };
}

export default function ObservabilityToolbar({
  status,
  rangePresetId,
  onRangeChange,
  onRefresh,
  refreshing,
  live,
  lastUpdated,
}: {
  status: ObservabilityStatus | null;
  rangePresetId: string;
  onRangeChange: (id: string) => void;
  onRefresh: () => void;
  refreshing: boolean;
  live: boolean;
  lastUpdated: Date | null;
}) {
  const view = statusView(status);

  return (
    <div className="ui-toolbar-shell flex flex-wrap items-center justify-between gap-x-6 gap-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <EuiHealth color={view.color} textSize="xs">
          <span className="font-semibold text-foreground">Prometheus</span>
          <span className="text-muted-foreground"> · {view.label}</span>
        </EuiHealth>

        <span className="hidden h-4 w-px bg-border sm:block" aria-hidden="true" />

        <span className="inline-flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-widest text-muted-foreground">
          <span
            className={cx(
              "h-1.5 w-1.5 rounded-full",
              refreshing ? "animate-pulse bg-primary" : live ? "bg-success" : "bg-muted-foreground/40"
            )}
            aria-hidden="true"
          />
          {refreshing ? "Syncing" : live ? "Live" : "Paused"}
          <span className="text-muted-foreground/70">· {clockLabel(lastUpdated)}</span>
        </span>
      </div>

      <div className="flex flex-wrap items-center gap-2.5">
        <span className="ui-eyebrow">Range</span>
        <EuiButtonGroup
          legend="Metrics time range"
          type="single"
          buttonSize="compressed"
          options={RANGE_PRESETS.map((preset) => ({ id: preset.id, label: preset.label }))}
          idSelected={rangePresetId}
          onChange={onRangeChange}
        />
        <Button
          variant="secondary"
          size="md"
          onClick={onRefresh}
          disabled={refreshing}
          leadingIcon={<EuiIcon type="refresh" size="s" />}
        >
          {refreshing ? "Refreshing…" : "Refresh"}
        </Button>
      </div>
    </div>
  );
}
