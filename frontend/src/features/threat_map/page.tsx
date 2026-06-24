import { useMemo, useState } from "react";

import EmptyState from "@/shared/components/EmptyState";
import { DataQueryStateBanner } from "@/shared/components/DataView";
import { Panel } from "@/shared/components/Panel";
import { SelectInput } from "@/shared/components/SelectInput";
import { useSeverityChartColors } from "@/shared/components/charts/chartTheme";
import type { SeverityLevel } from "@/shared/lib/severity";

import { ThreatMap } from "./components/ThreatMap";
import { useThreatGeo } from "./useThreatGeo";
import { WORLD_VIEWBOX_HEIGHT, WORLD_VIEWBOX_WIDTH } from "./worldMap";

const WINDOW_OPTIONS: Array<{ value: number; label: string }> = [
  { value: 360, label: "Last 6 hours" },
  { value: 1440, label: "Last 24 hours" },
  { value: 10080, label: "Last 7 days" },
  { value: 43200, label: "Last 30 days" },
];

const SEVERITY_OPTIONS: Array<{ value: string; label: string }> = [
  { value: "", label: "All severities" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

const LEGEND: Array<{ level: SeverityLevel; label: string }> = [
  { level: "critical", label: "Critical" },
  { level: "high", label: "High" },
  { level: "medium", label: "Medium" },
  { level: "low", label: "Low" },
];

function fmtClock(date: Date | null): string | null {
  if (!date) return null;
  return date.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit" });
}

export default function ThreatMapPage() {
  const [sinceMinutes, setSinceMinutes] = useState(1440);
  const [severity, setSeverity] = useState("");
  const severityColors = useSeverityChartColors();

  const query = useMemo(
    () => ({ sinceMinutes, limit: 200, severity: severity || null }),
    [sinceMinutes, severity],
  );
  const { data, error, isLoading, isRefreshing, lastUpdatedAt } = useThreatGeo(query);

  const windowLabel = WINDOW_OPTIONS.find((option) => option.value === sinceMinutes)?.label ?? "";
  const updatedAt = fmtClock(lastUpdatedAt);

  const bannerMessage = data
    ? [
        `${data.located_ips.toLocaleString()} located`,
        `${data.unlocated_ips.toLocaleString()} unlocated`,
        `${data.total_alerts.toLocaleString()} alerts`,
        windowLabel.toLowerCase(),
        `source ${data.meta.source}`,
        data.meta.cache_hit ? "cache" : null,
        error ? "refresh error" : null,
      ]
        .filter(Boolean)
        .join(" · ")
    : null;

  const overlay = !data
    ? isLoading
      ? <EmptyState title="Loading" hint="Resolving threat source geography…" />
      : <EmptyState title="No data" hint={error || "The threat map could not be loaded."} />
    : data.points.length === 0
      ? <EmptyState title="No geolocated threats" hint="No suspicious source IPs could be placed on the map for this window." />
      : null;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <div className="w-44">
            <SelectInput value={sinceMinutes} onChange={(event) => setSinceMinutes(Number(event.target.value))}>
              {WINDOW_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </SelectInput>
          </div>
          <div className="w-40">
            <SelectInput value={severity} onChange={(event) => setSeverity(event.target.value)}>
              {SEVERITY_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </SelectInput>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3 text-[11px] text-muted-foreground">
          {LEGEND.map((entry) => (
            <span key={entry.level} className="inline-flex items-center gap-1.5">
              <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: severityColors[entry.level] }} />
              {entry.label}
            </span>
          ))}
          <span className="text-muted-foreground/80">size ∝ volume</span>
        </div>
      </div>

      {bannerMessage ? (
        <DataQueryStateBanner tone={error ? "warning" : "neutral"} message={bannerMessage} />
      ) : null}

      <Panel
        title="Geographic origin of suspicious sources"
        actions={
          isRefreshing ? (
            <span className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground">syncing</span>
          ) : updatedAt ? (
            <span className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground">updated {updatedAt}</span>
          ) : null
        }
      >
        <div className="relative w-full" style={{ aspectRatio: `${WORLD_VIEWBOX_WIDTH} / ${WORLD_VIEWBOX_HEIGHT}` }}>
          <ThreatMap points={data?.points ?? []} />
          {overlay ? (
            <div className="pointer-events-none absolute inset-0 flex items-center justify-center">{overlay}</div>
          ) : null}
        </div>
      </Panel>
    </div>
  );
}
