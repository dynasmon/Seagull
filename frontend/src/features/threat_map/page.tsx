import { useMemo, useState } from "react";
import { useEuiTheme } from "@elastic/eui";

import EmptyState from "@/shared/components/EmptyState";
import { DataQueryStateBanner } from "@/shared/components/DataView";
import { Panel } from "@/shared/components/Panel";
import { SelectInput } from "@/shared/components/SelectInput";
import { ToggleSwitch } from "@/shared/components/ToggleSwitch";
import { useSeverityChartColors } from "@/shared/components/charts/chartTheme";
import type { SeverityLevel } from "@/shared/lib/severity";
import { usePortalRealtimeSubscription } from "@/shared/realtime";

import { ThreatMap } from "./components/ThreatMap";
import { ThreatRankPanels } from "./components/ThreatRankPanels";
import { useThreatGeo } from "./useThreatGeo";
import type { ThreatSourceMode } from "./types";
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

const SOURCE_OPTIONS: Array<{ value: ThreatSourceMode; label: string }> = [
  { value: "both", label: "Events + alerts" },
  { value: "events", label: "Ambient events" },
  { value: "alerts", label: "Confirmed alerts" },
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
  const [source, setSource] = useState<ThreatSourceMode>("both");
  const [animate, setAnimate] = useState(true);
  const [protection, setProtection] = useState<{ active: boolean; phase: string; sampleHot: number | null }>({
    active: false,
    phase: "ok",
    sampleHot: null,
  });
  const severityColors = useSeverityChartColors();
  const { euiTheme } = useEuiTheme();

  const query = useMemo(
    () => ({ sinceMinutes, limit: 200, severity: severity || null, source }),
    [sinceMinutes, severity, source],
  );
  const { data, error, isLoading, isRefreshing, lastUpdatedAt } = useThreatGeo(query);

  usePortalRealtimeSubscription("ui.overview.storm.patch", (event) => {
    setProtection({
      active: Boolean(event.payload?.protection_active ?? event.payload?.active),
      phase: String(event.payload?.phase ?? "ok"),
      sampleHot:
        typeof event.payload?.sample_hot_percent === "number" ? event.payload.sample_hot_percent : null,
    });
  });

  const windowLabel = WINDOW_OPTIONS.find((option) => option.value === sinceMinutes)?.label ?? "";
  const updatedAt = fmtClock(lastUpdatedAt);

  const ddosAttacks = data?.ddos_attacks ?? 0;
  const ddosUnlocated = data?.ddos_unlocated_sources ?? 0;

  const protectionMessage = protection.active
    ? [
        "ingest protection active",
        protection.phase && protection.phase !== "ok" ? `phase ${protection.phase}` : null,
        typeof protection.sampleHot === "number" ? `hot sampled to ${protection.sampleHot}%` : null,
        "DDoS and SSH signals preserved",
      ]
        .filter(Boolean)
        .join(" · ")
    : null;

  const bannerMessage = data
    ? [
        data.home?.label ? `home ${data.home.label}` : null,
        `${data.located_ips.toLocaleString()} located`,
        `${data.unlocated_ips.toLocaleString()} unlocated`,
        `${data.total_alerts.toLocaleString()} alerts`,
        ddosAttacks > 0 ? `${ddosAttacks.toLocaleString()} ddos` : null,
        ddosUnlocated > 0 ? `${ddosUnlocated.toLocaleString()} ddos sources unlocated` : null,
        windowLabel.toLowerCase(),
        data.meta.cache_hit ? "cache" : null,
        error ? "refresh error" : null,
      ]
        .filter(Boolean)
        .join(" · ")
    : null;

  const overlay = !data
    ? isLoading
      ? <EmptyState title="Loading" hint="Resolving threat geography…" />
      : <EmptyState title="No data" hint={error || "The threat map could not be loaded."} />
    : data.points.length === 0
      ? ddosAttacks > 0
        ? (
          <EmptyState
            title="DDoS detected — sources not geolocatable"
            hint={`${ddosAttacks.toLocaleString()} flood attack${ddosAttacks === 1 ? "" : "s"} in this window · ${ddosUnlocated.toLocaleString()} attacker source${ddosUnlocated === 1 ? "" : "s"} are private/simulated or awaiting geo-enrichment.`}
          />
        )
        : <EmptyState title="No geolocated threats" hint="No suspicious source IPs could be placed on the map for this window." />
      : null;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <div className="w-44">
            <SelectInput value={source} onChange={(event) => setSource(event.target.value as ThreatSourceMode)}>
              {SOURCE_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </SelectInput>
          </div>
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
          <ToggleSwitch label="Animate flows" checked={animate} onChange={(event) => setAnimate(event.target.checked)} />
        </div>

        <div className="flex flex-wrap items-center gap-3 text-[11px] text-muted-foreground">
          {LEGEND.map((entry) => (
            <span key={entry.level} className="inline-flex items-center gap-1.5">
              <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: severityColors[entry.level] }} />
              {entry.label}
            </span>
          ))}
          <span className="inline-flex items-center gap-1.5">
            <span
              className="inline-block h-2.5 w-2.5 rounded-full border"
              style={{ borderColor: euiTheme.colors.primary, backgroundColor: euiTheme.colors.emptyShade }}
            />
            Your network
          </span>
          <span className="text-muted-foreground/80">arcs → your network · dot ∝ volume</span>
        </div>
      </div>

      {protectionMessage ? (
        <DataQueryStateBanner tone="warning" message={protectionMessage} />
      ) : null}

      {bannerMessage ? (
        <DataQueryStateBanner tone={error ? "warning" : "neutral"} message={bannerMessage} />
      ) : null}

      <Panel
        title="Network threat map"
        subtitle="Ambient suspicious traffic with confirmed alerts promoted"
        actions={
          isRefreshing ? (
            <span className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground">syncing</span>
          ) : updatedAt ? (
            <span className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground">updated {updatedAt}</span>
          ) : null
        }
      >
        <div className="relative w-full" style={{ aspectRatio: `${WORLD_VIEWBOX_WIDTH} / ${WORLD_VIEWBOX_HEIGHT}` }}>
          <ThreatMap points={data?.points ?? []} flows={data?.flows ?? []} home={data?.home ?? null} animate={animate} />
          {overlay ? (
            <div className="pointer-events-none absolute inset-0 flex items-center justify-center">{overlay}</div>
          ) : null}
        </div>
      </Panel>

      <ThreatRankPanels
        topSourceCountries={data?.top_source_countries ?? []}
        topSourceIps={data?.top_source_ips ?? []}
        topDestinationCountries={data?.top_destination_countries ?? []}
        topDestinationIps={data?.top_destination_ips ?? []}
      />
    </div>
  );
}
