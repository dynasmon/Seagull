import { lazy, Suspense, useMemo, useState } from "react";
import { useEuiTheme } from "@elastic/eui";

import EmptyState from "@/shared/components/EmptyState";
import { Button } from "@/shared/components/Button";
import { DataQueryStateBanner } from "@/shared/components/DataView";
import { MetricCard } from "@/shared/components/MetricCard";
import { Panel } from "@/shared/components/Panel";
import { SelectInput } from "@/shared/components/SelectInput";
import { ToggleSwitch } from "@/shared/components/ToggleSwitch";
import { useSeverityChartColors } from "@/shared/components/charts/chartTheme";
import { usePersistentState } from "@/shared/hooks/usePersistentState";
import { useReducedMotion } from "@/shared/hooks/useReducedMotion";
import type { SeverityLevel } from "@/shared/lib/severity";
import { usePortalRealtimeSubscription } from "@/shared/realtime";

import { ThreatRankPanels } from "./components/ThreatRankPanels";
import CountryDetailDrawer, { type CountrySelection } from "./components/CountryDetailDrawer";
import type { DirectionFilter } from "./components/ThreatGlobe";
import { useThreatGeo } from "./useThreatGeo";
import type { ThreatSourceMode } from "./types";

const ThreatGlobe = lazy(() => import("./components/ThreatGlobe"));
const ANIMATE_FLOWS_STORAGE_KEY = "seagull_threat_map_animate_flows_v1";
const AUTO_ROTATE_STORAGE_KEY = "seagull_threat_map_auto_rotate_v1";

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

const DIRECTION_OPTIONS: Array<{ value: DirectionFilter; label: string }> = [
  { value: "all", label: "All directions" },
  { value: "inbound", label: "Inbound" },
  { value: "outbound", label: "Outbound" },
  { value: "internal", label: "Internal" },
  { value: "transit", label: "Transit" },
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
  const [animateOverride, setAnimateOverride] = usePersistentState<boolean | null>(
    ANIMATE_FLOWS_STORAGE_KEY,
    null,
    (raw) => (typeof raw === "boolean" ? raw : null),
  );
  const [autoRotate, setAutoRotate] = usePersistentState<boolean>(
    AUTO_ROTATE_STORAGE_KEY,
    false,
    (raw) => (typeof raw === "boolean" ? raw : false),
  );
  const [direction, setDirection] = useState<DirectionFilter>("all");
  const [resetSignal, setResetSignal] = useState(0);
  const [selectedCountry, setSelectedCountry] = useState<CountrySelection | null>(null);
  const [cityFocus, setCityFocus] = useState<{ lat: number; lng: number; key: number } | null>(null);
  const [protection, setProtection] = useState<{ active: boolean; phase: string; sampleHot: number | null }>({
    active: false,
    phase: "ok",
    sampleHot: null,
  });
  const severityColors = useSeverityChartColors();
  const { euiTheme } = useEuiTheme();
  const reducedMotion = useReducedMotion();
  const animate = animateOverride ?? !reducedMotion;

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
  const totalAlerts = data?.total_alerts ?? 0;
  const locatedIps = data?.located_ips ?? 0;
  const countriesObserved = data?.top_source_countries.length ?? 0;
  const metricsLoading = isLoading && !data;

  const recenter = () => {
    setSelectedCountry(null);
    setCityFocus(null);
    setResetSignal((value) => value + 1);
  };

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
          <div className="w-40">
            <SelectInput value={direction} onChange={(event) => setDirection(event.target.value as DirectionFilter)}>
              {DIRECTION_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </SelectInput>
          </div>
          <ToggleSwitch
            label="Animate flows"
            checked={animate}
            onChange={(event) => setAnimateOverride(event.target.checked)}
          />
          <ToggleSwitch
            label="Auto-rotate"
            checked={autoRotate}
            onChange={(event) => {
              const enabled = event.target.checked;
              setAutoRotate(enabled);
              if (enabled) {
                setSelectedCountry(null);
                setCityFocus(null);
              }
            }}
          />
          <Button variant="secondary" size="sm" onClick={recenter}>
            Recenter
          </Button>
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

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <MetricCard title="Located IPs" value={locatedIps.toLocaleString()} tone="info" loading={metricsLoading} />
        <MetricCard
          title="Total alerts"
          value={totalAlerts.toLocaleString()}
          tone={totalAlerts > 0 ? "danger" : "default"}
          loading={metricsLoading}
        />
        <MetricCard
          title="DDoS attacks"
          value={ddosAttacks.toLocaleString()}
          tone={ddosAttacks > 0 ? "warning" : "default"}
          loading={metricsLoading}
        />
        <MetricCard
          title="Countries observed"
          value={countriesObserved.toLocaleString()}
          tone="default"
          loading={metricsLoading}
        />
      </div>

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
        <div className="relative w-full" style={{ aspectRatio: "16 / 10" }}>
          <Suspense
            fallback={
              <div className="absolute inset-0 flex items-center justify-center text-sm text-muted-foreground">
                Loading globe…
              </div>
            }
          >
            <ThreatGlobe
              points={data?.points ?? []}
              flows={data?.flows ?? []}
              home={data?.home ?? null}
              animate={animate}
              direction={direction}
              autoRotate={autoRotate}
              resetSignal={resetSignal}
              selectedCode={selectedCountry?.code ?? null}
              cityFocus={cityFocus}
              onSelectCountry={(selection) => {
                setSelectedCountry(selection);
                setCityFocus(null);
              }}
              onAutoRotateOff={() => setAutoRotate(false)}
            />
          </Suspense>
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

      <CountryDetailDrawer
        selection={selectedCountry}
        points={data?.points ?? []}
        onFocusCity={(lat, lon) => setCityFocus({ lat, lng: lon, key: Date.now() })}
        onClose={() => {
          setSelectedCountry(null);
          setCityFocus(null);
        }}
      />
    </div>
  );
}
