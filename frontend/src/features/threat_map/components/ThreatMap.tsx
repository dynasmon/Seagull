import { useMemo, useState } from "react";
import { EuiPanel, useEuiTheme } from "@elastic/eui";

import { IpAddressPill } from "@/shared/components/IpAddressPill";
import { useSeverityChartColors } from "@/shared/components/charts/chartTheme";
import type { SeverityLevel } from "@/shared/lib/severity";

import {
  WORLD_LAND_PATH,
  WORLD_VIEWBOX_HEIGHT,
  WORLD_VIEWBOX_WIDTH,
  projectToMap,
} from "../worldMap";
import type { ThreatGeoPoint } from "../types";

const MIN_RADIUS = 5;
const MAX_RADIUS = 26;

function severityLevel(severity: string | null | undefined): SeverityLevel {
  const value = (severity || "").toLowerCase();
  if (value === "critical" || value === "high" || value === "medium" || value === "low" || value === "info") {
    return value;
  }
  return "neutral";
}

function pointLabel(point: ThreatGeoPoint): string {
  const place = [point.city, point.region].filter(Boolean)[0];
  const country = point.country ? point.country.toUpperCase() : "";
  if (place && country) return `${place} · ${country}`;
  return place || country || "Unknown location";
}

function markerRadius(count: number, maxCount: number): number {
  if (maxCount <= 1) return MIN_RADIUS + (MAX_RADIUS - MIN_RADIUS) * 0.4;
  const ratio = Math.sqrt(Math.max(0, count) / maxCount);
  return MIN_RADIUS + (MAX_RADIUS - MIN_RADIUS) * ratio;
}

function formatRelativeTime(iso: string | null | undefined): string | null {
  if (!iso) return null;
  const hasTimezone = /[zZ]|[+-]\d{2}:?\d{2}$/.test(iso);
  const then = Date.parse(hasTimezone ? iso : `${iso}Z`);
  if (!Number.isFinite(then)) return null;
  const seconds = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (seconds < 60) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  return `${days}d ago`;
}

type Marker = {
  id: string;
  point: ThreatGeoPoint;
  x: number;
  y: number;
  r: number;
  color: string;
};

export function ThreatMap({ points }: { points: ThreatGeoPoint[] }) {
  const { euiTheme, colorMode } = useEuiTheme();
  const severityColors = useSeverityChartColors();
  const isDark = colorMode === "DARK";
  const [hoveredId, setHoveredId] = useState<string | null>(null);

  const markers = useMemo<Marker[]>(() => {
    const maxCount = points.reduce((max, p) => Math.max(max, p.count), 0);
    return points
      .map((point) => {
        const { x, y } = projectToMap(point.lat, point.lon);
        return {
          id: `${point.lat},${point.lon}`,
          point,
          x,
          y,
          r: markerRadius(point.count, maxCount),
          color: severityColors[severityLevel(point.severity)],
        };
      })
      .sort((a, b) => b.r - a.r);
  }, [points, severityColors]);

  const active = useMemo(() => markers.find((m) => m.id === hoveredId) ?? null, [markers, hoveredId]);

  const oceanColor = euiTheme.colors.lightestShade;
  const landColor = euiTheme.colors.mediumShade;
  const markerStroke = euiTheme.colors.emptyShade;

  const activeXRatio = active ? active.x / WORLD_VIEWBOX_WIDTH : 0;
  const activeYRatio = active ? active.y / WORLD_VIEWBOX_HEIGHT : 0;

  return (
    <>
      <svg
        className="absolute inset-0 h-full w-full"
        viewBox={`0 0 ${WORLD_VIEWBOX_WIDTH} ${WORLD_VIEWBOX_HEIGHT}`}
        preserveAspectRatio="xMidYMid meet"
        role="img"
        aria-label="World map of suspicious source locations"
      >
        <rect
          x={0}
          y={0}
          width={WORLD_VIEWBOX_WIDTH}
          height={WORLD_VIEWBOX_HEIGHT}
          rx={8}
          fill={oceanColor}
          fillOpacity={isDark ? 0.35 : 0.6}
        />
        <path d={WORLD_LAND_PATH} fill={landColor} fillOpacity={isDark ? 0.45 : 0.7} />
        <g>
          {markers.map((marker) => {
            const isActive = marker.id === hoveredId;
            return (
              <g
                key={marker.id}
                tabIndex={0}
                role="button"
                aria-label={`${marker.point.count} alerts from ${pointLabel(marker.point)}`}
                style={{ cursor: "pointer", outline: "none" }}
                onMouseEnter={() => setHoveredId(marker.id)}
                onMouseLeave={() => setHoveredId((current) => (current === marker.id ? null : current))}
                onFocus={() => setHoveredId(marker.id)}
                onBlur={() => setHoveredId((current) => (current === marker.id ? null : current))}
              >
                <circle cx={marker.x} cy={marker.y} r={marker.r + 6} fill="transparent" />
                <circle
                  cx={marker.x}
                  cy={marker.y}
                  r={marker.r}
                  fill={marker.color}
                  fillOpacity={isActive ? 0.95 : 0.7}
                  stroke={markerStroke}
                  strokeOpacity={0.6}
                  strokeWidth={1}
                />
              </g>
            );
          })}
          {active ? (
            <circle
              cx={active.x}
              cy={active.y}
              r={active.r + 4}
              fill="none"
              stroke={active.color}
              strokeWidth={1.5}
              pointerEvents="none"
            />
          ) : null}
        </g>
      </svg>

      {active ? (
        <div
          className="pointer-events-none absolute z-10 w-64"
          style={{
            left: `${activeXRatio * 100}%`,
            top: `${activeYRatio * 100}%`,
            transform: `translate(${activeXRatio > 0.5 ? "calc(-100% - 10px)" : "10px"}, ${
              activeYRatio > 0.5 ? "calc(-100% - 10px)" : "10px"
            })`,
          }}
        >
          <ThreatTooltip marker={active} severityColors={severityColors} surface={euiTheme.colors.emptyShade} />
        </div>
      ) : null}
    </>
  );
}

function ThreatTooltip({
  marker,
  severityColors,
  surface,
}: {
  marker: Marker;
  severityColors: Record<SeverityLevel, string>;
  surface: string;
}) {
  const { point } = marker;
  const lastSeen = formatRelativeTime(point.last_seen);
  const org = point.asn_org || point.org;
  const severityCounts = [
    { level: "critical" as SeverityLevel, count: point.critical },
    { level: "high" as SeverityLevel, count: point.high },
    { level: "medium" as SeverityLevel, count: point.medium },
    { level: "low" as SeverityLevel, count: point.low },
  ].filter((entry) => entry.count > 0);

  return (
    <EuiPanel paddingSize="s" hasShadow borderRadius="m" color="plain" style={{ backgroundColor: surface }}>
      <div className="space-y-2 text-xs">
        <div className="flex items-center gap-2">
          <span className="inline-block h-2.5 w-2.5 shrink-0 rounded-full" style={{ backgroundColor: marker.color }} />
          <span className="truncate font-semibold text-foreground">{pointLabel(point)}</span>
        </div>

        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-muted-foreground">
          <span>
            <span className="font-mono text-foreground">{point.count.toLocaleString()}</span> alerts
          </span>
          <span>
            <span className="font-mono text-foreground">{point.unique_ips.toLocaleString()}</span> IPs
          </span>
          {lastSeen ? <span>{lastSeen}</span> : null}
        </div>

        {severityCounts.length > 0 ? (
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            {severityCounts.map((entry) => (
              <span key={entry.level} className="inline-flex items-center gap-1 text-muted-foreground">
                <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: severityColors[entry.level] }} />
                <span className="capitalize text-foreground">{entry.level}</span>
                <span className="font-mono">{entry.count.toLocaleString()}</span>
              </span>
            ))}
          </div>
        ) : null}

        {org ? <div className="truncate text-muted-foreground">{org}</div> : null}

        {point.top_ips.length > 0 ? (
          <div className="space-y-1">
            <div className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground">Top sources</div>
            {point.top_ips.slice(0, 4).map((ip) => (
              <div key={ip.ip} className="flex items-center justify-between gap-2">
                <IpAddressPill ip={ip.ip} compact />
                <span className="font-mono text-muted-foreground">{ip.count.toLocaleString()}</span>
              </div>
            ))}
          </div>
        ) : null}

        {point.top_rules.length > 0 ? (
          <div className="space-y-1">
            <div className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground">Top rules</div>
            {point.top_rules.slice(0, 3).map((rule) => (
              <div key={rule.rule_id} className="flex items-center justify-between gap-2">
                <span className="truncate font-mono text-foreground">{rule.rule_id}</span>
                <span className="font-mono text-muted-foreground">{rule.count.toLocaleString()}</span>
              </div>
            ))}
          </div>
        ) : null}
      </div>
    </EuiPanel>
  );
}
