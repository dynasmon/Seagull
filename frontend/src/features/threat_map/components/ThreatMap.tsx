import { useEffect, useMemo, useRef, useState } from "react";
import { EuiPanel, useEuiTheme } from "@elastic/eui";

import { IpAddressPill } from "@/shared/components/IpAddressPill";
import { useSeverityChartColors } from "@/shared/components/charts/chartTheme";
import type { SeverityLevel } from "@/shared/lib/severity";

import {
  WORLD_LAND_PATH,
  WORLD_VIEWBOX_HEIGHT,
  WORLD_VIEWBOX_WIDTH,
  arcGeometry,
  projectToMap,
} from "../worldMap";
import type { ThreatGeoEndpoint, ThreatGeoFlow, ThreatGeoPoint } from "../types";

const MAX_ARCS = 150;
const MAX_ANIMATED_ARCS = 44;
const MIN_DOT = 1.5;
const MAX_DOT = 6;
const ARC_DURATION_S = 2.9;

type ThreatDirectionLike = ThreatGeoPoint["direction"];

function severityLevel(severity: string | null | undefined): SeverityLevel {
  const value = (severity || "").toLowerCase();
  if (value === "critical" || value === "high" || value === "medium" || value === "low" || value === "info") {
    return value;
  }
  return "neutral";
}

function placeLabel(city?: string | null, region?: string | null, country?: string | null): string {
  const place = [city, region].filter(Boolean)[0];
  const cc = country ? country.toUpperCase() : "";
  if (place && cc) return `${place} · ${cc}`;
  return place || cc || "Unknown location";
}

function pointLabel(point: ThreatGeoPoint): string {
  return placeLabel(point.city, point.region, point.country);
}

function provenanceLabel(provenance: string): string {
  if (provenance === "alert") return "Confirmed alert";
  if (provenance === "mixed") return "Alert + ambient";
  return "Ambient event";
}

function directionLabel(direction: ThreatDirectionLike): string {
  if (direction === "outbound") return "Outbound";
  if (direction === "internal") return "Internal";
  if (direction === "transit") return "Transit";
  if (direction === "mixed") return "Mixed";
  return "Inbound";
}

function dotRadius(count: number, maxCount: number): number {
  if (maxCount <= 1) return MIN_DOT + (MAX_DOT - MIN_DOT) * 0.4;
  const ratio = Math.sqrt(Math.max(0, count) / maxCount);
  return MIN_DOT + (MAX_DOT - MIN_DOT) * ratio;
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

function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) return;
    const query = window.matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => setReduced(query.matches);
    update();
    query.addEventListener("change", update);
    return () => query.removeEventListener("change", update);
  }, []);
  return reduced;
}

function useActiveVisibility(ref: React.RefObject<Element>): boolean {
  const [visible, setVisible] = useState(true);
  useEffect(() => {
    const node = ref.current;
    if (!node || typeof IntersectionObserver === "undefined") return;
    let onScreen = true;
    const observer = new IntersectionObserver(
      (entries) => {
        onScreen = entries[0]?.isIntersecting ?? true;
        setVisible(onScreen && !document.hidden);
      },
      { threshold: 0.1 },
    );
    observer.observe(node);
    const onVisibility = () => setVisible(onScreen && !document.hidden);
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      observer.disconnect();
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [ref]);
  return visible;
}

type SourceDot = {
  id: string;
  point: ThreatGeoPoint;
  x: number;
  y: number;
  r: number;
  color: string;
  promoted: boolean;
  outbound: boolean;
};

type Arc = {
  id: string;
  path: string;
  color: string;
  weight: number;
  promoted: boolean;
  outbound: boolean;
};

function projectionsClose(a: { x: number; y: number }, b: { x: number; y: number }): boolean {
  return Math.abs(a.x - b.x) < 0.6 && Math.abs(a.y - b.y) < 0.6;
}

function graticule(): string[] {
  const lines: string[] = [];
  for (let lon = -150; lon <= 150; lon += 30) {
    const top = projectToMap(85, lon);
    const bottom = projectToMap(-85, lon);
    lines.push(`M ${top.x} ${top.y} L ${bottom.x} ${bottom.y}`);
  }
  for (let lat = -60; lat <= 60; lat += 30) {
    const left = projectToMap(lat, -180);
    const right = projectToMap(lat, 180);
    lines.push(`M ${left.x} ${left.y} L ${right.x} ${right.y}`);
  }
  return lines;
}

export function ThreatMap({
  points,
  flows = [],
  home = null,
  animate = true,
}: {
  points: ThreatGeoPoint[];
  flows?: ThreatGeoFlow[];
  home?: ThreatGeoEndpoint | null;
  animate?: boolean;
}) {
  const { euiTheme, colorMode } = useEuiTheme();
  const severityColors = useSeverityChartColors();
  const isDark = colorMode === "DARK";
  const [hoveredId, setHoveredId] = useState<string | null>(null);

  const containerRef = useRef<HTMLDivElement>(null);
  const reducedMotion = usePrefersReducedMotion();
  const onScreen = useActiveVisibility(containerRef);
  const animationOn = animate && !reducedMotion && onScreen;

  const homeXY = useMemo(() => (home ? projectToMap(home.lat, home.lon) : null), [home]);
  const gridLines = useMemo(() => graticule(), []);

  const maxCount = useMemo(() => points.reduce((max, p) => Math.max(max, p.count), 0), [points]);

  const dots = useMemo<SourceDot[]>(() => {
    return points
      .map((point) => {
        const { x, y } = projectToMap(point.lat, point.lon);
        return {
          id: `${point.lat},${point.lon},${point.direction},${point.provenance}`,
          point,
          x,
          y,
          r: dotRadius(point.count, maxCount),
          color: severityColors[severityLevel(point.severity)],
          promoted: point.provenance === "alert" || point.provenance === "mixed",
          outbound: point.direction === "outbound",
        };
      })
      .sort((a, b) => b.r - a.r);
  }, [points, maxCount, severityColors]);

  const arcs = useMemo<Arc[]>(() => {
    const built: Arc[] = [];
    if (homeXY) {
      for (const point of points) {
        const origin = projectToMap(point.lat, point.lon);
        if (projectionsClose(origin, homeXY)) continue;
        const outbound = point.direction === "outbound";
        const from = outbound ? homeXY : origin;
        const to = outbound ? origin : homeXY;
        const geo = arcGeometry(from.x, from.y, to.x, to.y);
        built.push({
          id: `a:${point.lat},${point.lon},${point.direction},${point.provenance}`,
          path: geo.path,
          color: severityColors[severityLevel(point.severity)],
          weight: point.count,
          promoted: point.provenance === "alert" || point.provenance === "mixed",
          outbound,
        });
      }
    }
    for (const flow of flows) {
      if (!flow.origin || !flow.target) continue;
      const from = projectToMap(flow.origin.lat, flow.origin.lon);
      const to = projectToMap(flow.target.lat, flow.target.lon);
      if (projectionsClose(from, to)) continue;
      const geo = arcGeometry(from.x, from.y, to.x, to.y);
      built.push({
        id: `f:${flow.id}`,
        path: geo.path,
        color: severityColors[severityLevel(flow.severity)],
        weight: flow.weight,
        promoted: flow.provenance === "alert" || flow.provenance === "mixed",
        outbound: flow.direction === "outbound",
      });
    }
    built.sort((a, b) => b.weight - a.weight);
    return built.slice(0, MAX_ARCS);
  }, [points, flows, homeXY, severityColors]);

  const animatedIds = useMemo(() => {
    if (!animationOn) return new Set<string>();
    return new Set(arcs.slice(0, MAX_ANIMATED_ARCS).map((arc) => arc.id));
  }, [arcs, animationOn]);

  const active = useMemo(() => dots.find((d) => d.id === hoveredId) ?? null, [dots, hoveredId]);

  const oceanTop = isDark ? euiTheme.colors.darkestShade : euiTheme.colors.lightestShade;
  const oceanBottom = isDark ? euiTheme.colors.darkShade : euiTheme.colors.lightShade;
  const landColor = euiTheme.colors.mediumShade;
  const gridColor = euiTheme.colors.mediumShade;
  const homeColor = euiTheme.colors.primary;
  const homeCore = euiTheme.colors.emptyShade;

  const activeXRatio = active ? active.x / WORLD_VIEWBOX_WIDTH : 0;
  const activeYRatio = active ? active.y / WORLD_VIEWBOX_HEIGHT : 0;

  return (
    <div ref={containerRef} className="absolute inset-0 h-full w-full">
      <svg
        className="absolute inset-0 h-full w-full"
        viewBox={`0 0 ${WORLD_VIEWBOX_WIDTH} ${WORLD_VIEWBOX_HEIGHT}`}
        preserveAspectRatio="xMidYMid meet"
        role="img"
        aria-label="World map of suspicious network activity converging on the monitored network"
      >
        <defs>
          <linearGradient id="tmOcean" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={oceanTop} stopOpacity={isDark ? 0.55 : 0.7} />
            <stop offset="100%" stopColor={oceanBottom} stopOpacity={isDark ? 0.3 : 0.55} />
          </linearGradient>
          <radialGradient id="tmHomeGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor={homeColor} stopOpacity={0.5} />
            <stop offset="100%" stopColor={homeColor} stopOpacity={0} />
          </radialGradient>
        </defs>

        {animationOn ? (
          <style>{
            "@keyframes tmComet{to{stroke-dashoffset:-100}}" +
            "@keyframes tmHomeRing{0%{r:5;opacity:0.45}100%{r:30;opacity:0}}" +
            "@keyframes tmHomeCore{0%,100%{opacity:0.85}50%{opacity:1}}" +
            ".tm-comet{animation:tmComet var(--tm-dur) linear infinite}" +
            ".tm-home-ring{animation:tmHomeRing 2.9s ease-out infinite}" +
            ".tm-home-core{animation:tmHomeCore 2.9s ease-in-out infinite}"
          }</style>
        ) : null}

        <rect
          x={0}
          y={0}
          width={WORLD_VIEWBOX_WIDTH}
          height={WORLD_VIEWBOX_HEIGHT}
          rx={10}
          fill="url(#tmOcean)"
        />

        <g stroke={gridColor} strokeOpacity={isDark ? 0.12 : 0.18} strokeWidth={0.5}>
          {gridLines.map((d, index) => (
            <path key={`grid-${index}`} d={d} fill="none" />
          ))}
        </g>

        <path d={WORLD_LAND_PATH} fill={landColor} fillOpacity={isDark ? 0.5 : 0.72} />

        <g fill="none" strokeLinecap="round">
          {arcs.map((arc) => {
            const animated = animatedIds.has(arc.id);
            const baseOpacity = arc.promoted ? 0.55 : 0.28;
            const width = arc.promoted ? 1.1 : 0.8;
            return (
              <g key={arc.id}>
                <path d={arc.path} stroke={arc.color} strokeOpacity={baseOpacity} strokeWidth={width} />
                {animated ? (
                  <>
                    <path
                      d={arc.path}
                      pathLength={100}
                      stroke={arc.color}
                      strokeOpacity={0.22}
                      strokeWidth={width + 2.4}
                      strokeDasharray="10 90"
                      className="tm-comet"
                      style={{ ["--tm-dur" as string]: `${ARC_DURATION_S}s`, animationDelay: `${(arc.weight % 7) * 0.32}s` }}
                    />
                    <path
                      d={arc.path}
                      pathLength={100}
                      stroke={arc.color}
                      strokeOpacity={0.95}
                      strokeWidth={width + 0.4}
                      strokeDasharray="7 93"
                      className="tm-comet"
                      style={{ ["--tm-dur" as string]: `${ARC_DURATION_S}s`, animationDelay: `${(arc.weight % 7) * 0.32}s` }}
                    />
                  </>
                ) : null}
              </g>
            );
          })}
        </g>

        <g>
          {dots.map((dot) => {
            const isActive = dot.id === hoveredId;
            const baseOpacity = dot.promoted ? 0.92 : 0.62;
            return (
              <g
                key={dot.id}
                tabIndex={0}
                role="button"
                aria-label={`${dot.point.count} ${provenanceLabel(dot.point.provenance).toLowerCase()} hits from ${pointLabel(dot.point)}`}
                style={{ cursor: "pointer", outline: "none" }}
                onMouseEnter={() => setHoveredId(dot.id)}
                onMouseLeave={() => setHoveredId((current) => (current === dot.id ? null : current))}
                onFocus={() => setHoveredId(dot.id)}
                onBlur={() => setHoveredId((current) => (current === dot.id ? null : current))}
              >
                <circle cx={dot.x} cy={dot.y} r={dot.r + 7} fill="transparent" />
                <circle
                  cx={dot.x}
                  cy={dot.y}
                  r={dot.r}
                  fill={dot.color}
                  fillOpacity={isActive ? 1 : baseOpacity}
                  stroke={dot.color}
                  strokeOpacity={0.35}
                  strokeWidth={dot.r + 2}
                  paintOrder="stroke"
                />
                {isActive ? (
                  <circle
                    cx={dot.x}
                    cy={dot.y}
                    r={dot.r + 4}
                    fill="none"
                    stroke={dot.color}
                    strokeWidth={1.2}
                    pointerEvents="none"
                  />
                ) : null}
              </g>
            );
          })}
        </g>

        {homeXY ? (
          <g pointerEvents="none">
            <circle cx={homeXY.x} cy={homeXY.y} r={34} fill="url(#tmHomeGlow)" />
            {animationOn
              ? [0, 1, 2].map((index) => (
                  <circle
                    key={`home-ring-${index}`}
                    className="tm-home-ring"
                    cx={homeXY.x}
                    cy={homeXY.y}
                    r={5}
                    fill="none"
                    stroke={homeColor}
                    strokeWidth={1.4}
                    style={{ animationDelay: `${index * 0.97}s` }}
                  />
                ))
              : null}
            <circle cx={homeXY.x} cy={homeXY.y} r={6.5} fill={homeColor} fillOpacity={0.25} />
            <circle
              className={animationOn ? "tm-home-core" : undefined}
              cx={homeXY.x}
              cy={homeXY.y}
              r={3.6}
              fill={homeCore}
              stroke={homeColor}
              strokeWidth={1.8}
            />
            <text
              x={homeXY.x}
              y={homeXY.y - 13}
              textAnchor="middle"
              fontSize={9}
              fontWeight={600}
              fill={homeColor}
              style={{ letterSpacing: "0.5px" }}
            >
              {home?.label || "Your network"}
            </text>
          </g>
        ) : null}
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
          <ThreatTooltip dot={active} severityColors={severityColors} surface={euiTheme.colors.emptyShade} />
        </div>
      ) : null}
    </div>
  );
}

function ThreatTooltip({
  dot,
  severityColors,
  surface,
}: {
  dot: SourceDot;
  severityColors: Record<SeverityLevel, string>;
  surface: string;
}) {
  const { point } = dot;
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
          <span className="inline-block h-2.5 w-2.5 shrink-0 rounded-full" style={{ backgroundColor: dot.color }} />
          <span className="truncate font-semibold text-foreground">{pointLabel(point)}</span>
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          <span
            className="rounded-sm border px-1.5 py-0 text-[9px] uppercase tracking-[0.08em]"
            style={{
              borderColor: dot.promoted ? dot.color : undefined,
              color: dot.promoted ? dot.color : undefined,
            }}
          >
            {provenanceLabel(point.provenance)}
          </span>
          <span className="rounded-sm border border-border/60 px-1.5 py-0 text-[9px] uppercase tracking-[0.08em] text-muted-foreground">
            {directionLabel(point.direction)}
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-muted-foreground">
          <span>
            <span className="font-mono text-foreground">{point.count.toLocaleString()}</span> hits
          </span>
          <span>
            <span className="font-mono text-foreground">{point.unique_ips.toLocaleString()}</span> IPs
          </span>
          {lastSeen ? <span>{lastSeen}</span> : null}
        </div>

        {point.alert_count > 0 && point.event_count > 0 ? (
          <div className="text-[11px] text-muted-foreground">
            <span className="font-mono text-foreground">{point.alert_count.toLocaleString()}</span> alerts ·{" "}
            <span className="font-mono text-foreground">{point.event_count.toLocaleString()}</span> events
          </div>
        ) : null}

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
            <div className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground">
              {dot.outbound ? "Top targets" : "Top sources"}
            </div>
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
