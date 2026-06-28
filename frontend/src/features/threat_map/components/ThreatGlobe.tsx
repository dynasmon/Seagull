import { useEffect, useMemo, useRef, useState } from "react";
import Globe, { type GlobeMethods } from "react-globe.gl";
import { useEuiTheme } from "@elastic/eui";

import { useSeverityChartColors } from "@/shared/components/charts/chartTheme";
import { useReducedMotion } from "@/shared/hooks/useReducedMotion";

import { buildGlobeTheme, toSeverityLevel, withAlpha } from "./globeTheme";
import type { CountrySelection } from "./CountryDetailDrawer";
import { countryCodeForFeature, useCountryAggregations } from "../useCountryAggregations";
import { useGlobeAutoRotate } from "../useGlobeAutoRotate";
import type { ThreatGeoEndpoint, ThreatGeoFlow, ThreatGeoPoint } from "../types";

const EARTH_TEXTURE = "/datasets/earth-night.jpg";
const COUNTRIES_URL = "/datasets/countries-110m.geojson";
const MIN_POINT_ALTITUDE = 0.005;
const MAX_POINT_ALTITUDE = 0.06;
const MIN_POINT_RADIUS = 0.15;
const MAX_POINT_RADIUS = 0.5;
const HOME_ALTITUDE = 2.2;
const SELECTED_ALTITUDE = 1.1;
const CITY_ALTITUDE = 0.4;
const HOME_CORE_RADIUS = 0.62;
const HOME_CORE_ALTITUDE = 0.02;
const POLYGON_IDLE_ALTITUDE = 0.005;
const POLYGON_TRAFFIC_ALTITUDE = 0.009;
const POLYGON_HOVER_ALTITUDE = 0.02;
const POLYGON_SELECTED_ALTITUDE = 0.035;
const MAX_ARCS = 180;
const MIN_ARC_STROKE = 0.55;
const MAX_ARC_STROKE = 2.4;
const MIN_ARC_ANIMATE_MS = 1200;
const MAX_ARC_ANIMATE_MS = 3200;
const HOME_PROXIMITY_DEGREES = 0.5;
const RING_MAX_RADIUS = 4;
const RING_PROPAGATION_SPEED = 2.4;
const RING_REPEAT_PERIOD = 900;
const RING_ALTITUDE = 0.006;

export type DirectionFilter = "all" | "inbound" | "outbound" | "internal" | "transit";

export type ThreatGlobeProps = {
  points: ThreatGeoPoint[];
  flows: ThreatGeoFlow[];
  home: ThreatGeoEndpoint | null;
  animate: boolean;
  direction: DirectionFilter;
  autoRotate: boolean;
  resetSignal: number;
  selectedCode: string | null;
  cityFocus: { lat: number; lng: number; key: number } | null;
  onSelectCountry: (selection: CountrySelection | null) => void;
  onAutoRotateOff: () => void;
};

type CountryFeature = {
  type: "Feature";
  properties: Record<string, unknown>;
  geometry: unknown;
  bbox?: number[];
};

type GlobePoint = {
  lat: number;
  lng: number;
  altitude: number;
  radius: number;
  color: string;
};

type GlobeRing = {
  lat: number;
  lng: number;
};

type GlobeArc = {
  startLat: number;
  startLng: number;
  endLat: number;
  endLng: number;
  colors: [string, string];
  baseColor: string;
  stroke: number;
  dashAnimateTime: number;
  initialGap: number;
  weight: number;
};

function scaleByCount(count: number, maxCount: number, min: number, max: number): number {
  if (maxCount <= 1) return min + (max - min) * 0.45;
  const ratio = Math.sqrt(Math.max(0, count) / maxCount);
  return min + (max - min) * ratio;
}

function near(latA: number, lngA: number, latB: number, lngB: number): boolean {
  return Math.abs(latA - latB) < HOME_PROXIMITY_DEGREES && Math.abs(lngA - lngB) < HOME_PROXIMITY_DEGREES;
}

function centroidFromFeature(feature: CountryFeature): { lat: number; lng: number } | null {
  const bbox = feature.bbox;
  if (!Array.isArray(bbox) || bbox.length < 4) return null;
  const minLng = bbox[0];
  const minLat = bbox[1];
  let maxLng = bbox[2];
  const maxLat = bbox[3];
  if (maxLng < minLng) maxLng += 360;
  let lng = (minLng + maxLng) / 2;
  if (lng > 180) lng -= 360;
  return { lat: (minLat + maxLat) / 2, lng };
}

export default function ThreatGlobe({
  points,
  flows,
  home,
  animate,
  direction,
  autoRotate,
  resetSignal,
  selectedCode,
  cityFocus,
  onSelectCountry,
  onAutoRotateOff,
}: ThreatGlobeProps) {
  const { euiTheme, colorMode } = useEuiTheme();
  const severityColors = useSeverityChartColors();
  const reducedMotion = useReducedMotion();
  const isDark = colorMode === "DARK";
  const animationOn = animate && !reducedMotion;

  const theme = useMemo(
    () =>
      buildGlobeTheme({
        isDark,
        primary: euiTheme.colors.primary,
        border: euiTheme.colors.lightShade,
        emptyShade: euiTheme.colors.emptyShade,
        mediumShade: euiTheme.colors.mediumShade,
        text: euiTheme.colors.text,
        severity: severityColors,
      }),
    [euiTheme, isDark, severityColors],
  );

  const containerRef = useRef<HTMLDivElement>(null);
  const globeRef = useRef<GlobeMethods | undefined>(undefined);
  const lastPolygonClick = useRef(0);
  const hadSelection = useRef(false);
  const didCenter = useRef(false);
  const lastReset = useRef(resetSignal);
  const [size, setSize] = useState({ width: 0, height: 0 });
  const [globeReady, setGlobeReady] = useState(false);
  const [countries, setCountries] = useState<CountryFeature[]>([]);
  const [hoverFeature, setHoverFeature] = useState<CountryFeature | null>(null);

  const visiblePoints = useMemo(
    () => (direction === "all" ? points : points.filter((point) => point.direction === direction)),
    [points, direction],
  );
  const visibleFlows = useMemo(
    () => (direction === "all" ? flows : flows.filter((flow) => flow.direction === direction)),
    [flows, direction],
  );
  const aggregations = useCountryAggregations(visiblePoints);

  useEffect(() => {
    const node = containerRef.current;
    if (!node) return;
    const observer = new ResizeObserver((entries) => {
      const rect = entries[0]?.contentRect;
      if (rect) setSize({ width: Math.round(rect.width), height: Math.round(rect.height) });
    });
    observer.observe(node);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    let active = true;
    fetch(COUNTRIES_URL)
      .then((response) => response.json())
      .then((collection: { features?: CountryFeature[] }) => {
        if (active) setCountries(collection.features ?? []);
      })
      .catch(() => {
        if (active) setCountries([]);
      });
    return () => {
      active = false;
    };
  }, []);

  const maxCount = useMemo(() => visiblePoints.reduce((max, point) => Math.max(max, point.count), 0), [visiblePoints]);

  const globePoints = useMemo<GlobePoint[]>(() => {
    const result = visiblePoints.map((point) => ({
      lat: point.lat,
      lng: point.lon,
      altitude: scaleByCount(point.count, maxCount, MIN_POINT_ALTITUDE, MAX_POINT_ALTITUDE),
      radius: scaleByCount(point.count, maxCount, MIN_POINT_RADIUS, MAX_POINT_RADIUS),
      color: severityColors[toSeverityLevel(point.severity)],
    }));
    if (home) {
      result.push({
        lat: home.lat,
        lng: home.lon,
        altitude: HOME_CORE_ALTITUDE,
        radius: HOME_CORE_RADIUS,
        color: theme.homeRing,
      });
    }
    return result;
  }, [visiblePoints, maxCount, severityColors, home, theme.homeRing]);

  const homeRings = useMemo<GlobeRing[]>(() => (home ? [{ lat: home.lat, lng: home.lon }] : []), [home]);

  const maxWeight = useMemo(() => {
    let max = 0;
    for (const point of visiblePoints) max = Math.max(max, point.count);
    for (const flow of visibleFlows) max = Math.max(max, flow.weight);
    return max;
  }, [visiblePoints, visibleFlows]);

  const arcs = useMemo<GlobeArc[]>(() => {
    if (!home) return [];
    const homeLat = home.lat;
    const homeLng = home.lon;
    const primary = euiTheme.colors.primary;
    const built: GlobeArc[] = [];

    const makeArc = (
      startLat: number,
      startLng: number,
      endLat: number,
      endLng: number,
      colors: [string, string],
      weight: number,
    ): GlobeArc => {
      const trail = withAlpha(colors[1], 0.22);
      return {
        startLat,
        startLng,
        endLat,
        endLng,
        colors,
        baseColor: trail,
        stroke: scaleByCount(weight, maxWeight, MIN_ARC_STROKE, MAX_ARC_STROKE),
        dashAnimateTime:
          MAX_ARC_ANIMATE_MS - scaleByCount(weight, maxWeight, 0, MAX_ARC_ANIMATE_MS - MIN_ARC_ANIMATE_MS),
        initialGap: (Math.round(Math.abs(weight)) % 9) / 9,
        weight,
      };
    };

    for (const point of visiblePoints) {
      if (near(point.lat, point.lon, homeLat, homeLng)) continue;
      const outbound = point.direction === "outbound";
      const accent = severityColors[toSeverityLevel(point.severity)];
      built.push(
        outbound
          ? makeArc(homeLat, homeLng, point.lat, point.lon, [primary, accent], point.count)
          : makeArc(point.lat, point.lon, homeLat, homeLng, [accent, primary], point.count),
      );
    }

    for (const flow of visibleFlows) {
      if (!flow.origin || !flow.target) continue;
      if (near(flow.origin.lat, flow.origin.lon, flow.target.lat, flow.target.lon)) continue;
      const accent = severityColors[toSeverityLevel(flow.severity)];
      built.push(
        makeArc(flow.origin.lat, flow.origin.lon, flow.target.lat, flow.target.lon, [accent, primary], flow.weight),
      );
    }

    built.sort((a, b) => b.weight - a.weight);
    return built.slice(0, MAX_ARCS);
  }, [visiblePoints, visibleFlows, home, maxWeight, severityColors, euiTheme.colors.primary]);

  const arcsRendered = useMemo<Array<GlobeArc & { kind: "trail" | "comet" }>>(() => {
    const out: Array<GlobeArc & { kind: "trail" | "comet" }> = [];
    for (const arc of arcs) {
      out.push({ ...arc, kind: "trail" });
      out.push({ ...arc, kind: "comet" });
    }
    return out;
  }, [arcs]);

  const featureCode = useMemo(() => {
    const map = new Map<CountryFeature, string | null>();
    for (const feature of countries) {
      map.set(feature, countryCodeForFeature(feature.properties));
    }
    return map;
  }, [countries]);

  const selectedFeature = useMemo(() => {
    if (!selectedCode) return null;
    return countries.find((feature) => featureCode.get(feature) === selectedCode) ?? null;
  }, [countries, featureCode, selectedCode]);

  const polygonCapColor = (feature: object) => {
    const country = feature as CountryFeature;
    const code = featureCode.get(country) ?? null;
    const aggregation = code ? aggregations.get(code) : undefined;
    const hovered = country === hoverFeature;
    const selected = code != null && code === selectedCode;
    if (!aggregation) {
      if (selected) return withAlpha(theme.atmosphere, 0.18);
      return hovered ? withAlpha(theme.severity.neutral, 0.12) : theme.polygonCapIdle;
    }
    const boost = (hovered ? theme.polygonCapHoverBoost : 0) + (selected ? 0.28 : 0);
    const opacity = Math.min(0.9, theme.capOpacity[aggregation.dominantSeverity] + boost);
    return withAlpha(theme.severity[aggregation.dominantSeverity], opacity);
  };

  const polygonAltitude = (feature: object) => {
    const country = feature as CountryFeature;
    const code = featureCode.get(country) ?? null;
    if (code != null && code === selectedCode) return POLYGON_SELECTED_ALTITUDE;
    if (country === hoverFeature) return POLYGON_HOVER_ALTITUDE;
    return code && aggregations.has(code) ? POLYGON_TRAFFIC_ALTITUDE : POLYGON_IDLE_ALTITUDE;
  };

  const polygonStrokeColor = (feature: object) => {
    const country = feature as CountryFeature;
    const code = featureCode.get(country) ?? null;
    return code != null && code === selectedCode ? theme.atmosphere : theme.polygonStroke;
  };

  const polygonLabel = (feature: object) => {
    const country = feature as CountryFeature;
    const code = featureCode.get(country) ?? null;
    const aggregation = code ? aggregations.get(code) : undefined;
    if (!aggregation || !code) return "";
    const name = String(country.properties.ADMIN ?? country.properties.NAME ?? code);
    const color = theme.severity[aggregation.dominantSeverity];
    return `
      <div style="font-family:Inter,sans-serif;min-width:160px;padding:8px 10px;border-radius:8px;background:${euiTheme.colors.emptyShade};border:1px solid ${theme.polygonStroke};box-shadow:0 8px 24px rgba(2,8,20,0.35);color:${theme.labelText};">
        <div style="display:flex;align-items:center;gap:6px;font-size:12px;font-weight:600;">
          <span style="width:8px;height:8px;border-radius:9999px;background:${color};"></span>
          <span>${name}</span>
          <span style="opacity:.5;font-family:monospace;">${code}</span>
        </div>
        <div style="margin-top:4px;font-size:11px;opacity:.75;">
          ${aggregation.hits.toLocaleString()} hits · ${aggregation.uniqueIps.toLocaleString()} IPs · top ${aggregation.dominantSeverity}
        </div>
      </div>`;
  };

  const handlePolygonClick = (feature: object) => {
    const country = feature as CountryFeature;
    const code = featureCode.get(country) ?? null;
    if (!code) return;
    lastPolygonClick.current = Date.now();
    const name = String(country.properties.ADMIN ?? country.properties.NAME ?? code);
    onSelectCountry({ code, name });
  };

  const handleGlobeClick = () => {
    if (Date.now() - lastPolygonClick.current < 120) return;
    if (selectedCode) onSelectCountry(null);
  };

  const handleGlobeReady = () => {
    const controls = globeRef.current?.controls();
    if (controls) {
      controls.enableZoom = false;
      controls.enablePan = false;
      controls.minDistance = 180;
      controls.maxDistance = 620;
      controls.dampingFactor = 0.12;
      controls.enableDamping = true;
    }
    setGlobeReady(true);
  };

  useEffect(() => {
    if (!globeReady) return;
    const node = containerRef.current;
    if (!node) return;
    const handleWheel = (event: WheelEvent) => {
      const controls = globeRef.current?.controls();
      if (!controls) return;
      controls.enableZoom = event.shiftKey;
    };
    node.addEventListener("wheel", handleWheel, { capture: true, passive: true });
    return () => node.removeEventListener("wheel", handleWheel, { capture: true });
  }, [globeReady]);

  useEffect(() => {
    if (!globeReady || didCenter.current || !home) return;
    didCenter.current = true;
    globeRef.current?.pointOfView({ lat: home.lat, lng: home.lon, altitude: HOME_ALTITUDE }, 0);
  }, [globeReady, home]);

  useEffect(() => {
    if (!globeReady) return;
    if (selectedCode) {
      hadSelection.current = true;
      const target = selectedFeature ? centroidFromFeature(selectedFeature) : null;
      if (target) globeRef.current?.pointOfView({ lat: target.lat, lng: target.lng, altitude: SELECTED_ALTITUDE }, 1200);
    } else if (hadSelection.current) {
      hadSelection.current = false;
      if (home) globeRef.current?.pointOfView({ lat: home.lat, lng: home.lon, altitude: HOME_ALTITUDE }, 1000);
    }
  }, [selectedCode, selectedFeature, globeReady, home]);

  useEffect(() => {
    if (!globeReady || !cityFocus) return;
    globeRef.current?.pointOfView({ lat: cityFocus.lat, lng: cityFocus.lng, altitude: CITY_ALTITUDE }, 1000);
  }, [cityFocus, globeReady]);

  useEffect(() => {
    if (!globeReady) return;
    if (resetSignal === lastReset.current) return;
    lastReset.current = resetSignal;
    if (home) globeRef.current?.pointOfView({ lat: home.lat, lng: home.lon, altitude: HOME_ALTITUDE }, 1200);
  }, [resetSignal, globeReady, home]);

  useGlobeAutoRotate({
    globeRef,
    containerRef,
    ready: globeReady,
    enabled: autoRotate && !reducedMotion,
    paused: Boolean(selectedCode),
    onUserInteract: onAutoRotateOff,
  });

  const hoverCode = hoverFeature ? featureCode.get(hoverFeature) ?? null : null;
  const hoverHasTraffic = Boolean(hoverCode && aggregations.has(hoverCode));

  return (
    <div
      ref={containerRef}
      data-testid="threat-globe"
      className="absolute inset-0 h-full w-full overflow-hidden"
      style={{
        background: `radial-gradient(120% 90% at 50% 8%, rgb(var(--surface-1) / 0.7), rgb(var(--background)) 70%)`,
        cursor: hoverHasTraffic ? "pointer" : "grab",
      }}
    >
      {size.width > 0 && size.height > 0 ? (
        <Globe
          ref={globeRef}
          width={size.width}
          height={size.height}
          backgroundColor="rgba(0, 0, 0, 0)"
          globeImageUrl={EARTH_TEXTURE}
          showAtmosphere
          atmosphereColor={theme.atmosphere}
          atmosphereAltitude={0.18}
          polygonsData={countries}
          polygonCapColor={polygonCapColor}
          polygonSideColor={() => theme.polygonSide}
          polygonStrokeColor={polygonStrokeColor}
          polygonAltitude={polygonAltitude}
          polygonLabel={polygonLabel}
          polygonsTransitionDuration={300}
          onPolygonHover={(feature) => setHoverFeature(feature ? (feature as CountryFeature) : null)}
          onPolygonClick={handlePolygonClick}
          onGlobeClick={handleGlobeClick}
          arcsData={arcsRendered}
          arcStartLat="startLat"
          arcStartLng="startLng"
          arcEndLat="endLat"
          arcEndLng="endLng"
          arcColor={(arc: object) => {
            const a = arc as GlobeArc & { kind: "trail" | "comet" };
            return a.kind === "trail" ? [a.baseColor, a.baseColor] : a.colors;
          }}
          arcStroke={(arc) => {
            const a = arc as GlobeArc & { kind: "trail" | "comet" };
            return a.kind === "trail" ? Math.max(0.35, a.stroke * 0.55) : a.stroke;
          }}
          arcAltitudeAutoScale={0.5}
          arcDashLength={(arc) =>
            (arc as GlobeArc & { kind: "trail" | "comet" }).kind === "trail" ? 1 : 0.32
          }
          arcDashGap={(arc) =>
            (arc as GlobeArc & { kind: "trail" | "comet" }).kind === "trail" ? 0 : 0.45
          }
          arcDashInitialGap={(arc) => {
            const a = arc as GlobeArc & { kind: "trail" | "comet" };
            return a.kind === "trail" ? 0 : a.initialGap;
          }}
          arcDashAnimateTime={(arc) => {
            const a = arc as GlobeArc & { kind: "trail" | "comet" };
            if (a.kind === "trail") return 0;
            return animationOn ? a.dashAnimateTime : 0;
          }}
          arcsTransitionDuration={0}
          ringsData={animationOn ? homeRings : []}
          ringColor={() => (t: number) => withAlpha(theme.homeRing, 1 - t)}
          ringMaxRadius={RING_MAX_RADIUS}
          ringPropagationSpeed={RING_PROPAGATION_SPEED}
          ringRepeatPeriod={RING_REPEAT_PERIOD}
          ringAltitude={RING_ALTITUDE}
          pointsData={globePoints}
          pointLat="lat"
          pointLng="lng"
          pointColor="color"
          pointAltitude="altitude"
          pointRadius="radius"
          pointsMerge
          pointResolution={12}
          onGlobeReady={handleGlobeReady}
        />
      ) : null}
      <div className="pointer-events-none absolute bottom-2 right-3 select-none text-[10px] uppercase tracking-[0.12em] text-muted-foreground/70">
        hold shift + scroll to zoom
      </div>
    </div>
  );
}
