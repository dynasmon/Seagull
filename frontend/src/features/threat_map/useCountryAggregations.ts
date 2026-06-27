import { useMemo } from "react";

import type { SeverityLevel } from "@/shared/lib/severity";

import { toSeverityLevel } from "./components/globeTheme";
import type { ThreatGeoPoint } from "./types";

export type CountryAggregation = {
  code: string;
  hits: number;
  uniqueIps: number;
  points: ThreatGeoPoint[];
  severityCounts: Record<SeverityLevel, number>;
  dominantSeverity: SeverityLevel;
  lastSeen: string | null;
};

const SEVERITY_RANK: SeverityLevel[] = ["critical", "high", "medium", "low", "info", "neutral"];

const NAME_TO_ISO2: Record<string, string> = {
  NORWAY: "NO",
  FRANCE: "FR",
  KOSOVO: "XK",
  "NORTHERN CYPRUS": "CY",
  SOMALILAND: "SO",
};

export function normalizeCountryCode(value: string | null | undefined): string | null {
  const code = (value || "").trim().toUpperCase();
  if (!code || code === "-99" || code.length !== 2) return null;
  return code;
}

export function countryCodeForFeature(properties: Record<string, unknown>): string | null {
  const candidates = [properties.ISO_A2, properties.WB_A2, properties.FIPS_10_];
  for (const candidate of candidates) {
    const code = normalizeCountryCode(typeof candidate === "string" ? candidate : null);
    if (code) return code;
  }
  const name = String(properties.ADMIN ?? properties.NAME ?? "").toUpperCase();
  return NAME_TO_ISO2[name] ?? null;
}

function emptySeverityCounts(): Record<SeverityLevel, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0, neutral: 0 };
}

export function useCountryAggregations(points: ThreatGeoPoint[]): Map<string, CountryAggregation> {
  return useMemo(() => {
    const map = new Map<string, CountryAggregation>();
    for (const point of points) {
      const code = normalizeCountryCode(point.country);
      if (!code) continue;
      let aggregation = map.get(code);
      if (!aggregation) {
        aggregation = {
          code,
          hits: 0,
          uniqueIps: 0,
          points: [],
          severityCounts: emptySeverityCounts(),
          dominantSeverity: "neutral",
          lastSeen: null,
        };
        map.set(code, aggregation);
      }
      aggregation.points.push(point);
      aggregation.hits += point.count;
      aggregation.uniqueIps += point.unique_ips;
      aggregation.severityCounts.critical += point.critical;
      aggregation.severityCounts.high += point.high;
      aggregation.severityCounts.medium += point.medium;
      aggregation.severityCounts.low += point.low;
      if (point.last_seen && (!aggregation.lastSeen || point.last_seen > aggregation.lastSeen)) {
        aggregation.lastSeen = point.last_seen;
      }
    }
    for (const aggregation of map.values()) {
      aggregation.dominantSeverity =
        SEVERITY_RANK.find((level) => aggregation.severityCounts[level] > 0) ??
        toSeverityLevel(aggregation.points[0]?.severity);
    }
    return map;
  }, [points]);
}
