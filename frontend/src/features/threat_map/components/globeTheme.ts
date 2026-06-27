import type { SeverityLevel } from "@/shared/lib/severity";

export type GlobeThemeInput = {
  isDark: boolean;
  primary: string;
  border: string;
  emptyShade: string;
  mediumShade: string;
  text: string;
  severity: Record<SeverityLevel, string>;
};

export type GlobeTheme = {
  atmosphere: string;
  homeRing: string;
  homeCore: string;
  polygonStroke: string;
  polygonSide: string;
  polygonCapIdle: string;
  polygonCapHoverBoost: number;
  pointEmissive: string;
  labelText: string;
  severity: Record<SeverityLevel, string>;
  capOpacity: Record<SeverityLevel, number>;
};

const CAP_OPACITY: Record<SeverityLevel, number> = {
  critical: 0.55,
  high: 0.44,
  medium: 0.32,
  low: 0.2,
  info: 0.2,
  neutral: 0.16,
};

export function toSeverityLevel(severity: string | null | undefined): SeverityLevel {
  const value = (severity || "").toLowerCase();
  if (value === "critical" || value === "high" || value === "medium" || value === "low" || value === "info") {
    return value;
  }
  return "neutral";
}

export function withAlpha(color: string, alpha: number): string {
  const a = Math.max(0, Math.min(1, alpha));
  const value = color.trim();
  if (value.startsWith("#")) {
    let hex = value.slice(1);
    if (hex.length === 3) {
      hex = hex
        .split("")
        .map((ch) => ch + ch)
        .join("");
    }
    const r = parseInt(hex.slice(0, 2), 16);
    const g = parseInt(hex.slice(2, 4), 16);
    const b = parseInt(hex.slice(4, 6), 16);
    return `rgba(${r}, ${g}, ${b}, ${a})`;
  }
  const match = value.match(/rgba?\(([^)]+)\)/i);
  if (match) {
    const [r, g, b] = match[1].split(",").map((part) => part.trim());
    return `rgba(${r}, ${g}, ${b}, ${a})`;
  }
  return value;
}

export function buildGlobeTheme(input: GlobeThemeInput): GlobeTheme {
  return {
    atmosphere: input.primary,
    homeRing: input.primary,
    homeCore: input.emptyShade,
    polygonStroke: withAlpha(input.border, input.isDark ? 0.5 : 0.65),
    polygonSide: withAlpha(input.primary, input.isDark ? 0.08 : 0.05),
    polygonCapIdle: "rgba(0, 0, 0, 0)",
    polygonCapHoverBoost: 0.2,
    pointEmissive: input.primary,
    labelText: input.text,
    severity: input.severity,
    capOpacity: CAP_OPACITY,
  };
}
