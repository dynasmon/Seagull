import { useMemo } from "react";
import { useEuiTheme, euiPaletteColorBlind } from "@elastic/eui";
import { DARK_THEME, LIGHT_THEME } from "@elastic/charts";
import type { PartialTheme, Theme } from "@elastic/charts";

import type { SeverityLevel } from "@/shared/lib/severity";

export interface EuiChartTheme {
  baseTheme: Theme;
  theme: PartialTheme;
  isDark: boolean;
  vizColors: string[];
  tokens: {
    text: string;
    subdued: string;
    grid: string;
    axisLine: string;
    surface: string;
  };
}

export function useEuiChartTheme(): EuiChartTheme {
  const { euiTheme, colorMode } = useEuiTheme();

  return useMemo(() => {
    const isDark = colorMode === "DARK";
    const c = euiTheme.colors;
    const fontFamily = euiTheme.font.family;

    const text = c.text;
    const subdued = c.subduedText;
    const grid = c.lightShade;
    const axisLine = c.lightShade;
    const surface = c.emptyShade;
    const vizColors = euiPaletteColorBlind();

    const theme: PartialTheme = {
      background: { color: "transparent" },
      chartMargins: { top: 6, bottom: 6, left: 6, right: 6 },
      chartPaddings: { top: 0, bottom: 0, left: 0, right: 0 },
      colors: { vizColors },
      axes: {
        axisTitle: { fill: subdued, fontSize: 11, fontFamily },
        axisPanelTitle: { fill: subdued, fontSize: 11, fontFamily },
        tickLabel: { fill: subdued, fontSize: 11, fontFamily },
        axisLine: { stroke: axisLine },
        tickLine: { visible: false, size: 0, stroke: axisLine },
        gridLine: {
          horizontal: { visible: true, stroke: grid, strokeWidth: 1, opacity: isDark ? 0.45 : 0.7 },
          vertical: { visible: false, stroke: grid, strokeWidth: 1, opacity: 0 },
        },
      },
      lineSeriesStyle: {
        line: { strokeWidth: 2 },
        point: { visible: "never", radius: 2, strokeWidth: 2 },
      },
      areaSeriesStyle: {
        area: { opacity: 0.16 },
        line: { strokeWidth: 2 },
        point: { visible: "never", radius: 2, strokeWidth: 2 },
      },
      barSeriesStyle: {
        rectBorder: { visible: false, strokeWidth: 0 },
        rect: { opacity: 1 },
      },
      partition: {
        emptySizeRatio: 0,
        outerSizeRatio: 0.92,
        circlePadding: 3,
        sectorLineStroke: surface,
        sectorLineWidth: 1.2,
        fontFamily,
        linkLabel: { maxCount: 0, fontSize: 11, textColor: subdued },
      },
      crosshair: {
        line: { stroke: subdued, strokeWidth: 1, dash: [4, 4] },
        band: { fill: grid, visible: true },
      },
    };

    return {
      baseTheme: isDark ? DARK_THEME : LIGHT_THEME,
      theme,
      isDark,
      vizColors,
      tokens: { text, subdued, grid, axisLine, surface },
    };
  }, [euiTheme, colorMode]);
}

const SEVERITY_CHART_KEYS: Record<string, SeverityLevel | "high"> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
  unknown: "neutral",
  failures: "critical",
  failure: "critical",
};

export function useSeverityChartColors(): Record<SeverityLevel, string> {
  const { euiTheme } = useEuiTheme();
  const c = euiTheme.colors;
  return useMemo(
    () => ({
      critical: c.danger,
      high: "#E8730C",
      medium: c.warning,
      low: c.primary,
      info: c.primary,
      neutral: c.mediumShade,
    }),
    [c.danger, c.warning, c.primary, c.mediumShade]
  );
}

export function useSeriesColorResolver(): (key: string, index: number) => string {
  const { vizColors } = useEuiChartTheme();
  const severity = useSeverityChartColors();
  return useMemo(
    () => (key: string, index: number) => {
      const mapped = SEVERITY_CHART_KEYS[(key || "").toLowerCase()];
      if (mapped) return severity[mapped];
      return vizColors[index % vizColors.length];
    },
    [vizColors, severity]
  );
}
