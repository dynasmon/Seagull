import { memo, useMemo } from "react";
import {
  Chart,
  Settings,
  Axis,
  LineSeries,
  AreaSeries,
  Position,
  ScaleType,
  CurveType,
} from "@elastic/charts";

import { ChartFrame } from "./ChartFrame";
import { useEuiChartTheme, useSeriesColorResolver } from "./chartTheme";
import { maskTrailingNoDataBuckets } from "./maskTrailingNoData";

export interface TimeSeriesChartProps {
  data: Array<Record<string, unknown>>;
  seriesKeys: string[];
  xKey?: string;
  height?: number;
  minWidth?: number;
  allowHorizontalScroll?: boolean;
  variant?: "line" | "area";
  stacked?: boolean;
  curve?: "linear" | "monotone";
  legend?: boolean;
  legendPosition?: "bottom" | "right";
  seriesNames?: Record<string, string>;
  colorFor?: (key: string, index: number) => string | undefined;
  valueFormatter?: (value: number) => string;
  emptyLabel?: string;
}

export const TimeSeriesChart = memo(function TimeSeriesChart({
  data,
  seriesKeys,
  xKey = "t",
  height = 240,
  minWidth = 720,
  allowHorizontalScroll = false,
  variant = "line",
  stacked = false,
  curve = "linear",
  legend = true,
  legendPosition = "bottom",
  seriesNames,
  colorFor,
  valueFormatter,
  emptyLabel,
}: TimeSeriesChartProps) {
  const { baseTheme, theme } = useEuiChartTheme();
  const defaultColor = useSeriesColorResolver();

  const masked = useMemo(
    () => maskTrailingNoDataBuckets(data, seriesKeys),
    [data, seriesKeys]
  );

  const isEmpty = !Array.isArray(data) || data.length === 0 || seriesKeys.length === 0;
  const SeriesComponent = variant === "area" ? AreaSeries : LineSeries;
  const curveType = curve === "monotone" ? CurveType.CURVE_MONOTONE_X : CurveType.LINEAR;
  const showLegend = legend && seriesKeys.length > 1;

  return (
    <ChartFrame
      height={height}
      minWidth={minWidth}
      allowHorizontalScroll={allowHorizontalScroll}
      isEmpty={isEmpty}
      emptyLabel={emptyLabel}
    >
      <Chart size={{ height }}>
        <Settings
          baseTheme={baseTheme}
          theme={theme}
          showLegend={showLegend}
          legendPosition={legendPosition === "right" ? Position.Right : Position.Bottom}
          legendSize={legendPosition === "right" ? 130 : undefined}
        />
        <Axis id="x" position={Position.Bottom} />
        <Axis
          id="y"
          position={Position.Left}
          ticks={4}
          tickFormat={valueFormatter ? (v) => valueFormatter(Number(v)) : undefined}
        />
        {seriesKeys.map((key, index) => {
          const resolved = colorFor?.(key, index) ?? defaultColor(key, index);
          return (
            <SeriesComponent
              key={key}
              id={key}
              name={seriesNames?.[key] ?? key}
              xScaleType={ScaleType.Ordinal}
              yScaleType={ScaleType.Linear}
              xAccessor={xKey}
              yAccessors={[key]}
              stackAccessors={stacked ? [xKey] : undefined}
              curve={curveType}
              color={resolved}
              data={masked}
            />
          );
        })}
      </Chart>
    </ChartFrame>
  );
});
