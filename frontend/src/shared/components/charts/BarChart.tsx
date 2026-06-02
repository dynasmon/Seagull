import { memo } from "react";
import {
  Chart,
  Settings,
  Axis,
  BarSeries,
  Position,
  ScaleType,
} from "@elastic/charts";
import type { XYChartElementEvent } from "@elastic/charts";

import { ChartFrame } from "./ChartFrame";
import { useEuiChartTheme } from "./chartTheme";

export interface BarChartProps {
  data: Array<Record<string, unknown>>;
  xKey?: string;
  yKey?: string;
  height?: number;
  horizontal?: boolean;
  color?: string;
  colorFor?: (category: string, index: number) => string;
  name?: string;
  valueFormatter?: (value: number) => string;
  categoryFormatter?: (category: string) => string;
  onBarClick?: (category: string) => void;
  allowHorizontalScroll?: boolean;
  minWidth?: number;
  emptyLabel?: string;
}

export const BarChart = memo(function BarChart({
  data,
  xKey = "x",
  yKey = "y",
  height = 240,
  horizontal = false,
  color,
  colorFor,
  name = "value",
  valueFormatter,
  categoryFormatter,
  onBarClick,
  allowHorizontalScroll = false,
  minWidth = 0,
  emptyLabel,
}: BarChartProps) {
  const { baseTheme, theme, vizColors } = useEuiChartTheme();

  const isEmpty = !Array.isArray(data) || data.length === 0;
  const categoryPosition = horizontal ? Position.Left : Position.Bottom;
  const valuePosition = horizontal ? Position.Bottom : Position.Left;

  const splitByCategory = typeof colorFor === "function";
  const colorAccessor = splitByCategory
    ? (seriesId: { seriesKeys: Array<string | number> }) => {
        const raw = seriesId.seriesKeys[0];
        const idx = data.findIndex((d) => String(d[xKey]) === String(raw));
        return colorFor!(String(raw), idx < 0 ? 0 : idx);
      }
    : color ?? vizColors[0];

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
          rotation={horizontal ? 90 : 0}
          showLegend={false}
          onElementClick={
            onBarClick
              ? (elements) => {
                  const event = elements[0] as XYChartElementEvent | undefined;
                  if (!event) return;
                  const [geometry] = event;
                  onBarClick(String(geometry.x));
                }
              : undefined
          }
        />
        <Axis
          id="category"
          position={categoryPosition}
          tickFormat={categoryFormatter ? (v) => categoryFormatter(String(v)) : undefined}
        />
        <Axis
          id="value"
          position={valuePosition}
          ticks={4}
          tickFormat={valueFormatter ? (v) => valueFormatter(Number(v)) : undefined}
        />
        <BarSeries
          id={name}
          name={name}
          xScaleType={ScaleType.Ordinal}
          yScaleType={ScaleType.Linear}
          xAccessor={xKey}
          yAccessors={[yKey]}
          splitSeriesAccessors={splitByCategory ? [xKey] : undefined}
          color={colorAccessor}
          data={data}
        />
      </Chart>
    </ChartFrame>
  );
});
