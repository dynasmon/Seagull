import { memo } from "react";
import { Chart, Settings, Partition, PartitionLayout, Position } from "@elastic/charts";

import { ChartFrame } from "./ChartFrame";
import { useEuiChartTheme } from "./chartTheme";

export interface DonutDatum {
  label: string;
  value: number;
}

export interface DonutChartProps {
  data: DonutDatum[];
  height?: number;
  donut?: boolean;
  legend?: boolean;
  legendPosition?: "right" | "bottom";
  colorFor?: (label: string, index: number) => string;
  valueFormatter?: (value: number) => string;
  emptyLabel?: string;
}

export const DonutChart = memo(function DonutChart({
  data,
  height = 240,
  donut = true,
  legend = true,
  legendPosition = "right",
  colorFor,
  valueFormatter,
  emptyLabel,
}: DonutChartProps) {
  const { baseTheme, theme, vizColors } = useEuiChartTheme();

  const total = Array.isArray(data) ? data.reduce((sum, d) => sum + (Number(d.value) || 0), 0) : 0;
  const isEmpty = !Array.isArray(data) || data.length === 0 || total <= 0;

  const partitionTheme = {
    ...theme,
    partition: { ...theme.partition, emptySizeRatio: donut ? 0.5 : 0 },
  };

  return (
    <ChartFrame height={height} isEmpty={isEmpty} emptyLabel={emptyLabel}>
      <Chart size={{ height }}>
        <Settings
          baseTheme={baseTheme}
          theme={partitionTheme}
          showLegend={legend}
          legendPosition={legendPosition === "bottom" ? Position.Bottom : Position.Right}
          legendSize={legendPosition === "right" ? 140 : undefined}
          legendMaxDepth={1}
        />
        <Partition
          id="partition"
          data={data}
          layout={PartitionLayout.sunburst}
          valueAccessor={(d: DonutDatum) => Number(d.value) || 0}
          valueFormatter={(v: number) => (valueFormatter ? valueFormatter(v) : String(v))}
          layers={[
            {
              groupByRollup: (d: DonutDatum) => d.label,
              nodeLabel: (key) => String(key),
              shape: {
                fillColor: (key, sortIndex) =>
                  colorFor
                    ? colorFor(String(key), sortIndex)
                    : vizColors[sortIndex % vizColors.length],
              },
            },
          ]}
        />
      </Chart>
    </ChartFrame>
  );
});
