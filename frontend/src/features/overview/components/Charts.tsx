import { memo } from "react";

import { TimeSeriesChart } from "@/shared/components/charts";

export const SimpleTimeSeries = memo(function SimpleTimeSeries({
  data,
  seriesKeys,
  height = 220,
  minWidth = 720,
  allowHorizontalScroll = false,
}: {
  data: Array<Record<string, any>>;
  seriesKeys: string[];
  height?: number;
  minWidth?: number;
  allowHorizontalScroll?: boolean;
}) {
  return (
    <TimeSeriesChart
      data={data}
      seriesKeys={seriesKeys}
      height={height}
      minWidth={minWidth}
      allowHorizontalScroll={allowHorizontalScroll}
    />
  );
});
