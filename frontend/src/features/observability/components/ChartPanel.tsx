import { useMemo } from "react";

import { TimeSeriesChart, useSeriesColorResolver } from "@/shared/components/charts";
import { Panel } from "@/shared/components/Panel";

import { axisFormatterFor, unitBadge } from "../lib/format";
import type { ChartPanelSpec } from "../lib/panels";
import { buildChartData } from "../lib/transform";
import type { EnvelopeMap } from "../types";

const PANEL_HEIGHT = 248;

export default function ChartPanel({
  panel,
  envelopes,
  available,
}: {
  panel: ChartPanelSpec;
  envelopes: EnvelopeMap;
  available: boolean;
}) {
  const resolve = useSeriesColorResolver();
  const data = useMemo(() => buildChartData(panel, envelopes), [panel, envelopes]);
  const valueFormatter = useMemo(() => axisFormatterFor(panel.unit), [panel.unit]);

  const series = useMemo(
    () =>
      data.isEmpty
        ? []
        : data.seriesKeys.map((id, index) => ({
            id,
            name: data.seriesNames[id] ?? id,
            color: resolve(data.seriesNames[id] ?? id, index),
          })),
    [data.isEmpty, data.seriesKeys, data.seriesNames, resolve]
  );
  const colorFor = useMemo(
    () => (seriesId: string, index: number) => resolve(data.seriesNames[seriesId] ?? seriesId, index),
    [data.seriesNames, resolve]
  );

  const showLegend = series.length > 1;
  const chartHeight = showLegend ? 166 : 192;

  return (
    <Panel
      title={panel.title}
      actions={<span className="ui-eyebrow text-muted-foreground/70">{unitBadge(panel.unit)}</span>}
      style={{ height: PANEL_HEIGHT }}
      bodyClassName="flex flex-col gap-2"
    >
      {showLegend ? (
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          {series.map((item) => (
            <span key={item.id} className="inline-flex items-center gap-1.5 text-[11px] text-muted-foreground">
              <span className="h-2 w-2 rounded-[2px]" style={{ backgroundColor: item.color }} aria-hidden="true" />
              {item.name}
            </span>
          ))}
        </div>
      ) : null}
      <div className="min-h-0 flex-1">
        <TimeSeriesChart
          data={data.isEmpty ? [] : data.rows}
          seriesKeys={data.isEmpty ? [] : data.seriesKeys}
          seriesNames={data.seriesNames}
          xKey="t"
          height={chartHeight}
          variant={panel.variant ?? "line"}
          stacked={panel.stacked}
          legend={false}
          colorFor={colorFor}
          valueFormatter={valueFormatter}
          emptyLabel={available ? "No data in this window" : "Metrics unavailable"}
        />
      </div>
    </Panel>
  );
}
