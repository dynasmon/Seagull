import Loading from "@/shared/components/Loading";
import { Panel } from "@/shared/components/Panel";

import { SimpleTimeSeries } from "@/features/overview/components/Charts";

type ChartData = { series: string[]; data: Array<Record<string, any>> };

function ChartPanel({ title, chart, height }: { title: string; chart: ChartData | null; height: number }) {
  return (
    <Panel title={title} style={{ height }}>
      {!chart ? (
        <Loading label="Loading chart..." />
      ) : (
        <div className="h-full w-full min-w-0 overflow-hidden">
          <SimpleTimeSeries
            data={chart.data}
            seriesKeys={chart.series}
            height={Math.max(180, height - 120)}
            allowHorizontalScroll={false}
          />
        </div>
      )}
    </Panel>
  );
}

export default function AgentTelemetrySnapshot({
  height,
  charts,
}: {
  height: number;
  charts: {
    traffic: null | ChartData;
    ssh: null | ChartData;
    ddos: null | ChartData;
    sev: null | ChartData;
  };
}) {
  return (
    <div className="grid min-w-0 gap-3 lg:grid-cols-2">
      <ChartPanel title="Telemetry snapshot: Traffic" chart={charts.traffic} height={height} />
      <ChartPanel title="Heartbeat: SSH failures" chart={charts.ssh} height={height} />
      <ChartPanel title="Security posture: DDoS" chart={charts.ddos} height={height} />
      <ChartPanel title="Security posture: Alert severity" chart={charts.sev} height={height} />
    </div>
  );
}
