import Loading from "@/shared/components/Loading";
import { Panel } from "@/shared/components/Panel";

import { SimpleTimeSeries } from "@/features/overview/components/Charts";

export default function AgentTelemetrySnapshot({
  height,
  charts,
}: {
  height: number;
  charts: {
    traffic: null | { series: string[]; data: Array<Record<string, any>> };
    ssh: null | { series: string[]; data: Array<Record<string, any>> };
    ddos: null | { series: string[]; data: Array<Record<string, any>> };
    sev: null | { series: string[]; data: Array<Record<string, any>> };
  };
}) {
  return (
    <div className="grid gap-6 lg:grid-cols-2 min-w-0">
      <Panel title="Telemetry snapshot: Traffic" style={{ height }}>
        {!charts.traffic ? (
          <Loading label="Loading chart..." />
        ) : (
          <div className="h-full w-full min-w-0 overflow-hidden">
            <SimpleTimeSeries data={charts.traffic.data} seriesKeys={charts.traffic.series} height={Math.max(180, height - 120)} allowHorizontalScroll={false} />
          </div>
        )}
      </Panel>

      <Panel title="Heartbeat: SSH failures" style={{ height }}>
        {!charts.ssh ? (
          <Loading label="Loading chart..." />
        ) : (
          <div className="h-full w-full min-w-0 overflow-hidden">
            <SimpleTimeSeries data={charts.ssh.data} seriesKeys={charts.ssh.series} height={Math.max(180, height - 120)} allowHorizontalScroll={false} />
          </div>
        )}
      </Panel>

      <Panel title="Security posture: DDoS" style={{ height }}>
        {!charts.ddos ? (
          <Loading label="Loading chart..." />
        ) : (
          <div className="h-full w-full min-w-0 overflow-hidden">
            <SimpleTimeSeries data={charts.ddos.data} seriesKeys={charts.ddos.series} height={Math.max(180, height - 120)} allowHorizontalScroll={false} />
          </div>
        )}
      </Panel>

      <Panel title="Security posture: Alert severity" style={{ height }}>
        {!charts.sev ? (
          <Loading label="Loading chart..." />
        ) : (
          <div className="h-full w-full min-w-0 overflow-hidden">
            <SimpleTimeSeries data={charts.sev.data} seriesKeys={charts.sev.series} height={Math.max(180, height - 120)} allowHorizontalScroll={false} />
          </div>
        )}
      </Panel>
    </div>
  );
}
