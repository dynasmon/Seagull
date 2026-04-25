import { MetricCard } from "@/shared/components/MetricCard";
import { Panel } from "@/shared/components/Panel";
import type { MetricTone } from "@/shared/components/MetricCard";

function agentTone(tone: "default" | "good" | "warn"): MetricTone {
  if (tone === "good") return "success";
  if (tone === "warn") return "warning";
  return "default";
}

export default function AgentAtGlancePanel({
  topStats,
  eventsRate,
  alerts60m,
  lastEventAge,
  disabled,
}: {
  topStats: { status: string; online: boolean; lastSeen: string };
  eventsRate: string;
  alerts60m: string;
  lastEventAge: string;
  disabled: boolean;
}) {
  return (
    <Panel
      title="Selected agent summary"
      actions={<span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">{topStats.online ? "Online" : disabled ? "Disabled" : "Offline"}</span>}
      style={{ height: 220 }}
    >
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 min-w-0">
        <MetricCard title="Status" value={topStats.status} tone={agentTone(topStats.online ? "good" : disabled ? "warn" : "default")} />
        <MetricCard title="Last seen" value={topStats.lastSeen} />
        <MetricCard title="Events / 5m" value={eventsRate} helper="Telemetry snapshot" />
        <MetricCard title="Alerts / 60m" value={alerts60m} tone={agentTone(Number(alerts60m) > 0 ? "warn" : "default")} />
        <MetricCard title="Last event age" value={lastEventAge} helper="Operational latency" />
      </div>
    </Panel>
  );
}
