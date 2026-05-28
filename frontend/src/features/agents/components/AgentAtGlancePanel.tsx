import { MetricCard } from "@/shared/components/MetricCard";
import { Panel } from "@/shared/components/Panel";
import { StatusPill } from "@/shared/components/StatusPill";
import type { MetricTone } from "@/shared/components/MetricCard";
import type { StatusVariant } from "@/shared/components/StatusPill";

function agentTone(tone: "default" | "good" | "warn"): MetricTone {
  if (tone === "good") return "success";
  if (tone === "warn") return "warning";
  return "default";
}

function statusVariant(online: boolean, disabled: boolean): StatusVariant {
  if (disabled) return "neutral";
  return online ? "active" : "warning";
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
  const statusLabel = topStats.online ? "Online" : disabled ? "Disabled" : "Offline";
  return (
    <Panel
      title="Selected agent summary"
      actions={
        <StatusPill variant={statusVariant(topStats.online, disabled)} withDot>
          {statusLabel}
        </StatusPill>
      }
      style={{ minHeight: 200 }}
    >
      <div className="grid min-w-0 grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <MetricCard
          size="sm"
          title="Status"
          value={topStats.status}
          tone={agentTone(topStats.online ? "good" : disabled ? "warn" : "default")}
        />
        <MetricCard size="sm" title="Last seen" value={topStats.lastSeen} />
        <MetricCard size="sm" title="Events / 5m" value={eventsRate} helper="Telemetry snapshot" />
        <MetricCard
          size="sm"
          title="Alerts / 60m"
          value={alerts60m}
          tone={agentTone(Number(alerts60m) > 0 ? "warn" : "default")}
        />
        <MetricCard size="sm" title="Last event age" value={lastEventAge} helper="Operational latency" />
      </div>
    </Panel>
  );
}
