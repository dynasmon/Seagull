import { Panel, StatTile } from "./AgentsPageShared";

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
    <Panel title="Selected agent summary" right={topStats.online ? "Online" : disabled ? "Disabled" : "Offline"} style={{ height: 220 }}>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 min-w-0">
        <StatTile label="Status" value={topStats.status} tone={topStats.online ? "good" : disabled ? "warn" : "default"} />
        <StatTile label="Last seen" value={topStats.lastSeen} />
        <StatTile label="Events / 5m" value={eventsRate} hint="Telemetry snapshot" />
        <StatTile label="Alerts / 60m" value={alerts60m} tone={Number(alerts60m) > 0 ? "warn" : "default"} />
        <StatTile label="Last event age" value={lastEventAge} hint="Operational latency" />
      </div>
    </Panel>
  );
}
