import { MetricCard } from "@/shared/components/MetricCard";
import { Panel } from "@/shared/components/Panel";
import { StatusPill } from "@/shared/components/StatusPill";
import IpAddressPill from "@/shared/components/IpAddressPill";
import type { MetricTone } from "@/shared/components/MetricCard";
import type { StatusVariant } from "@/shared/components/StatusPill";

import type { AgentPublic } from "../types";
import { agentAddress, agentDisplayName, agentHostname, agentPlatform, agentProfile } from "../lib/identity";
import { fmtLastSeen } from "../lib/agentUtils";

function agentTone(tone: "default" | "good" | "warn"): MetricTone {
  if (tone === "good") return "success";
  if (tone === "warn") return "warning";
  return "default";
}

function statusVariant(online: boolean, disabled: boolean): StatusVariant {
  if (disabled) return "neutral";
  return online ? "active" : "warning";
}

function IdentityFact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{label}</div>
      <div className="mt-0.5 truncate text-[12px] text-foreground">{children}</div>
    </div>
  );
}

function AgentIdentityStrip({ agent }: { agent: AgentPublic }) {
  const address = agentAddress(agent);
  const hostname = agentHostname(agent);
  const platform = agentPlatform(agent);
  const profile = agentProfile(agent);

  return (
    <div className="mb-3 grid min-w-0 grid-cols-2 gap-3 rounded-md border border-border/70 bg-surface-2/50 px-3 py-2.5 sm:grid-cols-4">
      <IdentityFact label="Agent">
        <span className="font-mono text-[11.5px]">{agent.agent_id}</span>
      </IdentityFact>
      <IdentityFact label="Host">
        <span className="font-mono text-[11.5px]">{hostname || "-"}</span>
      </IdentityFact>
      <IdentityFact label="Connects from">
        {address ? (
          <IpAddressPill ip={address} compact />
        ) : (
          <span className="text-muted-foreground">Not seen yet</span>
        )}
      </IdentityFact>
      <IdentityFact label="Platform">
        <span className="font-mono text-[11.5px]">{[platform, profile].filter(Boolean).join(" · ") || "-"}</span>
      </IdentityFact>
    </div>
  );
}

export default function AgentAtGlancePanel({
  agent,
  topStats,
  eventsRate,
  alerts60m,
  lastEventAge,
  disabled,
}: {
  agent: AgentPublic | null;
  topStats: { status: string; online: boolean; lastSeen: string };
  eventsRate: string;
  alerts60m: string;
  lastEventAge: string;
  disabled: boolean;
}) {
  const statusLabel = topStats.online ? "Online" : disabled ? "Disabled" : "Offline";
  return (
    <Panel
      title={agent ? agentDisplayName(agent) : "Selected agent summary"}
      actions={
        <StatusPill variant={statusVariant(topStats.online, disabled)} withDot>
          {statusLabel}
        </StatusPill>
      }
      style={{ minHeight: 200 }}
    >
      {agent ? <AgentIdentityStrip agent={agent} /> : null}

      <div className="grid min-w-0 grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <MetricCard
          size="sm"
          title="Status"
          value={topStats.status}
          tone={agentTone(topStats.online ? "good" : disabled ? "warn" : "default")}
        />
        <MetricCard
          size="sm"
          title="Last seen"
          value={agent ? fmtLastSeen(agent.last_seen_at) : "-"}
          helper={topStats.lastSeen}
        />
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
