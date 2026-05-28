import { Dot } from "./AgentsPageShared";
import { isOnline, fmtLastSeen } from "../lib/agentUtils";

interface AgentStatusBadgeProps {
  lastSeenAt?: string | null;
  isRevoked: boolean;
}

export default function AgentStatusBadge({ lastSeenAt, isRevoked }: AgentStatusBadgeProps) {
  const online = !isRevoked && isOnline(lastSeenAt);
  const state = isRevoked ? "disabled" : online ? "online" : "offline";
  const statusText = isRevoked ? "Disabled" : online ? "Online" : "Offline";

  return (
    <div className="inline-flex items-center gap-2 rounded-md border border-border bg-surface-2 px-2 py-1">
      <Dot state={state} />
      <span className="whitespace-nowrap text-[10.5px] font-semibold uppercase tracking-[0.08em] text-foreground/85">
        {statusText} · <span className="font-mono text-muted-foreground">{fmtLastSeen(lastSeenAt)}</span>
      </span>
    </div>
  );
}
