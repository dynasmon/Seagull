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
    <div className="flex items-center gap-2">
      <Dot state={state} />
      <span className="text-[10px] font-mono text-muted-foreground whitespace-nowrap">
        {statusText} · {fmtLastSeen(lastSeenAt)}
      </span>
    </div>
  );
}
