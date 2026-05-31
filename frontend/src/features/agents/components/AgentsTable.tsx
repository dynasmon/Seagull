import { EuiPanel } from "@elastic/eui";

import type { AgentPublic } from "@/features/agents/types";
import EmptyState from "@/shared/components/EmptyState";

import { Dot } from "./AgentsPageShared";
import { isOnline, fmtLastSeen } from "../lib/agentUtils";

interface AgentsTableProps {
  agentsFiltered: AgentPublic[];
  selectedAgentId: string;
  compact: boolean;
  onSelectAgent: (id: string) => void;
}

export default function AgentsTable({ agentsFiltered, selectedAgentId, compact, onSelectAgent }: AgentsTableProps) {
  if (agentsFiltered.length === 0) {
    return <EmptyState title="No matches" hint="Try a different search query." />;
  }

  return (
    <div className="space-y-1.5">
      {agentsFiltered.map((a) => {
        const disabled = Boolean(a.is_revoked);
        const online = !disabled && isOnline(a.last_seen_at);
        const state = disabled ? "disabled" : online ? "online" : "offline";
        const active = a.agent_id === selectedAgentId;

        return (
          <EuiPanel
            key={a.agent_id}
            onClick={() => onSelectAgent(a.agent_id)}
            hasBorder
            hasShadow={false}
            paddingSize={compact ? "s" : "m"}
            borderRadius="m"
            color={active ? "primary" : "plain"}
            className="w-full text-left"
            aria-pressed={active}
          >
            <div className="flex items-center justify-between gap-3">
              <div className="flex min-w-0 items-center gap-2.5">
                <Dot state={state} />
                <div className="min-w-0">
                  <div className="truncate text-[12.5px] font-semibold text-foreground">{a.display_name || a.agent_id}</div>
                  <div className="truncate font-mono text-[10.5px] text-muted-foreground">{a.agent_id}</div>
                </div>
              </div>
              <div className="whitespace-nowrap text-[10.5px] uppercase tracking-[0.06em] text-muted-foreground">
                {fmtLastSeen(a.last_seen_at)}
              </div>
            </div>
            {a.tags && a.tags.length ? (
              <div className="mt-2 flex flex-wrap gap-1">
                {a.tags.slice(0, 4).map((t) => (
                  <span
                    key={t}
                    className="rounded border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground"
                  >
                    {t}
                  </span>
                ))}
                {a.tags.length > 4 ? (
                  <span className="rounded border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
                    +{a.tags.length - 4}
                  </span>
                ) : null}
              </div>
            ) : null}
          </EuiPanel>
        );
      })}
    </div>
  );
}
