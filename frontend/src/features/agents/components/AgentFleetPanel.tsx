import type { AgentPublic } from "@/features/agents/types";
import EmptyState from "@/shared/components/EmptyState";
import { cx } from "@/shared/lib/cx";

import { Dot, Panel, inputClassName } from "./AgentsPageShared";

export default function AgentFleetPanel({
  agentsFiltered,
  agentsSorted,
  selectedAgentId,
  agentQuery,
  onAgentQueryChange,
  onSelectAgent,
  onOpenConfig,
  fmtLastSeen,
  isOnline,
  compact = true,
  showConfigButton = false,
  height,
}: {
  agentsFiltered: AgentPublic[];
  agentsSorted: AgentPublic[];
  selectedAgentId: string;
  agentQuery: string;
  onAgentQueryChange: (next: string) => void;
  onSelectAgent: (agentId: string) => void;
  onOpenConfig?: () => void;
  fmtLastSeen: (lastSeenAt?: string | null) => string;
  isOnline: (lastSeenAt?: string | null) => boolean;
  compact?: boolean;
  showConfigButton?: boolean;
  height: number;
}) {
  return (
    <Panel title="Fleet overview" right={`${agentsFiltered.length}/${agentsSorted.length}`} scrollY style={{ height }}>
      <div className="space-y-3">
        <input
          value={agentQuery}
          onChange={(e) => onAgentQueryChange(e.target.value)}
          placeholder="Search agents (name, id, tags)..."
          className={inputClassName(false)}
        />

        {showConfigButton && onOpenConfig ? (
          <button
            type="button"
            onClick={onOpenConfig}
            className={cx(
              "w-full border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
              "hover:bg-primary/5"
            )}
          >
            Configure selected agent
          </button>
        ) : null}

        <div className="space-y-2">
          {agentsFiltered.length === 0 ? (
            <EmptyState title="No matches" hint="Try a different search query." />
          ) : (
            agentsFiltered.map((a) => {
              const disabled = Boolean(a.is_revoked);
              const online = !disabled && isOnline(a.last_seen_at);
              const state = disabled ? "disabled" : online ? "online" : "offline";
              const active = a.agent_id === selectedAgentId;

              return (
                <button
                  key={a.agent_id}
                  type="button"
                  onClick={() => onSelectAgent(a.agent_id)}
                  className={cx(
                    "w-full text-left rounded-md border border-border/60 px-3",
                    compact ? "py-1.5" : "py-2.5",
                    active ? "bg-primary/10" : "bg-background/20",
                    "hover:bg-muted/10",
                    "focus:outline-none focus:ring-2 focus:ring-primary/30"
                  )}
                >
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex items-center gap-3 min-w-0">
                      <Dot state={state} />
                      <div className="min-w-0">
                        <div className="text-sm font-mono truncate">{a.display_name || a.agent_id}</div>
                        <div className="text-[10px] font-mono text-muted-foreground truncate">{a.agent_id}</div>
                      </div>
                    </div>
                    <div className="text-[10px] font-mono text-muted-foreground whitespace-nowrap">{fmtLastSeen(a.last_seen_at)}</div>
                  </div>
                  {a.tags && a.tags.length ? (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {a.tags.slice(0, 4).map((t) => (
                        <span
                          key={t}
                          className="rounded border border-border/60 bg-background/30 px-2 py-0.5 text-[10px] font-mono text-muted-foreground"
                        >
                          {t}
                        </span>
                      ))}
                      {a.tags.length > 4 ? (
                        <span className="rounded border border-border/60 bg-background/30 px-2 py-0.5 text-[10px] font-mono text-muted-foreground">
                          +{a.tags.length - 4}
                        </span>
                      ) : null}
                    </div>
                  ) : null}
                </button>
              );
            })
          )}
        </div>
      </div>
    </Panel>
  );
}
