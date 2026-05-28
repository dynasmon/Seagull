import type { AgentDetail } from "@/features/agents/types";
import { Button } from "@/shared/components/Button";
import EmptyState from "@/shared/components/EmptyState";
import { Panel } from "@/shared/components/Panel";
import { StatusPill } from "@/shared/components/StatusPill";

export default function AgentActionsPanel({
  agent,
  isAdmin,
  toggleBusy,
  agentError,
  onOpenConfig,
  onOpenResponseAction,
  onToggleRevoked,
}: {
  agent: AgentDetail | null;
  isAdmin: boolean;
  toggleBusy: boolean;
  agentError: string | null;
  onOpenConfig: () => void;
  onOpenResponseAction: () => void;
  onToggleRevoked: () => void;
}) {
  return (
    <Panel
      title="Response actions"
      actions={
        agent?.is_revoked ? (
          <StatusPill variant="neutral" withDot>Disabled</StatusPill>
        ) : (
          <StatusPill variant="active" withDot>Enabled</StatusPill>
        )
      }
      style={{ minHeight: 220 }}
    >
      {!agent ? (
        <EmptyState title="Agent not loaded" hint="Try refresh or check API connectivity." />
      ) : (
        <div className="flex flex-col gap-3">
          <div className="space-y-1">
            <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Selected</div>
            <div className="truncate text-[13px] font-semibold text-foreground">{agent.display_name || agent.agent_id}</div>
            <div className="truncate font-mono text-[10.5px] text-muted-foreground">{agent.agent_id}</div>
          </div>

          <div className="flex flex-col gap-2">
            <Button variant="secondary" size="md" onClick={onOpenConfig} className="w-full">
              Open configuration
            </Button>

            {isAdmin && (
              <Button variant="subtle" size="md" onClick={onOpenResponseAction} className="w-full">
                Queue response action
              </Button>
            )}

            <Button
              variant={agent.is_revoked ? "success" : "danger"}
              size="md"
              onClick={onToggleRevoked}
              disabled={toggleBusy}
              className="w-full"
            >
              {toggleBusy ? "Working…" : agent.is_revoked ? "Enable agent" : "Disable agent"}
            </Button>
          </div>

          {agentError && <div className="text-[11px] text-danger">{agentError}</div>}
        </div>
      )}
    </Panel>
  );
}
