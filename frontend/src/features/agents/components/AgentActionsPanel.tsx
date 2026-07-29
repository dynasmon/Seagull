import { useNavigate } from "react-router-dom";

import type { AgentDetail } from "@/features/agents/types";
import { Button } from "@/shared/components/Button";
import EmptyState from "@/shared/components/EmptyState";
import { Panel } from "@/shared/components/Panel";
import { StatusPill } from "@/shared/components/StatusPill";

function agentProfile(agent: AgentDetail | null): string {
  const raw = String(agent?.metadata?.profile || "").trim().toLowerCase();
  return raw === "sensor" || raw === "managed" ? raw : "managed";
}

export default function AgentActionsPanel({
  agent,
  isAdmin,
  toggleBusy,
  agentError,
  onOpenConfig,
  onToggleRevoked,
}: {
  agent: AgentDetail | null;
  isAdmin: boolean;
  toggleBusy: boolean;
  agentError: string | null;
  onOpenConfig: () => void;
  onToggleRevoked: () => void;
}) {
  const navigate = useNavigate();
  const profile = agentProfile(agent);
  const responseCapable = profile !== "sensor";
  return (
    <Panel
      title="Response actions"
      actions={
        agent?.is_revoked ? (
          <StatusPill variant="neutral" withDot>Disabled</StatusPill>
        ) : responseCapable ? (
          <StatusPill variant="active" withDot>Enabled</StatusPill>
        ) : (
          <StatusPill variant="neutral" withDot>Sensor only</StatusPill>
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
              <Button
                variant="subtle"
                size="md"
                onClick={() => navigate(`/response-center?agent_id=${encodeURIComponent(agent.agent_id)}&mode=dispatch`)}
                className="w-full"
                disabled={!responseCapable}
              >
                Queue response action
              </Button>
            )}

            {!responseCapable && (
              <div className="text-[11px] text-muted-foreground">
                This endpoint runs the sensor profile: it collects telemetry and cannot execute response actions.
              </div>
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
