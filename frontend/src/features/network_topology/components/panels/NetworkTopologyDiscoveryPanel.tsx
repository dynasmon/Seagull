import { Button } from "@/shared/components/Button";
import { Panel } from "@/shared/components/Panel";
import { SelectInput } from "@/shared/components/SelectInput";
import { StatusPill } from "@/shared/components/StatusPill";
import { TextInput } from "@/shared/components/TextInput";

type DiscoveryActionSummary = {
  id: number;
  status: string;
  requested_at: string;
  result?: Record<string, unknown> | null;
};

export type NetworkTopologyDiscoveryPanelProps = {
  isAdmin: boolean;
  agents: Array<{ agent_id: string; label: string }>;
  selectedAgentId: string;
  mode: "passive_only" | "active_enabled";
  allowedCidrs: string[];
  lastRunAt: string | null;
  discoveredHosts: string[];
  observedHosts: string[];
  lastError: string | null;
  warnings: string[];
  confirmationText: string;
  busy: boolean;
  latestAction: DiscoveryActionSummary | null;
  onSelectAgent: (agentId: string) => void;
  onConfirmationTextChange: (value: string) => void;
  onTrigger: () => void;
};

function formatTimestamp(value: string | null) {
  if (!value) return "Never";
  const dt = new Date(value);
  return Number.isNaN(dt.getTime()) ? value : dt.toLocaleString();
}

export function NetworkTopologyDiscoveryPanel({
  isAdmin,
  agents,
  selectedAgentId,
  mode,
  allowedCidrs,
  lastRunAt,
  discoveredHosts,
  observedHosts,
  lastError,
  warnings,
  confirmationText,
  busy,
  latestAction,
  onSelectAgent,
  onConfirmationTextChange,
  onTrigger,
}: NetworkTopologyDiscoveryPanelProps) {
  const activeEnabled = mode === "active_enabled";
  const readyToTrigger = isAdmin && activeEnabled && Boolean(selectedAgentId) && confirmationText.trim() === "DISCOVER";

  return (
    <Panel
      title="Discovery"
      subtitle="Passive visibility by default. Active discovery is explicit, bounded, and admin-controlled."
    >
      <div className="space-y-4 text-sm">
        <div className="grid gap-3 md:grid-cols-[minmax(0,1fr)_auto] md:items-end">
          <label className="block">
            <span className="mb-1 block text-[10px] font-semibold uppercase tracking-[0.08em] text-muted-foreground">
              Agent
            </span>
            <SelectInput value={selectedAgentId} onChange={(event) => onSelectAgent(event.target.value)}>
              <option value="">Select an agent</option>
              {agents.map((agent) => (
                <option key={agent.agent_id} value={agent.agent_id}>
                  {agent.label}
                </option>
              ))}
            </SelectInput>
          </label>
          <StatusPill variant={activeEnabled ? "warning" : "inactive"}>
            {activeEnabled ? "Active enabled" : "Passive only"}
          </StatusPill>
        </div>

        <div className="grid gap-3 md:grid-cols-3">
          <div className="rounded-md border border-border/70 bg-background/35 p-3">
            <div className="text-[10px] uppercase tracking-[0.08em] text-muted-foreground">Allowed CIDRs</div>
            <div className="mt-1 font-mono text-[12px]">
              {allowedCidrs.length ? allowedCidrs.join(", ") : "Auto: private local CIDRs only"}
            </div>
          </div>
          <div className="rounded-md border border-border/70 bg-background/35 p-3">
            <div className="text-[10px] uppercase tracking-[0.08em] text-muted-foreground">Last run</div>
            <div className="mt-1 text-[12px]">{formatTimestamp(lastRunAt)}</div>
          </div>
          <div className="rounded-md border border-border/70 bg-background/35 p-3">
            <div className="text-[10px] uppercase tracking-[0.08em] text-muted-foreground">Discovered hosts</div>
            <div className="mt-1 text-[12px]">{discoveredHosts.length}</div>
          </div>
        </div>

        <div className="grid gap-3 lg:grid-cols-2">
          <div className="rounded-md border border-border/70 bg-background/35 p-3">
            <div className="text-[10px] uppercase tracking-[0.08em] text-muted-foreground">Newly discovered</div>
            <div className="mt-2 min-h-5 font-mono text-[12px] text-muted-foreground">
              {discoveredHosts.length ? discoveredHosts.join(", ") : "None reported"}
            </div>
          </div>
          <div className="rounded-md border border-border/70 bg-background/35 p-3">
            <div className="text-[10px] uppercase tracking-[0.08em] text-muted-foreground">Observed neighbors</div>
            <div className="mt-2 min-h-5 font-mono text-[12px] text-muted-foreground">
              {observedHosts.length ? observedHosts.join(", ") : "None reported"}
            </div>
          </div>
        </div>

        {lastError ? (
          <div className="rounded-md border border-danger/40 bg-danger/10 p-3 text-[12px] text-danger">{lastError}</div>
        ) : null}

        {warnings.length ? (
          <div className="rounded-md border border-warning/40 bg-warning/10 p-3 text-[12px] text-warning">
            {warnings.join(" · ")}
          </div>
        ) : null}

        {latestAction ? (
          <div className="rounded-md border border-border/70 bg-background/35 p-3 text-[12px] text-muted-foreground">
            Latest manual request #{latestAction.id}: <span className="font-semibold text-foreground">{latestAction.status}</span>
            {" · "}
            requested {formatTimestamp(latestAction.requested_at)}
          </div>
        ) : null}

        {isAdmin ? (
          <div className="rounded-md border border-warning/35 bg-warning/5 p-4">
            <div className="text-[12px] font-semibold text-foreground">Manual active discovery</div>
            <p className="mt-1 text-[12px] text-muted-foreground">
              This asks the selected agent to perform a bounded host-discovery run only within its allowed scope. Type{" "}
              <span className="font-mono font-semibold text-foreground">DISCOVER</span> to make the action deliberate.
            </p>
            <div className="mt-3 flex flex-col gap-2 sm:flex-row">
              <TextInput
                value={confirmationText}
                onChange={(event) => onConfirmationTextChange(event.target.value)}
                placeholder="Type DISCOVER"
                disabled={!activeEnabled || busy}
              />
              <Button variant="danger" onClick={onTrigger} disabled={!readyToTrigger || busy}>
                {busy ? "Requesting..." : "Request discovery"}
              </Button>
            </div>
          </div>
        ) : (
          <div className="rounded-md border border-border/70 bg-background/35 p-3 text-[12px] text-muted-foreground">
            Active discovery can only be triggered by an administrator.
          </div>
        )}
      </div>
    </Panel>
  );
}
