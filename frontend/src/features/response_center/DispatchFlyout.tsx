import { useEffect, useMemo, useState } from "react";
import { EuiButtonGroup, EuiComboBox, EuiSwitch, type EuiComboBoxOptionOption } from "@elastic/eui";

import { isOnline } from "@/features/agents/lib/agentUtils";
import type { AgentPublic } from "@/features/agents/types";
import { Badge } from "@/shared/components/Badge";
import { Button } from "@/shared/components/Button";
import Drawer from "@/shared/components/Drawer";
import { InlineAlert } from "@/shared/components/InlineAlert";
import { SelectInput } from "@/shared/components/SelectInput";
import { StatusPill } from "@/shared/components/StatusPill";
import { TextArea } from "@/shared/components/TextArea";
import { TextInput } from "@/shared/components/TextInput";
import { getErrorMessage } from "@/shared/lib/errors";

import ActionCatalogPanel from "./ActionCatalogPanel";
import { createResponseAction, createResponseActionBatch } from "./api";
import DispatchModal from "./DispatchModal";
import { categoryLabel, riskVariant } from "./lib";
import { type ActionTypeOut, type BatchDispatchOut } from "./types";

type TargetMode = "single" | "multi";

interface DispatchFlyoutProps {
  open: boolean;
  onClose: () => void;
  catalog: ActionTypeOut[];
  agents: AgentPublic[];
  selectedActionKey: string | null;
  setSelectedActionKey: (key: string) => void;
  defaultAgentId: string;
  prefillPayload?: Record<string, any> | null;
  onDispatched: () => void;
  onOpenAction?: (actionId: number) => void;
}

function toIso(localValue: string): string {
  if (!localValue) return "";
  const date = new Date(localValue);
  return Number.isNaN(date.getTime()) ? "" : date.toISOString();
}

function offsetLocal(minutes: number): string {
  const date = new Date(Date.now() + minutes * 60_000);
  const tzAdjusted = new Date(date.getTime() - date.getTimezoneOffset() * 60_000);
  return tzAdjusted.toISOString().slice(0, 16);
}

function agentLabel(agent: AgentPublic): string {
  return (agent.display_name || agent.agent_id) + " (" + agent.agent_id + ")";
}

export default function DispatchFlyout({
  open,
  onClose,
  catalog,
  agents,
  selectedActionKey,
  setSelectedActionKey,
  defaultAgentId,
  prefillPayload = null,
  onDispatched,
  onOpenAction,
}: DispatchFlyoutProps) {
  const [targetMode, setTargetMode] = useState<TargetMode>("single");
  const [agentId, setAgentId] = useState(defaultAgentId);
  const [agentIds, setAgentIds] = useState<string[]>([]);
  const [onlineOnly, setOnlineOnly] = useState(false);
  const [payloadText, setPayloadText] = useState("{}");
  const [expiresAt, setExpiresAt] = useState("");
  const [preparedPayload, setPreparedPayload] = useState<Record<string, any>>({});
  const [modalOpen, setModalOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [batchResult, setBatchResult] = useState<BatchDispatchOut | null>(null);

  const actionType = selectedActionKey || catalog[0]?.key || "";
  const definition = useMemo(() => catalog.find((d) => d.key === actionType) || null, [catalog, actionType]);

  useEffect(() => {
    const template = definition?.payload_template ?? {};
    setPayloadText(prefillPayload ? JSON.stringify(prefillPayload, null, 2) : JSON.stringify(template, null, 2));
    setError(null);
    setSuccess(null);
    setBatchResult(null);
  }, [actionType, prefillPayload, definition]);

  useEffect(() => {
    if (defaultAgentId) setAgentId(defaultAgentId);
  }, [defaultAgentId]);

  const sortedAgents = useMemo(() => {
    const rows = onlineOnly ? agents.filter((a) => isOnline(a.last_seen_at)) : agents;
    return [...rows].sort((a, b) => {
      const aOnline = isOnline(a.last_seen_at) ? 0 : 1;
      const bOnline = isOnline(b.last_seen_at) ? 0 : 1;
      if (aOnline !== bOnline) return aOnline - bOnline;
      return a.agent_id.localeCompare(b.agent_id);
    });
  }, [agents, onlineOnly]);

  const comboOptions = useMemo<Array<EuiComboBoxOptionOption<string>>>(
    () =>
      sortedAgents.map((agent) => ({
        label: agentLabel(agent),
        value: agent.agent_id,
        append: isOnline(agent.last_seen_at) ? undefined : (
          <span className="text-[10px] uppercase text-muted-foreground">offline</span>
        ),
      })),
    [sortedAgents],
  );

  const selectedComboOptions = useMemo<Array<EuiComboBoxOptionOption<string>>>(
    () =>
      agentIds.map((id) => {
        const agent = agents.find((a) => a.agent_id === id);
        return { label: agent ? agentLabel(agent) : id, value: id };
      }),
    [agentIds, agents],
  );

  function switchTargetMode(next: TargetMode) {
    setTargetMode(next);
    setError(null);
    setSuccess(null);
    setBatchResult(null);
    if (next === "multi" && agentIds.length === 0 && agentId) {
      setAgentIds([agentId]);
    }
  }

  const targetAgentIds = targetMode === "multi" ? agentIds : agentId ? [agentId] : [];

  function parsePayload(): Record<string, any> | null {
    const trimmed = payloadText.trim();
    if (!trimmed) return {};
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        setError("Payload must be a JSON object.");
        return null;
      }
      return parsed;
    } catch {
      setError("Payload is not valid JSON.");
      return null;
    }
  }

  async function submit(payload: Record<string, any>, justification: string) {
    setBusy(true);
    setError(null);
    try {
      if (targetMode === "multi") {
        const out = await createResponseActionBatch({
          action_type: actionType,
          agent_ids: agentIds,
          payload,
          expires_at: toIso(expiresAt) || undefined,
          justification: justification || undefined,
        });
        setBatchResult(out);
        setSuccess(`Batch ${out.batch_id}: queued ${out.queued.length} of ${out.total}`);
      } else {
        const created = await createResponseAction({
          action_type: actionType,
          agent_id: agentId,
          payload,
          expires_at: toIso(expiresAt) || undefined,
          justification: justification || undefined,
        });
        setBatchResult(null);
        setSuccess(`Queued #${created.id} (${created.action_type}) on ${created.agent_id}`);
      }
      setModalOpen(false);
      onDispatched();
    } catch (caught) {
      setError(getErrorMessage(caught, "Failed to dispatch action"));
    } finally {
      setBusy(false);
    }
  }

  function handleDispatch() {
    setError(null);
    setSuccess(null);
    setBatchResult(null);
    if (targetAgentIds.length === 0) {
      setError(targetMode === "multi" ? "Select at least one target agent." : "Select a target agent.");
      return;
    }
    if (!actionType) {
      setError("Select an action type.");
      return;
    }
    const payload = parsePayload();
    if (payload === null) return;
    setPreparedPayload(payload);
    if (definition?.requires_confirmation) {
      setModalOpen(true);
    } else {
      void submit(payload, "");
    }
  }

  return (
    <>
      <Drawer
        open={open}
        onClose={onClose}
        title="Dispatch response action"
        description="Select a capability, target one or more agents, and queue an audited execution."
        headerLabel="Dispatch"
        widthClassName="w-[920px]"
        footer={
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="text-[11px] text-muted-foreground">
              {definition ? `${categoryLabel(definition.category)} · ~${definition.estimated_duration_seconds}s` : "No action selected"}
            </div>
            <div className="flex items-center gap-2">
              <Button variant="secondary" size="sm" onClick={onClose} disabled={busy}>
                Close
              </Button>
              <Button
                variant="primary"
                size="sm"
                onClick={handleDispatch}
                disabled={busy || !actionType || targetAgentIds.length === 0}
              >
                {busy
                  ? "Dispatching…"
                  : definition?.requires_confirmation
                    ? "Review & dispatch"
                    : targetMode === "multi"
                      ? `Dispatch to ${agentIds.length || 0} agent${agentIds.length === 1 ? "" : "s"}`
                      : "Dispatch"}
              </Button>
            </div>
          </div>
        }
      >
        <div className="grid gap-4 lg:grid-cols-[320px_minmax(0,1fr)]">
          <ActionCatalogPanel
            catalog={catalog}
            loading={false}
            error={null}
            selectedKey={selectedActionKey}
            onSelect={setSelectedActionKey}
          />

          <div className="space-y-4">
            {definition ? (
              <div className="rounded-md border border-border/60 bg-background/30 p-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="text-[13px] font-semibold text-foreground">{definition.label}</div>
                  <Badge variant={riskVariant(definition.risk_level)}>{definition.risk_level}</Badge>
                </div>
                <div className="mt-1 text-[12px] text-muted-foreground">{definition.description}</div>
                <div className="mt-2 flex flex-wrap items-center gap-3 text-[10.5px] uppercase tracking-[0.08em] text-muted-foreground">
                  <span>{categoryLabel(definition.category)}</span>
                  <span>{definition.reversible ? "Reversible" : "Not reversible"}</span>
                  <span>{definition.requires_confirmation ? "Confirmation required" : "No confirmation"}</span>
                  {definition.undo_action ? <span>Undo · {definition.undo_action}</span> : null}
                </div>
              </div>
            ) : null}

            <div className="space-y-2">
              <div className="flex items-center justify-between gap-2">
                <div className="text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
                  Target {targetMode === "multi" ? "agents" : "agent"}
                </div>
                <EuiButtonGroup
                  legend="Target mode"
                  type="single"
                  buttonSize="compressed"
                  options={[
                    { id: "target-single", label: "Single agent" },
                    { id: "target-multi", label: "Multiple agents" },
                  ]}
                  idSelected={targetMode === "multi" ? "target-multi" : "target-single"}
                  onChange={(id) => switchTargetMode(id === "target-multi" ? "multi" : "single")}
                  isDisabled={busy}
                />
              </div>

              {targetMode === "single" ? (
                <SelectInput
                  className="font-mono text-[11px]"
                  value={agentId}
                  onChange={(event) => {
                    setAgentId(event.target.value);
                    setSuccess(null);
                  }}
                  disabled={busy}
                >
                  <option value="">Select an agent</option>
                  {sortedAgents.map((a) => (
                    <option key={a.agent_id} value={a.agent_id}>
                      {agentLabel(a)}
                    </option>
                  ))}
                </SelectInput>
              ) : (
                <div className="space-y-2">
                  <EuiComboBox<string>
                    placeholder="Search and select agents"
                    options={comboOptions}
                    selectedOptions={selectedComboOptions}
                    onChange={(selected) => {
                      setAgentIds(selected.map((opt) => String(opt.value ?? opt.label)));
                      setSuccess(null);
                    }}
                    isDisabled={busy}
                    fullWidth
                    compressed
                    aria-label="Target agents"
                  />
                  <div className="flex items-center justify-between gap-2">
                    <EuiSwitch
                      compressed
                      label="Online agents only"
                      checked={onlineOnly}
                      onChange={(event) => setOnlineOnly(event.target.checked)}
                      disabled={busy}
                    />
                    {definition && agentIds.length > 0 ? (
                      <span className="text-[11px] text-muted-foreground">
                        Execute <span className="font-mono text-foreground">{definition.key}</span> on {agentIds.length}{" "}
                        agent{agentIds.length === 1 ? "" : "s"}
                      </span>
                    ) : null}
                  </div>
                </div>
              )}
            </div>

            <div>
              <div className="text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground">Payload (JSON)</div>
              <TextArea
                className="mt-1 font-mono text-[11px]"
                rows={8}
                value={payloadText}
                onChange={(event) => {
                  setPayloadText(event.target.value);
                  setError(null);
                }}
                disabled={busy}
              />
            </div>

            <div>
              <div className="text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground">Expiration (optional)</div>
              <TextInput
                type="datetime-local"
                className="mt-1 font-mono text-[11px]"
                value={expiresAt}
                onChange={(event) => setExpiresAt(event.target.value)}
                disabled={busy}
              />
              <div className="mt-2 flex flex-wrap gap-2">
                <Button variant="ghost" size="sm" onClick={() => setExpiresAt(offsetLocal(15))} disabled={busy}>
                  +15m
                </Button>
                <Button variant="ghost" size="sm" onClick={() => setExpiresAt(offsetLocal(60))} disabled={busy}>
                  +1h
                </Button>
                <Button variant="ghost" size="sm" onClick={() => setExpiresAt(offsetLocal(240))} disabled={busy}>
                  +4h
                </Button>
                <Button variant="ghost" size="sm" onClick={() => setExpiresAt(offsetLocal(1440))} disabled={busy}>
                  +24h
                </Button>
                <Button variant="ghost" size="sm" onClick={() => setExpiresAt("")} disabled={busy}>
                  Clear
                </Button>
              </div>
            </div>

            {error ? <InlineAlert tone="danger">{error}</InlineAlert> : null}
            {success ? <InlineAlert tone="success">{success}</InlineAlert> : null}

            {batchResult ? (
              <div className="space-y-2 rounded-md border border-border/60 bg-background/30 p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-[11px] text-foreground">{batchResult.batch_id}</span>
                  <StatusPill variant={batchResult.queued.length > 0 ? "success" : "neutral"}>
                    {batchResult.queued.length} queued
                  </StatusPill>
                  {batchResult.skipped.length > 0 ? (
                    <StatusPill variant="warning">{batchResult.skipped.length} skipped</StatusPill>
                  ) : null}
                </div>
                {batchResult.queued.length > 0 ? (
                  <div className="flex flex-wrap gap-2">
                    {batchResult.queued.map((item) => (
                      <button
                        key={item.action_id}
                        type="button"
                        className="rounded border border-border/60 bg-background/40 px-2 py-0.5 font-mono text-[11px] text-foreground hover:border-border"
                        onClick={() => onOpenAction?.(item.action_id)}
                        title={`Open execution #${item.action_id}`}
                      >
                        #{item.action_id} · {item.agent_id}
                      </button>
                    ))}
                  </div>
                ) : null}
                {batchResult.skipped.length > 0 ? (
                  <div className="space-y-1">
                    {batchResult.skipped.map((item) => (
                      <div key={item.agent_id} className="font-mono text-[11px] text-muted-foreground">
                        {item.agent_id} · {item.reason}
                      </div>
                    ))}
                  </div>
                ) : null}
              </div>
            ) : null}
          </div>
        </div>
      </Drawer>

      {modalOpen && definition ? (
        <DispatchModal
          definition={definition}
          targetAgentIds={targetAgentIds}
          payload={preparedPayload}
          busy={busy}
          error={error}
          onConfirm={(justification) => submit(preparedPayload, justification)}
          onClose={() => setModalOpen(false)}
        />
      ) : null}
    </>
  );
}
