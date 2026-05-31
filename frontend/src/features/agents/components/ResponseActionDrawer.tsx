import { EuiPanel } from "@elastic/eui";

import EmptyState from "@/shared/components/EmptyState";
import Drawer from "@/shared/components/Drawer";
import { Button } from "@/shared/components/Button";
import { InlineAlert } from "@/shared/components/InlineAlert";
import { Panel } from "@/shared/components/Panel";
import { SelectInput } from "@/shared/components/SelectInput";
import { TextInput } from "@/shared/components/TextInput";
import { TextArea } from "@/shared/components/TextArea";
import {
  InvestigationActionBar,
  InvestigationActionButton,
  InvestigationFactCard,
  InvestigationMetaStrip,
  InvestigationRawJsonPanel,
  InvestigationSection,
  InvestigationShell,
  InvestigationSummaryGrid,
  InvestigationTabs,
} from "@/shared/components/investigation";
import PinToWorkspaceDrawer from "@/features/investigations/PinToWorkspaceDrawer";
import { pinResponseResultToWorkspace } from "@/features/investigations/api";

import { FieldLabel } from "./AgentsPageShared";
import type { AgentPublic } from "../types";
import { RESPONSE_ACTION_TYPES, fmtMaybeIso, fmtDuration } from "../lib/agentUtils";
import type { AgentActionsController } from "../hooks/useAgentActions";

interface ResponseActionDrawerProps {
  controller: AgentActionsController;
  user: { username?: string } | null;
  isAdmin: boolean;
  agentsSorted: AgentPublic[];
}

export default function ResponseActionDrawer({ controller, user, isAdmin, agentsSorted }: ResponseActionDrawerProps) {
  const {
    responseActionOpen,
    closeResponseActionDrawer,
    responseActionAgentId,
    setResponseActionAgentId,
    responseActionType,
    setResponseActionType,
    responseActionPayloadText,
    setResponseActionPayloadText,
    responseActionAdvancedOpen,
    setResponseActionAdvancedOpen,
    responseActionExpiresAt,
    setResponseActionExpiresAt,
    responseActionError,
    setResponseActionError,
    responseActionCreated,
    setResponseActionCreated,
    responseActionMode,
    setResponseActionMode,
    responseActionTab,
    setResponseActionTab,
    responseActionSelectedId,
    responseActionHistory,
    responseActionHistoryLoading,
    responseActionHistoryError,
    responseActionLiveLoading,
    responseActionLiveError,
    responseActionResult,
    responseActionResultLoading,
    responseActionResultError,
    responseActionResultRawOpen,
    setResponseActionResultRawOpen,
    pinResponseResultId,
    setPinResponseResultId,
    responseActionBusy,
    responseActionDefinition,
    responseActionAgentRow,
    responseActionPayload,
    responseActionPayloadError,
    responseActionExpirationInvalid,
    responseActionExpirationInPast,
    responseActionAgentStatus,
    responseActionExpiresLabel,
    canSubmitResponseAction,
    responseActionLiveView,
    responseActionCanCancel,
    loadResponseActionHistory,
    loadResponseActionLive,
    loadResponseActionResult,
    setResponseActionExpiryOffset,
    onSelectResponseAction,
    onCancelSelectedResponseAction,
    onCopyResponseResultJson,
    onDownloadResponseResultJson,
    onSubmitResponseAction,
    fmtLastSeen,
  } = controller;
  return (
    <>
      <Drawer
        open={responseActionOpen}
        onClose={closeResponseActionDrawer}
        title={`Response action • ${responseActionAgentRow?.display_name || responseActionAgentId || "Select target"}`}
        description="Operator workflow for audited agent-side response execution."
        widthClassName="w-[860px]"
        headerLabel="Response action"
      >
        {!isAdmin ? (
          <EmptyState title="Access denied" hint="Only administrators can queue response actions." />
        ) : (
          <InvestigationShell>
            <InvestigationMetaStrip
              items={[
                { label: "Operator", value: user?.username || "-", variant: "neutral" },
                { label: "Target", value: responseActionAgentRow?.display_name || responseActionAgentId || "not selected", variant: "info" },
                { label: "Agent ID", value: responseActionAgentId || "-" },
                { label: "Agent status", value: responseActionAgentStatus, variant: responseActionAgentStatus === "Online" ? "low" : "neutral" },
                { label: "Last seen", value: responseActionAgentRow ? fmtLastSeen(responseActionAgentRow.last_seen_at) : "-" },
              ]}
            />

            <InvestigationActionBar>
              <InvestigationActionButton
                onClick={() => {
                  setResponseActionMode("create");
                  setResponseActionTab("create");
                }}
                tone={responseActionMode === "create" ? "primary" : "default"}
              >
                Create action
              </InvestigationActionButton>
              <InvestigationActionButton
                onClick={() => {
                  setResponseActionMode("investigate");
                  if (responseActionTab === "create") {
                    setResponseActionTab(responseActionSelectedId ? "result" : "execution");
                  }
                }}
                tone={responseActionMode === "investigate" ? "primary" : "default"}
              >
                Investigate results
              </InvestigationActionButton>
              <InvestigationActionButton
                onClick={() => {
                  if (responseActionSelectedId) {
                    loadResponseActionLive(responseActionSelectedId);
                    loadResponseActionResult(responseActionSelectedId);
                  }
                  loadResponseActionHistory(responseActionAgentId);
                }}
              >
                Refresh action data
              </InvestigationActionButton>
              <InvestigationActionButton
                onClick={() => {
                  if (!responseActionResult) return;
                  setPinResponseResultId(responseActionResult.id);
                }}
                disabled={!responseActionResult}
                tone="primary"
              >
                Pin selected result
              </InvestigationActionButton>
            </InvestigationActionBar>

            {responseActionError && <InlineAlert tone="danger">{responseActionError}</InlineAlert>}

            {responseActionCreated && (
              <InlineAlert tone="success">
                Response action #{responseActionCreated.id} queued for {responseActionCreated.agent_id} with status {responseActionCreated.status}.
              </InlineAlert>
            )}

            {responseActionMode === "create" ? (
              <div className="space-y-4">
                <div className="grid gap-4 lg:grid-cols-2">
                  <Panel title="Target & scheduling">
                    <div className="space-y-4">
                      <div>
                        <FieldLabel>Target agent</FieldLabel>
                        <SelectInput
                          className="mt-1 font-mono text-[11px]"
                          value={responseActionAgentId}
                          onChange={(e) => {
                            setResponseActionAgentId(e.target.value);
                            setResponseActionError(null);
                            setResponseActionCreated(null);
                          }}
                          disabled={responseActionBusy}
                        >
                          <option value="">Select an agent</option>
                          {agentsSorted.map((a) => (
                            <option key={a.agent_id} value={a.agent_id}>
                              {(a.display_name || a.agent_id) + " (" + a.agent_id + ")"}
                            </option>
                          ))}
                        </SelectInput>
                      </div>

                      <div>
                        <FieldLabel>Expiration (optional)</FieldLabel>
                        <TextInput
                          type="datetime-local"
                          className="mt-1 font-mono text-[11px]"
                          value={responseActionExpiresAt}
                          onChange={(e) => {
                            setResponseActionExpiresAt(e.target.value);
                            setResponseActionError(null);
                            setResponseActionCreated(null);
                          }}
                          disabled={responseActionBusy}
                        />
                        <div className="mt-2 flex flex-wrap gap-2">
                          <Button variant="ghost" size="sm" onClick={() => setResponseActionExpiryOffset(15)} disabled={responseActionBusy}>
                            +15m
                          </Button>
                          <Button variant="ghost" size="sm" onClick={() => setResponseActionExpiryOffset(60)} disabled={responseActionBusy}>
                            +1h
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setResponseActionExpiresAt("");
                              setResponseActionError(null);
                              setResponseActionCreated(null);
                            }}
                            disabled={responseActionBusy}
                          >
                            Clear
                          </Button>
                        </div>
                        {responseActionExpirationInvalid && (
                          <div className="mt-1 text-[11px] text-danger">Expiration must be a valid date and time.</div>
                        )}
                        {responseActionExpirationInPast && (
                          <div className="mt-1 text-[11px] text-danger">Expiration must be in the future.</div>
                        )}
                      </div>
                    </div>
                  </Panel>

                  <Panel title="Action">
                    <div className="space-y-4">
                      <div>
                        <FieldLabel>Action type</FieldLabel>
                        <SelectInput
                          className="mt-1 font-mono text-[11px]"
                          value={responseActionType}
                          onChange={(e) => {
                            setResponseActionType(e.target.value);
                            setResponseActionError(null);
                            setResponseActionCreated(null);
                          }}
                          disabled={responseActionBusy}
                        >
                          {RESPONSE_ACTION_TYPES.map((x) => (
                            <option key={x.key} value={x.key}>
                              {x.label}
                            </option>
                          ))}
                        </SelectInput>
                        <div className="mt-1 text-[11px] text-muted-foreground">{responseActionDefinition.hint}</div>
                      </div>

                      <div className="rounded border border-border/60 bg-background/30 p-3 space-y-2">
                        <div>
                          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Expected effect</div>
                          <div className="mt-1 text-[12px] text-muted-foreground">{responseActionDefinition.effect}</div>
                        </div>
                        <div>
                          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Expected result</div>
                          <div className="mt-1 text-[12px] text-muted-foreground">{responseActionDefinition.expectedResult}</div>
                        </div>
                        <div>
                          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Audit</div>
                          <div className="mt-1 text-[12px] text-muted-foreground">{responseActionDefinition.auditNote}</div>
                        </div>
                      </div>
                    </div>
                  </Panel>
                </div>

                <Panel title="Payload" actions={<span className="text-[10px] font-mono text-muted-foreground">{responseActionAdvancedOpen ? "Advanced mode" : "Guided mode"}</span>}>
                  <div className="space-y-3">
                    <div className="rounded border border-border/60 bg-background/30 px-3 py-2 text-[12px] text-muted-foreground">
                      Payload is optional. Guided mode sends defaults from the server-side action schema.
                    </div>
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => {
                        setResponseActionAdvancedOpen((prev) => !prev);
                        setResponseActionError(null);
                        setResponseActionCreated(null);
                      }}
                      disabled={responseActionBusy}
                    >
                      {responseActionAdvancedOpen ? "Hide advanced payload" : "Show advanced payload JSON"}
                    </Button>
                    {responseActionAdvancedOpen && (
                      <div>
                        <TextArea
                          className="mt-1 font-mono text-[11px]"
                          rows={7}
                          value={responseActionPayloadText}
                          onChange={(e) => {
                            setResponseActionPayloadText(e.target.value);
                            setResponseActionError(null);
                            setResponseActionCreated(null);
                          }}
                          disabled={responseActionBusy}
                        />
                        {responseActionPayloadError && (
                          <div className="mt-1 text-[11px] text-danger">Payload: {responseActionPayloadError}</div>
                        )}
                      </div>
                    )}
                  </div>
                </Panel>

                <Panel title="Execution summary" actions={<span className="text-[10px] font-mono text-muted-foreground">Review before queueing</span>}>
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Agent</div>
                      <div className="mt-1 text-[12px] font-mono">{responseActionAgentId || "Not selected"}</div>
                    </div>
                    <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Action</div>
                      <div className="mt-1 text-[12px] font-mono">{responseActionDefinition.label}</div>
                    </div>
                    <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Expiration</div>
                      <div className="mt-1 text-[12px] font-mono">{responseActionExpiresLabel}</div>
                    </div>
                    <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Payload keys</div>
                      <div className="mt-1 text-[12px] font-mono">{Object.keys(responseActionPayload.payload || {}).length}</div>
                    </div>
                  </div>
                </Panel>

                <div className="rounded-lg border border-border/60 bg-background/40 px-4 py-3">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="text-[11px] text-muted-foreground">Queue this request to start the execution lifecycle.</div>
                    <div className="flex flex-wrap items-center gap-3">
                      <Button variant="secondary" size="sm" onClick={closeResponseActionDrawer} disabled={responseActionBusy}>
                        Close
                      </Button>
                      <Button variant="primary" size="sm" onClick={onSubmitResponseAction} disabled={!canSubmitResponseAction}>
                        {responseActionBusy ? "Queueing..." : "Queue response action"}
                      </Button>
                    </div>
                  </div>
                </div>
              </div>
            ) : null}

            {responseActionMode === "investigate" ? (
              <>
                <InvestigationSection title="Investigation focus" subtitle="Inspect execution timeline and returned evidence.">
                  <InvestigationSummaryGrid>
                    <InvestigationFactCard
                      label="Selected action"
                      value={responseActionSelectedId ? `#${responseActionSelectedId}` : "-"}
                      mono
                    />
                    <InvestigationFactCard
                      label="Action type"
                      value={responseActionLiveView?.action_type || responseActionResult?.status || "-"}
                      mono
                    />
                    <InvestigationFactCard
                      label="Execution state"
                      value={responseActionLiveView?.status || responseActionResult?.status || "-"}
                      mono
                    />
                    <InvestigationFactCard
                      label="Requested at"
                      value={fmtMaybeIso(responseActionLiveView?.requested_at || null)}
                      mono
                    />
                    <InvestigationFactCard
                      label="Duration"
                      value={
                        responseActionResult
                          ? fmtDuration(responseActionResult.started_at, responseActionResult.finished_at)
                          : responseActionLiveView
                            ? fmtDuration(responseActionLiveView.started_at, responseActionLiveView.finished_at)
                            : "-"
                      }
                      mono
                    />
                    <InvestigationFactCard
                      label="Result payload keys"
                      value={String(Object.keys(responseActionResult?.result_payload || {}).length)}
                      mono
                    />
                  </InvestigationSummaryGrid>
                </InvestigationSection>

                <InvestigationTabs
                  value={responseActionTab === "result" ? "result" : "execution"}
                  onChange={(next) => {
                    setResponseActionTab(next as "create" | "execution" | "result");
                  }}
                  tabs={[
                    { key: "execution", label: "Execution" },
                    { key: "result", label: "Result" },
                  ]}
                />

                {responseActionTab === "execution" && (
                  <div className="space-y-4">
                    <Panel title="Live execution status" actions={<span className="text-[10px] font-mono text-muted-foreground">{responseActionLiveLoading ? "Refreshing" : ""}</span>}>
                      <div className="space-y-4">
                        <div className="flex flex-wrap items-center gap-3">
                          <div className="min-w-[220px]">
                            <FieldLabel>Action instance</FieldLabel>
                            <SelectInput
                              className="mt-1 font-mono text-[11px]"
                              value={responseActionSelectedId ? String(responseActionSelectedId) : ""}
                              onChange={(e) => onSelectResponseAction(Number(e.target.value) || 0, "execution")}
                              disabled={responseActionBusy || responseActionHistoryLoading || responseActionHistory.length === 0}
                            >
                              <option value="">Select action</option>
                              {responseActionHistory.map((x) => (
                                <option key={x.id} value={x.id}>
                                  #{x.id} · {x.status}
                                </option>
                              ))}
                            </SelectInput>
                          </div>
                          <Button
                            variant="secondary"
                            size="sm"
                            onClick={() => {
                              if (responseActionSelectedId) {
                                loadResponseActionLive(responseActionSelectedId);
                                loadResponseActionResult(responseActionSelectedId);
                              }
                              loadResponseActionHistory(responseActionAgentId);
                            }}
                          >
                            Refresh status
                          </Button>
                        </div>

                        {responseActionLiveError && <InlineAlert tone="danger">{responseActionLiveError}</InlineAlert>}

                        {!responseActionLiveView ? (
                          <EmptyState title="No action selected" hint="Queue an action or select one from history." />
                        ) : (
                          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                            <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                              <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Current status</div>
                              <div className="mt-1 text-[12px] font-mono">{responseActionLiveView.status}</div>
                            </div>
                            <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                              <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Requested by</div>
                              <div className="mt-1 text-[12px] font-mono">{responseActionLiveView.requested_by || "-"}</div>
                            </div>
                            <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                              <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Requested at</div>
                              <div className="mt-1 text-[12px] font-mono">{fmtMaybeIso(responseActionLiveView.requested_at)}</div>
                            </div>
                            <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                              <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Delivered at</div>
                              <div className="mt-1 text-[12px] font-mono">{fmtMaybeIso(responseActionLiveView.delivered_at)}</div>
                            </div>
                            <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                              <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Started at</div>
                              <div className="mt-1 text-[12px] font-mono">{fmtMaybeIso(responseActionLiveView.started_at)}</div>
                            </div>
                            <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                              <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Finished at</div>
                              <div className="mt-1 text-[12px] font-mono">{fmtMaybeIso(responseActionLiveView.finished_at)}</div>
                            </div>
                            <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                              <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Duration</div>
                              <div className="mt-1 text-[12px] font-mono">
                                {fmtDuration(responseActionLiveView.started_at, responseActionLiveView.finished_at)}
                              </div>
                            </div>
                            <div className="rounded border border-border/60 bg-background/30 px-3 py-2 sm:col-span-2">
                              <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Last error</div>
                              <div className="mt-1 text-[12px] font-mono break-words">{responseActionLiveView.last_error || "-"}</div>
                            </div>
                          </div>
                        )}

                        <div className="flex flex-wrap items-center gap-3">
                          <Button
                            variant="secondary"
                            size="sm"
                            onClick={onCancelSelectedResponseAction}
                            disabled={!responseActionSelectedId || !responseActionCanCancel || responseActionBusy}
                          >
                            {responseActionBusy ? "Working..." : "Cancel action"}
                          </Button>
                          <Button
                            variant="secondary"
                            size="sm"
                            onClick={() => setResponseActionTab("result")}
                            disabled={!responseActionSelectedId}
                          >
                            Open result viewer
                          </Button>
                        </div>
                      </div>
                    </Panel>
                  </div>
                )}

                {responseActionTab === "result" && (
                  <div className="space-y-4">
                    <Panel title="Result viewer" actions={<span className="text-[10px] font-mono text-muted-foreground">{responseActionResultLoading ? "Loading" : ""}</span>}>
                      <div className="space-y-4">
                        <div className="flex flex-wrap items-center gap-3">
                          <div className="min-w-[220px]">
                            <FieldLabel>Action instance</FieldLabel>
                            <SelectInput
                              className="mt-1 font-mono text-[11px]"
                              value={responseActionSelectedId ? String(responseActionSelectedId) : ""}
                              onChange={(e) => onSelectResponseAction(Number(e.target.value) || 0)}
                              disabled={responseActionBusy || responseActionHistory.length === 0}
                            >
                              <option value="">Select action</option>
                              {responseActionHistory.map((x) => (
                                <option key={x.id} value={x.id}>
                                  #{x.id} · {x.status}
                                </option>
                              ))}
                            </SelectInput>
                          </div>
                        </div>

                        {responseActionResultError && <InlineAlert tone="danger">{responseActionResultError}</InlineAlert>}

                        {!responseActionResult ? (
                          <EmptyState title="Result unavailable" hint="This action has not reported a result yet." />
                        ) : (
                          <div className="space-y-3">
                            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                              <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Status</div>
                                <div className="mt-1 text-[12px] font-mono">{responseActionResult.status}</div>
                              </div>
                              <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Started</div>
                                <div className="mt-1 text-[12px] font-mono">{fmtMaybeIso(responseActionResult.started_at)}</div>
                              </div>
                              <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Finished</div>
                                <div className="mt-1 text-[12px] font-mono">{fmtMaybeIso(responseActionResult.finished_at)}</div>
                              </div>
                              <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Duration</div>
                                <div className="mt-1 text-[12px] font-mono">{fmtDuration(responseActionResult.started_at, responseActionResult.finished_at)}</div>
                              </div>
                            </div>

                            <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                              <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Error</div>
                              <div className="mt-1 text-[12px] font-mono break-words">{responseActionResult.error || "-"}</div>
                            </div>

                            <div className="flex flex-wrap items-center gap-3">
                              <Button variant="secondary" size="sm" onClick={onCopyResponseResultJson}>
                                Copy JSON
                              </Button>
                              <Button variant="secondary" size="sm" onClick={onDownloadResponseResultJson}>
                                Download result
                              </Button>
                              <Button variant="secondary" size="sm" onClick={() => setPinResponseResultId(responseActionResult.id)}>
                                Pin to workspace
                              </Button>
                              <Button variant="secondary" size="sm" onClick={() => setResponseActionResultRawOpen((prev) => !prev)}>
                                {responseActionResultRawOpen ? "Hide details" : "Open details"}
                              </Button>
                            </div>

                            {responseActionResultRawOpen ? (
                              <InvestigationRawJsonPanel value={responseActionResult} title="Raw response result JSON" />
                            ) : null}
                          </div>
                        )}
                      </div>
                    </Panel>
                  </div>
                )}

                <Panel
                  title="History"
                  actions={<span className="text-[10px] font-mono text-muted-foreground">{responseActionHistoryLoading ? "Loading" : responseActionHistory.length ? String(responseActionHistory.length) : "Empty"}</span>}
                >
                  {responseActionHistoryError ? (
                    <InlineAlert tone="danger">{responseActionHistoryError}</InlineAlert>
                  ) : responseActionHistory.length === 0 ? (
                    <div className="text-[12px] text-muted-foreground">No actions found for this agent.</div>
                  ) : (
                    <div className="space-y-2 max-h-[240px] overflow-y-auto pr-1">
                      {responseActionHistory.map((x) => {
                        const active = x.id === responseActionSelectedId;
                        return (
                          <EuiPanel
                            key={x.id}
                            onClick={() => onSelectResponseAction(x.id)}
                            hasBorder
                            hasShadow={false}
                            paddingSize="s"
                            borderRadius="m"
                            color={active ? "primary" : "plain"}
                            className="w-full text-left"
                            aria-pressed={active}
                          >
                            <div className="flex items-center justify-between gap-3">
                              <div className="text-[12px] font-mono">#{x.id} {x.action_type}</div>
                              <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{x.status}</div>
                            </div>
                            <div className="mt-1 text-[11px] text-muted-foreground">requested {fmtMaybeIso(x.requested_at)}</div>
                          </EuiPanel>
                        );
                      })}
                    </div>
                  )}
                </Panel>
              </>
            ) : null}

            <div className="rounded-lg border border-border/60 bg-background/40 px-4 py-3">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="text-[11px] text-muted-foreground">
                  Request, execution, and result are available in a single operator console.
                </div>
                <Button variant="secondary" size="sm" onClick={closeResponseActionDrawer} disabled={responseActionBusy}>
                  Close
                </Button>
              </div>
            </div>
          </InvestigationShell>
        )}
      </Drawer>

      {pinResponseResultId && responseActionResult ? (
        <PinToWorkspaceDrawer
          open={Boolean(pinResponseResultId)}
          onClose={() => setPinResponseResultId(null)}
          title={`response result #${pinResponseResultId}`}
          defaultWorkspaceTitle={`Response action investigation · ${responseActionAgentId || "agent"}`}
          workspaceDefaults={{ primary_agent_id: responseActionResult.agent_id || undefined }}
          onPin={(workspaceId, options) =>
            pinResponseResultToWorkspace(workspaceId, pinResponseResultId, {
              ...options,
              source_module: "agents_response",
            })
          }
        />
      ) : null}
    </>
  );
}
