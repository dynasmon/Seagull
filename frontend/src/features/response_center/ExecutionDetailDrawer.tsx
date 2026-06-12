import { useEffect, useState } from "react";

import { fmtDuration, fmtMaybeIso } from "@/features/agents/lib/agentUtils";
import { pinResponseResultToWorkspace } from "@/features/investigations/api";
import PinToWorkspaceDrawer from "@/features/investigations/PinToWorkspaceDrawer";
import { Button } from "@/shared/components/Button";
import Drawer from "@/shared/components/Drawer";
import EmptyState from "@/shared/components/EmptyState";
import { InlineAlert } from "@/shared/components/InlineAlert";
import { Panel } from "@/shared/components/Panel";
import { StatusPill, type StatusVariant } from "@/shared/components/StatusPill";
import { Tabs } from "@/shared/components/Tabs";
import { InvestigationRawJsonPanel } from "@/shared/components/investigation";
import { getErrorMessage } from "@/shared/lib/errors";
import { isAbortError } from "@/shared/lib/http";

import { cancelResponseAction, getResponseAction, getResponseActionResult, getResponseActionTimeline } from "./api";
import { isCancellableStatus, statusVariant } from "./lib";
import ResultRenderer, { type ResultPivotInput } from "./ResultRenderer";
import type { ResponseActionOut, ResponseActionResultOut, TimelineEventOut } from "./types";

interface ExecutionDetailDrawerProps {
  detailId: number | null;
  onClose: () => void;
  onChanged: () => void;
  onPivot?: (input: ResultPivotInput) => void;
}

type DetailTab = "timeline" | "result" | "raw";

const EVENT_VARIANT: Record<string, StatusVariant> = {
  queued: "neutral",
  delivered: "info",
  started: "pending",
  completed: "success",
  failed: "danger",
  cancelled: "inactive",
  expired: "inactive",
};

export default function ExecutionDetailDrawer({ detailId, onClose, onChanged, onPivot }: ExecutionDetailDrawerProps) {
  const [action, setAction] = useState<ResponseActionOut | null>(null);
  const [timeline, setTimeline] = useState<TimelineEventOut[]>([]);
  const [result, setResult] = useState<ResponseActionResultOut | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<DetailTab>("timeline");
  const [busy, setBusy] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);
  const [pinOpen, setPinOpen] = useState(false);

  useEffect(() => {
    if (!detailId) return;
    let cancelled = false;
    setLoading(true);
    setError(null);
    (async () => {
      try {
        const [actionRow, timelineRows] = await Promise.all([
          getResponseAction(detailId),
          getResponseActionTimeline(detailId),
        ]);
        if (cancelled) return;
        setAction(actionRow);
        setTimeline(timelineRows);
      } catch (caught) {
        if (!cancelled && !isAbortError(caught)) setError(getErrorMessage(caught, "Failed to load action"));
      } finally {
        if (!cancelled) setLoading(false);
      }
      try {
        const resultRow = await getResponseActionResult(detailId);
        if (!cancelled) setResult(resultRow);
      } catch {
        if (!cancelled) setResult(null);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [detailId, reloadKey]);

  async function handleCancel() {
    if (!detailId) return;
    setBusy(true);
    setError(null);
    try {
      await cancelResponseAction(detailId);
      setReloadKey((k) => k + 1);
      onChanged();
    } catch (caught) {
      setError(getErrorMessage(caught, "Failed to cancel action"));
    } finally {
      setBusy(false);
    }
  }

  const open = detailId !== null;
  const canCancel = Boolean(action && isCancellableStatus(action.status));

  return (
    <>
      <Drawer
        open={open}
        onClose={onClose}
        title={`Response action ${detailId ? `#${detailId}` : ""}`}
        description={action ? `${action.action_type} · ${action.agent_id}` : "Execution inspector"}
        headerLabel="Execution"
        widthClassName="w-[760px]"
        headerActions={action ? <StatusPill variant={statusVariant(action.status)}>{action.status}</StatusPill> : null}
        footer={
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="text-[11px] text-muted-foreground">
              {action ? `Requested by ${action.requested_by} · ${fmtMaybeIso(action.requested_at)}` : ""}
            </div>
            <div className="flex items-center gap-2">
              {result ? (
                <Button variant="secondary" size="sm" onClick={() => setPinOpen(true)} disabled={busy}>
                  Pin to workspace
                </Button>
              ) : null}
              <Button variant="secondary" size="sm" onClick={handleCancel} disabled={!canCancel || busy}>
                {busy ? "Working…" : "Cancel action"}
              </Button>
              <Button variant="secondary" size="sm" onClick={onClose} disabled={busy}>
                Close
              </Button>
            </div>
          </div>
        }
      >
        {error ? <InlineAlert tone="danger">{error}</InlineAlert> : null}

        <div className="mt-3">
          <Tabs
            value={tab}
            onChange={(next) => setTab(next)}
            tabs={[
              { key: "timeline", label: "Timeline" },
              { key: "result", label: "Result" },
              { key: "raw", label: "Raw JSON" },
            ]}
          />
        </div>

        <div className="mt-4">
          {loading && !action ? (
            <div className="text-[12px] text-muted-foreground">Loading…</div>
          ) : tab === "timeline" ? (
            <Panel title="Lifecycle timeline">
              {timeline.length === 0 ? (
                <EmptyState title="No timeline" hint="No lifecycle events recorded yet." />
              ) : (
                <ol className="space-y-3">
                  {timeline.map((event, idx) => (
                    <li key={`${event.event}-${idx}`} className="flex items-start gap-3">
                      <StatusPill variant={EVENT_VARIANT[event.event] || "neutral"}>{event.event}</StatusPill>
                      <div className="min-w-0">
                        <div className="text-[11.5px] text-foreground">{fmtMaybeIso(event.at)}</div>
                        <div className="text-[11px] text-muted-foreground">
                          {event.actor}
                          {event.detail ? ` · ${event.detail}` : ""}
                        </div>
                      </div>
                    </li>
                  ))}
                </ol>
              )}
            </Panel>
          ) : tab === "result" ? (
            <Panel
              title="Result"
              actions={
                result ? (
                  <span className="text-[10px] font-mono text-muted-foreground">
                    {result.status} · {fmtDuration(result.started_at, result.finished_at)}
                  </span>
                ) : null
              }
            >
              {result ? (
                <div className="space-y-3">
                  {result.error ? <InlineAlert tone="danger">{result.error}</InlineAlert> : null}
                  <ResultRenderer
                    actionType={action?.action_type || ""}
                    result={result}
                    requestPayload={action?.payload}
                    onPivot={onPivot}
                  />
                </div>
              ) : (
                <EmptyState title="No result yet" hint="This action has not reported a result." />
              )}
            </Panel>
          ) : (
            <Panel title="Raw JSON">
              <InvestigationRawJsonPanel value={result ?? action ?? {}} title="Raw execution record" />
            </Panel>
          )}
        </div>
      </Drawer>

      {pinOpen && result ? (
        <PinToWorkspaceDrawer
          open={pinOpen}
          onClose={() => setPinOpen(false)}
          title={`response result #${result.id}`}
          defaultWorkspaceTitle={`Response action investigation · ${result.agent_id || "agent"}`}
          workspaceDefaults={{ primary_agent_id: result.agent_id || undefined }}
          onPin={(workspaceId, options) =>
            pinResponseResultToWorkspace(workspaceId, result.id, {
              ...options,
              source_module: "agents_response",
            })
          }
        />
      ) : null}
    </>
  );
}
