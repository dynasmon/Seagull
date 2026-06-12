import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import { fmtMaybeIso } from "@/features/agents/lib/agentUtils";
import { Button } from "@/shared/components/Button";
import { InlineAlert } from "@/shared/components/InlineAlert";
import { Panel } from "@/shared/components/Panel";
import { StatusPill } from "@/shared/components/StatusPill";
import { getErrorMessage } from "@/shared/lib/errors";
import { isAbortError } from "@/shared/lib/http";
import { usePortalRealtimeSubscription } from "@/shared/realtime/context";

import { listResponseActions } from "./api";
import { statusVariant } from "./lib";
import type { ResponseActionOut } from "./types";

interface ResponseActionMiniWidgetProps {
  agentId: string | null;
  enabled: boolean;
}

export default function ResponseActionMiniWidget({ agentId, enabled }: ResponseActionMiniWidgetProps) {
  const navigate = useNavigate();
  const [rows, setRows] = useState<ResponseActionOut[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);

  usePortalRealtimeSubscription("ui.response_actions.lifecycle.patch", (event) => {
    if (!enabled || !agentId) return;
    const eventAgentId = String(event.payload?.agent_id ?? event.payload?.workflow?.agent_id ?? "").trim();
    if (eventAgentId && eventAgentId !== agentId) return;
    setReloadKey((k) => k + 1);
  });

  useEffect(() => {
    if (!enabled || !agentId) {
      setRows([]);
      setError(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    listResponseActions({ agent_id: agentId, limit: 5 }, { force: true })
      .then((out) => {
        if (cancelled) return;
        setRows(out);
        setError(null);
      })
      .catch((caught) => {
        if (cancelled || isAbortError(caught)) return;
        setError(getErrorMessage(caught, "Failed to load response actions"));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [enabled, agentId, reloadKey]);

  if (!enabled || !agentId) return null;

  return (
    <Panel
      title="Recent response actions"
      actions={
        <Button
          variant="ghost"
          size="sm"
          onClick={() => navigate(`/response-center?agent_id=${encodeURIComponent(agentId)}`)}
        >
          Open Response Center
        </Button>
      }
    >
      {error ? (
        <InlineAlert tone="danger">{error}</InlineAlert>
      ) : rows.length === 0 ? (
        <div className="text-[12px] text-muted-foreground">
          {loading ? "Loading…" : "No response actions for this agent yet."}
        </div>
      ) : (
        <div className="divide-y divide-border/40">
          {rows.map((row) => (
            <button
              key={row.id}
              type="button"
              className="flex w-full items-center gap-3 px-1 py-1.5 text-left hover:bg-background/40"
              onClick={() => navigate(`/response-center?action_id=${row.id}`)}
              title={`Open execution #${row.id}`}
            >
              <span className="w-12 shrink-0 font-mono text-[11px] text-muted-foreground">#{row.id}</span>
              <StatusPill variant={statusVariant(row.status)}>{row.status}</StatusPill>
              <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-foreground">{row.action_type}</span>
              <span className="shrink-0 text-[10.5px] text-muted-foreground">{fmtMaybeIso(row.requested_at)}</span>
            </button>
          ))}
        </div>
      )}
    </Panel>
  );
}
