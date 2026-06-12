import { EuiCodeBlock } from "@elastic/eui";

import { Badge } from "@/shared/components/Badge";
import { Button } from "@/shared/components/Button";
import { StatusPill } from "@/shared/components/StatusPill";

import type { ResponseActionResultOut } from "../types";
import { DetailRow, DryRunBadge } from "./lib";

interface BlockIpResultRendererProps {
  actionType: string;
  result: ResponseActionResultOut;
  requestPayload?: Record<string, any> | null;
  onPivot?: (input: { actionKey: string; agentId?: string; payload?: Record<string, any> }) => void;
}

export default function BlockIpResultRenderer({ actionType, result, requestPayload, onPivot }: BlockIpResultRendererProps) {
  const payload = result.result_payload || {};
  const dryRun = Boolean(payload.dry_run);
  const tool = String(payload.firewall_tool || "—");
  const ruleText = typeof payload.rule_text === "string" ? payload.rule_text : "";
  const isUnblock = actionType === "unblock_outbound_ip";
  const ruleAdded = Boolean(payload.rule_added);
  const rulesRemoved = typeof payload.rules_removed === "number" ? payload.rules_removed : 0;

  function buildUnblockPayload(): Record<string, any> {
    const src = requestPayload || {};
    const out: Record<string, any> = { ip: src.ip ?? "", protocol: src.protocol ?? "tcp" };
    if (src.port) out.port = src.port;
    if (src.comment) out.comment = src.comment;
    return out;
  }

  const canPivot = !isUnblock && Boolean(onPivot) && Boolean(requestPayload?.ip);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="neutral">{tool}</Badge>
        {dryRun ? (
          <DryRunBadge />
        ) : isUnblock ? (
          <StatusPill variant={rulesRemoved > 0 ? "success" : "neutral"}>
            {rulesRemoved} rule{rulesRemoved === 1 ? "" : "s"} removed
          </StatusPill>
        ) : (
          <StatusPill variant={ruleAdded ? "success" : "neutral"}>{ruleAdded ? "rule added" : "no change"}</StatusPill>
        )}
      </div>

      {requestPayload?.ip ? (
        <DetailRow label="Target">
          <span className="font-mono text-[12px]">
            {String(requestPayload.ip)}
            {requestPayload.port ? `:${requestPayload.port}` : ""}
            {requestPayload.protocol ? ` / ${String(requestPayload.protocol)}` : ""}
          </span>
        </DetailRow>
      ) : null}

      {ruleText ? (
        <div>
          <div className="mb-1 font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">Rule</div>
          <EuiCodeBlock language="bash" fontSize="s" paddingSize="s" isCopyable>
            {ruleText}
          </EuiCodeBlock>
        </div>
      ) : null}

      {canPivot ? (
        <div className="flex items-center gap-2 pt-1">
          <Button
            variant="secondary"
            size="sm"
            onClick={() => onPivot?.({ actionKey: "unblock_outbound_ip", agentId: result.agent_id, payload: buildUnblockPayload() })}
          >
            Dispatch unblock
          </Button>
          <span className="text-[11px] text-muted-foreground">Reverse this block with the same target.</span>
        </div>
      ) : null}
    </div>
  );
}
