import { Badge } from "@/shared/components/Badge";
import { InlineAlert } from "@/shared/components/InlineAlert";
import { StatusPill } from "@/shared/components/StatusPill";

import type { ResponseActionResultOut } from "../types";
import { DetailRow, DryRunBadge } from "./lib";

export default function IsolateHostResultRenderer({ result }: { result: ResponseActionResultOut }) {
  const payload = result.result_payload || {};
  const dryRun = Boolean(payload.dry_run);
  const isolated = Boolean(payload.isolated);
  const tool = String(payload.firewall_tool || "—");
  const rulesAdded = typeof payload.rules_added === "number" ? payload.rules_added : 0;
  const controlPlane: string[] = Array.isArray(payload.control_plane_allowed)
    ? payload.control_plane_allowed.map((entry: any) => String(entry))
    : [];

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <StatusPill variant={isolated ? "success" : "neutral"}>{isolated ? "isolated" : "not isolated"}</StatusPill>
        {dryRun ? <DryRunBadge /> : null}
      </div>

      <DetailRow label="Firewall">
        <Badge variant="neutral">{tool}</Badge>
      </DetailRow>

      <DetailRow label="Rules added">
        <span className="font-mono text-[12px]">{rulesAdded}</span>
      </DetailRow>

      {controlPlane.length > 0 ? (
        <DetailRow label="Control plane exceptions">
          <div className="flex flex-wrap gap-1.5">
            {controlPlane.map((entry, idx) => (
              <span
                key={`${entry}-${idx}`}
                className="rounded border border-border/60 bg-background/40 px-1.5 py-0.5 font-mono text-[11px] text-foreground"
              >
                {entry}
              </span>
            ))}
          </div>
        </DetailRow>
      ) : null}

      {isolated && !dryRun ? (
        <InlineAlert tone="warning">
          Host network traffic is blocked except for the control plane. Dispatch unblock_outbound_ip or restore manually to lift isolation.
        </InlineAlert>
      ) : null}
    </div>
  );
}
