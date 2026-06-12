import { EuiCopy } from "@elastic/eui";

import { Badge } from "@/shared/components/Badge";
import { Button } from "@/shared/components/Button";
import { StatusPill } from "@/shared/components/StatusPill";

import type { ResponseActionResultOut } from "../types";
import { DetailRow, DryRunBadge, formatBytes } from "./lib";

export default function QuarantineFileResultRenderer({ result }: { result: ResponseActionResultOut }) {
  const payload = result.result_payload || {};
  const dryRun = Boolean(payload.dry_run);
  const quarantined = Boolean(payload.quarantined);
  const sha256 = typeof payload.sha256 === "string" ? payload.sha256 : "";
  const size = typeof payload.size_bytes === "number" ? payload.size_bytes : null;
  const permsBefore = payload.permissions_before ? String(payload.permissions_before) : "";
  const permsAfter = payload.permissions_after ? String(payload.permissions_after) : "";

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        {dryRun ? (
          <DryRunBadge />
        ) : (
          <StatusPill variant={quarantined ? "success" : "neutral"}>{quarantined ? "quarantined" : "not quarantined"}</StatusPill>
        )}
      </div>

      <div className="rounded-md border border-border/60 bg-background/30 p-3 font-mono text-[11.5px]">
        <div className="truncate text-foreground" title={String(payload.original_path || "")}>
          {String(payload.original_path || "—")}
        </div>
        <div className="my-1 text-muted-foreground">↓</div>
        <div className="truncate text-foreground" title={String(payload.quarantine_path || "")}>
          {String(payload.quarantine_path || "—")}
        </div>
      </div>

      {size !== null ? (
        <DetailRow label="Size">
          {formatBytes(size)} <span className="text-muted-foreground">({size.toLocaleString()} bytes)</span>
        </DetailRow>
      ) : null}

      <DetailRow label="Permissions">
        <span className="flex items-center gap-2">
          {permsBefore ? <Badge variant="neutral">{permsBefore}</Badge> : <span className="text-muted-foreground">—</span>}
          {permsAfter ? (
            <>
              <span className="text-muted-foreground">→</span>
              <Badge variant="medium">{permsAfter}</Badge>
            </>
          ) : null}
        </span>
      </DetailRow>

      {sha256 ? (
        <DetailRow label="SHA-256">
          <span className="flex items-center gap-2">
            <span className="truncate font-mono text-[11px]" title={sha256}>
              {sha256}
            </span>
            <EuiCopy textToCopy={sha256}>
              {(copy) => (
                <Button variant="ghost" size="sm" onClick={copy}>
                  Copy
                </Button>
              )}
            </EuiCopy>
          </span>
        </DetailRow>
      ) : null}
    </div>
  );
}
