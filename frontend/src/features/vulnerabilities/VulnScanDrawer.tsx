import { useMemo } from "react";

import Drawer from "@/shared/components/Drawer";
import { Badge } from "@/shared/components/Badge";
import { Card } from "@/shared/components/Card";
import { cx } from "@/shared/lib/cx";

import { PhaseTimeline, ScanStats } from "./ActiveScanPanel";
import { LiveElapsedText } from "./LiveElapsedText";
import { fmtSec, fmtWhen, fmtAge, scanLifecycleLabel, scanPhaseLabel, scanTriggerLabel, scanVariant } from "./scanUtils";
import type { VulnScan } from "./types";

function safeJson(v: any): string {
  try {
    return JSON.stringify(v ?? null, null, 2);
  } catch {
    return String(v);
  }
}

function ScanDurationDisplay({ scan }: { scan: VulnScan }) {
  const isLive =
    !scan.finished_at &&
    (scan.lifecycle_state === "queued" ||
      scan.lifecycle_state === "acknowledged" ||
      scan.lifecycle_state === "running");
  const className = "font-mono text-sm text-foreground";

  if (typeof scan.duration_ms === "number" && Number.isFinite(scan.duration_ms)) {
    return <span className={className}>{fmtSec(scan.duration_ms / 1000)}</span>;
  }
  if (scan.started_at && scan.finished_at) {
    const ms = Date.parse(scan.finished_at) - Date.parse(scan.started_at);
    return (
      <span className={className}>
        {Number.isFinite(ms) ? fmtSec(Math.max(0, ms / 1000)) : "-"}
      </span>
    );
  }
  if (isLive && (scan.started_at || scan.queued_at)) {
    return (
      <LiveElapsedText
        startIso={scan.started_at ?? scan.queued_at}
        endIso={null}
        className={cx(className, "text-primary")}
      />
    );
  }
  return <span className={className}>-</span>;
}

export default function VulnScanDrawer({
  open,
  scan,
  onClose,
}: {
  open: boolean;
  scan: VulnScan | null;
  onClose: () => void;
}) {
  const queueWaitLabel = useMemo(() => {
    if (!scan?.queued_at) return "-";
    const queuedAt = Date.parse(scan.queued_at);
    const dequeuedAt = Date.parse(
      scan.acknowledged_at || scan.started_at || scan.finished_at || ""
    );
    if (Number.isNaN(queuedAt) || Number.isNaN(dequeuedAt)) return "-";
    return fmtSec(Math.max(0, (dequeuedAt - queuedAt) / 1000));
  }, [scan]);

  const hasTimeline = useMemo(
    () => Boolean(scan && Object.keys(scan.phase_timestamps ?? {}).length),
    [scan]
  );
  const hasStats = useMemo(
    () =>
      Boolean(
        scan &&
          Object.values(scan.stats ?? {}).some(
            (value) => typeof value === "number" && Number.isFinite(value)
          )
      ),
    [scan]
  );

  if (!scan) return null;

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title={`Scan #${scan.id}`}
      description={`${scan.tool}${scan.tool_version ? ` v${scan.tool_version}` : ""} • ${scan.scan_uuid}`}
      widthClassName="w-[1040px]"
    >
      <div className="space-y-4">
        <Card title="Overview" className="rounded-xl">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant={scanVariant(scan.lifecycle_state)}>{scanLifecycleLabel(scan.lifecycle_state)}</Badge>
            <Badge variant="neutral">{scanPhaseLabel(scan.current_phase)}</Badge>
            <span
              className={cx(
                "rounded border px-2 py-0.5 text-[10px] font-mono uppercase tracking-widest",
                scan.trigger_source === "manual"
                  ? "border-info/30 text-info/70"
                  : "border-border/40 text-muted-foreground/60"
              )}
            >
              {scanTriggerLabel(scan.trigger_source)}
            </span>
            <span className="font-mono text-[11px] text-muted-foreground">
              {scan.tool}
              {scan.tool_version ? ` @ ${scan.tool_version}` : ""}
            </span>
          </div>

          <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
            <div className="rounded-lg border border-border/50 bg-background/20 p-3">
              <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                Reporter
              </div>
              <div className="mt-2 font-mono text-sm">{scan.reporter_agent_id || "-"}</div>
            </div>
            <div className="rounded-lg border border-border/50 bg-background/20 p-3">
              <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                Target
              </div>
              <div className="mt-2 truncate font-mono text-sm" title={scan.target || ""}>
                {scan.target || "-"}
              </div>
            </div>
            <div className="rounded-lg border border-border/50 bg-background/20 p-3">
              <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                Duration
              </div>
              <div className="mt-2">
                <ScanDurationDisplay scan={scan} />
              </div>
              <div className="mt-1 text-xs text-muted-foreground">queue wait {queueWaitLabel}</div>
            </div>
          </div>

          <dl className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
            <div>
              <dt className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                Queued
              </dt>
              <dd className="mt-1 font-mono text-[12px] text-muted-foreground">
                {fmtWhen(scan.queued_at)}
              </dd>
            </div>
            <div>
              <dt className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                Acknowledged
              </dt>
              <dd className="mt-1 font-mono text-[12px] text-muted-foreground">
                {fmtWhen(scan.acknowledged_at)}
              </dd>
            </div>
            <div>
              <dt className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                Started
              </dt>
              <dd className="mt-1 font-mono text-[12px] text-muted-foreground">
                {fmtWhen(scan.started_at)}
              </dd>
            </div>
            <div>
              <dt className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                Finished
              </dt>
              <dd className="mt-1 font-mono text-[12px] text-muted-foreground">
                {fmtWhen(scan.finished_at)}
              </dd>
            </div>
            <div>
              <dt className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                Last progress
              </dt>
              <dd className="mt-1 font-mono text-[12px] text-muted-foreground">
                {fmtWhen(scan.last_progress_at)}
                {scan.last_progress_at ? ` · ${fmtAge(scan.last_progress_at)}` : ""}
              </dd>
            </div>
            <div>
              <dt className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                Profile
              </dt>
              <dd className="mt-1 font-mono text-[12px] text-muted-foreground">
                {(scan.config as any)?.analysis_profile ||
                  (scan.scope as any)?.analysis_profile ||
                  "-"}
              </dd>
            </div>
          </dl>

          {scan.error_summary ? (
            <div className="mt-4 rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-sm text-danger">
              {scan.error_summary}
            </div>
          ) : null}
        </Card>

        <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
          <Card title="Execution Timeline" className="rounded-xl xl:col-span-2">
            {hasTimeline ? (
              <PhaseTimeline scan={scan} />
            ) : (
              <div className="text-sm text-muted-foreground">
                No phase transitions have been recorded for this scan yet.
              </div>
            )}
          </Card>

          <Card title="Pipeline Counters" className="rounded-xl">
            {hasStats ? (
              <>
                <ScanStats stats={scan.stats} />
                <pre className="mt-4 text-xs whitespace-pre-wrap break-words text-muted-foreground">
                  {safeJson(scan.stats)}
                </pre>
              </>
            ) : (
              <div className="text-sm text-muted-foreground">
                No numeric pipeline counters were reported for this scan.
              </div>
            )}
          </Card>
        </div>

        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          <Card title="Scope" className="rounded-xl">
            <pre className="text-xs whitespace-pre-wrap break-words text-muted-foreground">
              {safeJson(scan.scope)}
            </pre>
          </Card>
          <Card title="Config" className="rounded-xl">
            <pre className="text-xs whitespace-pre-wrap break-words text-muted-foreground">
              {safeJson(scan.config)}
            </pre>
          </Card>
        </div>

        <Card title="Raw" className="rounded-xl">
          <div className="mb-3 flex items-center justify-end">
            <button
              type="button"
              onClick={() => navigator.clipboard.writeText(safeJson(scan))}
              className={cx(
                "rounded-md border border-border/60 bg-background/40 px-3 py-2",
                "text-[10px] font-mono uppercase tracking-widest text-muted-foreground",
                "hover:bg-muted/15 hover:text-foreground focus:outline-none focus:ring-2 focus:ring-primary/30"
              )}
            >
              Copy JSON
            </button>
          </div>
          <pre className="text-xs whitespace-pre-wrap break-words text-muted-foreground">
            {safeJson(scan)}
          </pre>
        </Card>
      </div>
    </Drawer>
  );
}
