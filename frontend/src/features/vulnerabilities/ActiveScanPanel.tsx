import { memo, useMemo } from "react";

import { Badge } from "@/shared/components/Badge";
import { Button } from "@/shared/components/Button";
import { Card } from "@/shared/components/Card";
import { InlineAlert } from "@/shared/components/InlineAlert";
import { SelectInput } from "@/shared/components/SelectInput";
import { Table, type Column } from "@/shared/components/Table";
import { cx } from "@/shared/lib/cx";
import type { AgentPublic } from "@/features/agents/types";

import { LiveElapsedText } from "./LiveElapsedText";
import {
  PHASE_SEQ,
  STAT_DISPLAY,
  fmtSec,
  fmtWhen,
  fmtAge,
  fmtAbsoluteAndAge,
  scanLifecycleLabel,
  scanPhaseLabel,
  scanTriggerLabel,
  scanVariant,
  isLiveScan,
} from "./scanUtils";
import type { VulnScan } from "./types";

const KNOWN_STAT_KEYS = new Set(STAT_DISPLAY.flatMap((d) => d.keys));

export const ScanStats = memo(function ScanStats({ stats, nowrap = false }: { stats: Record<string, any>; nowrap?: boolean }) {
  const chips = useMemo(() => {
    if (!stats || typeof stats !== "object") return [];
    const rendered = new Set<string>();
    const out: Array<{ key: string; label: string; value: string }> = [];

    for (const { keys, label } of STAT_DISPLAY) {
      if (rendered.has(label)) continue;
      for (const key of keys) {
        const v = stats[key];
        if (typeof v === "number" && Number.isFinite(v)) {
          out.push({ key, label, value: String(Math.round(v)) });
          rendered.add(label);
          break;
        }
      }
    }

    for (const [key, v] of Object.entries(stats)) {
      if (KNOWN_STAT_KEYS.has(key)) continue;
      if (typeof v !== "number" || !Number.isFinite(v)) continue;
      const label = key.replace(/_/g, " ");
      if (rendered.has(label)) continue;
      rendered.add(label);
      out.push({ key, label, value: String(Math.round(v)) });
    }

    return out.slice(0, 10);
  }, [stats]);

  if (!chips.length) return null;

  return (
    <div
      className={cx("flex gap-1.5", nowrap ? "min-w-0 flex-nowrap overflow-hidden" : "flex-wrap")}
      title={nowrap ? chips.map((x) => `${x.label} ${x.value}`).join(" · ") : undefined}
    >
      {chips.map((x) => (
        <span
          key={x.key}
          className="inline-flex shrink-0 items-center gap-1.5 rounded border border-border bg-surface-2 px-2 py-0.5"
        >
          <span className="text-[9.5px] font-semibold uppercase tracking-[0.1em] text-muted-foreground/85">{x.label}</span>
          <span className="font-mono text-[11px] text-foreground">{x.value}</span>
        </span>
      ))}
    </div>
  );
});

export const PhaseTimeline = memo(function PhaseTimeline({ scan }: { scan: VulnScan }) {
  const { current_phase, lifecycle_state } = scan;

  const rows = useMemo(() => {
    const phaseTimestamps = (scan.phase_timestamps ?? {}) as Record<string, string>;
    const terminalPhase = ["completed", "failed", "cancelled"].includes(lifecycle_state)
      ? lifecycle_state
      : null;

    const ordered: string[] = [...PHASE_SEQ];
    for (const k of Object.keys(phaseTimestamps)) {
      if (!ordered.includes(k)) ordered.push(k);
    }

    const currentIdx = ordered.indexOf(current_phase);

    const visible = ordered.filter((p) => {
      if (["completed", "failed", "cancelled"].includes(p)) {
        return p === terminalPhase || p === current_phase;
      }
      return Boolean(phaseTimestamps[p]) || ordered.indexOf(p) <= currentIdx;
    });

    return visible.map((p, i) => {
      const ts = phaseTimestamps[p] ?? null;
      const nextWithTs = visible.slice(i + 1).find((np) => phaseTimestamps[np]);
      const durMs =
        ts && nextWithTs && phaseTimestamps[nextWithTs]
          ? Date.parse(phaseTimestamps[nextWithTs]) - Date.parse(ts)
          : null;
      return {
        phase: p,
        ts,
        durMs,
        isCurrent: p === current_phase,
        isDone: ts !== null && p !== current_phase,
      };
    });
  }, [current_phase, lifecycle_state, scan.phase_timestamps]);

  if (!rows.length) return null;

  return (
    <div className="space-y-px">
      {rows.map(({ phase, ts, durMs, isCurrent, isDone }) => (
        <div
          key={phase}
          className={cx(
            "flex items-center gap-2 rounded px-2 py-1.5",
            isCurrent && "bg-primary/10 ring-1 ring-inset ring-primary/20",
            isDone && !isCurrent && "opacity-50",
            !ts && !isCurrent && "opacity-25"
          )}
        >
          <span
            className={cx(
              "h-1.5 w-1.5 flex-none rounded-full",
              isCurrent ? "bg-primary" : ts ? "bg-muted-foreground/50" : "bg-border/80"
            )}
          />
          <span
            className={cx(
              "w-44 flex-none font-mono text-[10px] uppercase tracking-widest",
              isCurrent ? "text-foreground" : "text-muted-foreground"
            )}
          >
            {scanPhaseLabel(phase)}
          </span>
          <span className="flex-1 font-mono text-[10px] text-muted-foreground/80">
            {ts ? fmtWhen(ts) : "—"}
          </span>
          {durMs !== null && Number.isFinite(durMs) && durMs > 0 && (
            <span className="flex-none font-mono text-[10px] text-muted-foreground/50">
              {fmtSec(durMs / 1000)}
            </span>
          )}
        </div>
      ))}
    </div>
  );
});

const RecentScansTable = memo(function RecentScansTable({
  scans,
  scanTargetAgent,
  onlySelectedAgent,
  onViewScan,
}: {
  scans: VulnScan[];
  scanTargetAgent: string;
  onlySelectedAgent: boolean;
  onViewScan: (s: VulnScan) => void;
}) {
  const visible = useMemo(
    () =>
      scans.filter((s) =>
        onlySelectedAgent ? (s.reporter_agent_id || "") === (scanTargetAgent || "") : true
      ),
    [scans, onlySelectedAgent, scanTargetAgent]
  );

  if (!visible.length) {
    return (
      <div className="rounded-lg border border-border/50 bg-background/20 px-3 py-4 text-center text-xs text-muted-foreground">
        {onlySelectedAgent ? "No recent scans for this agent." : "No recent scans in the current scope."}
      </div>
    );
  }

  const columns: Column<VulnScan>[] = [
    {
      key: "status",
      title: "Status / Phase",
      render: (s) => {
        const live = isLiveScan(String(s.lifecycle_state || "").toLowerCase());
        return (
          <div className="flex min-w-0 items-center gap-1.5">
            <Badge variant={scanVariant(String(s.lifecycle_state || "").toLowerCase())}>{scanLifecycleLabel(s.lifecycle_state)}</Badge>
            {s.current_phase && s.current_phase !== s.lifecycle_state ? (
              <span className={cx("min-w-0 truncate text-[10px]", live ? "text-primary/80" : "text-muted-foreground/70")}>
                {scanPhaseLabel(s.current_phase)}
              </span>
            ) : null}
          </div>
        );
      },
    },
    {
      key: "reporter",
      title: "Reporter / Target",
      render: (s) => (
        <div className="flex min-w-0 items-center gap-1.5">
          <span className="shrink-0 font-mono text-[10px] text-foreground">{s.reporter_agent_id || "—"}</span>
          <span className="min-w-0 truncate font-mono text-[10px] text-muted-foreground/70" title={s.target || ""}>
            {s.target || "—"}
          </span>
        </div>
      ),
    },
    {
      key: "trigger",
      title: "Trigger",
      render: (s) => (
        <span
          className={cx(
            "rounded border px-1 py-0.5 text-[10px] font-mono uppercase tracking-widest",
            s.trigger_source === "manual" ? "border-info/30 text-info/70" : "border-border/40 text-muted-foreground/50"
          )}
        >
          {scanTriggerLabel(s.trigger_source)}
        </span>
      ),
    },
    {
      key: "started",
      title: "Started",
      className: "font-mono text-[10px] text-muted-foreground",
      render: (s) => (
        <div className="flex items-center gap-1.5 whitespace-nowrap" title={fmtAbsoluteAndAge(s.started_at || s.queued_at)}>
          <span>{fmtWhen(s.started_at || s.queued_at)}</span>
          <span className="text-muted-foreground/60">{fmtAge(s.started_at || s.queued_at)}</span>
        </div>
      ),
    },
    {
      key: "duration",
      title: "Duration",
      className: "font-mono text-[10px]",
      render: (s) => {
        const live = isLiveScan(String(s.lifecycle_state || "").toLowerCase());
        const hasStaticDuration =
          (typeof s.duration_ms === "number" && Number.isFinite(s.duration_ms)) ||
          Boolean(s.started_at && s.finished_at);
        return live && !hasStaticDuration ? (
          <LiveElapsedText startIso={s.started_at ?? s.queued_at} endIso={s.finished_at} className="text-primary/90" />
        ) : hasStaticDuration ? (
          <span className="text-muted-foreground">
            {typeof s.duration_ms === "number" && Number.isFinite(s.duration_ms)
              ? fmtSec(s.duration_ms / 1000)
              : fmtSec(Math.max(0, (Date.parse(s.finished_at!) - Date.parse(s.started_at!)) / 1000))}
          </span>
        ) : live ? (
          <LiveElapsedText startIso={s.started_at ?? s.queued_at} endIso={null} className="text-primary/90" />
        ) : (
          <span className="text-muted-foreground">—</span>
        );
      },
    },
    {
      key: "findings",
      title: "Findings",
      className: "font-mono text-[10px] text-muted-foreground",
      render: (s) => (s.stats as any)?.findings_emitted ?? (s.stats as any)?.emitted_findings ?? "—",
    },
    {
      key: "actions",
      title: "",
      align: "right",
      render: (s) => (
        <Button
          variant="subtle"
          size="sm"
          onClick={(e) => {
            e.stopPropagation();
            onViewScan(s);
          }}
        >
          View
        </Button>
      ),
    },
  ];

  return (
    <div className="max-h-[280px] overflow-auto rounded-md border border-border bg-card">
      <Table
        className="!shadow-none !border-0 !bg-transparent !rounded-none"
        columns={columns}
        rows={visible}
        rowKey={(s) => String(s.id || s.scan_uuid)}
        rowClassName={(s) =>
          cx("cursor-pointer", isLiveScan(String(s.lifecycle_state || "").toLowerCase()) && "bg-primary/[0.04] hover:bg-primary/[0.08]")
        }
        onRowClick={(s) => onViewScan(s)}
      />
    </div>
  );
});

function ScanDurationCell({ scan, isLive }: { scan: VulnScan; isLive: boolean }) {
  const labelClass = cx(
    "font-mono text-[12px] font-semibold",
    isLive ? "text-primary" : "text-foreground"
  );

  if (typeof scan.duration_ms === "number" && Number.isFinite(scan.duration_ms)) {
    return <span className={labelClass}>{fmtSec(scan.duration_ms / 1000)}</span>;
  }
  if (scan.started_at && scan.finished_at) {
    const ms = Date.parse(scan.finished_at) - Date.parse(scan.started_at);
    return (
      <span className={labelClass}>
        {Number.isFinite(ms) ? fmtSec(Math.max(0, ms / 1000)) : "—"}
      </span>
    );
  }
  if (scan.started_at || scan.queued_at) {
    return (
      <LiveElapsedText
        startIso={scan.started_at ?? scan.queued_at}
        endIso={scan.finished_at}
        className={labelClass}
      />
    );
  }
  return <span className={labelClass}>—</span>;
}

function QueueWaitLabel({ scan }: { scan: VulnScan }) {
  if (!scan.queued_at) return <span>—</span>;
  const queuedAt = Date.parse(scan.queued_at);
  const dequeuedAt = Date.parse(
    scan.acknowledged_at || scan.started_at || scan.finished_at || ""
  );
  if (Number.isNaN(queuedAt) || Number.isNaN(dequeuedAt)) return <span>—</span>;
  return <span>{fmtSec(Math.max(0, (dequeuedAt - queuedAt) / 1000))}</span>;
}

export function ActiveScanPanel({
  activeScan,
  recentScans,
  agents,
  scanTargetAgent,
  onAgentChange,
  onRunScan,
  scanBusy,
  scanMsg,
  scanErr,
  recentScansBusy,
  onRefreshScans,
  onViewScan,
  onlySelectedAgent,
  onToggleAgentFilter,
}: {
  activeScan: VulnScan | null;
  recentScans: VulnScan[];
  agents: AgentPublic[];
  scanTargetAgent: string;
  onAgentChange: (id: string) => void;
  onRunScan: () => void;
  scanBusy: boolean;
  scanMsg: string | null;
  scanErr: string | null;
  recentScansBusy: boolean;
  onRefreshScans: () => void;
  onViewScan: (s: VulnScan) => void;
  onlySelectedAgent: boolean;
  onToggleAgentFilter: () => void;
}) {
  const scan = activeScan;
  const scanState = scan ? String(scan.lifecycle_state || "").toLowerCase() : "";
  const scanIsLive = scan ? isLiveScan(scanState) : false;
  const hasPhaseTimeline = scan && Object.keys(scan.phase_timestamps ?? {}).length > 0;
  const hasStats =
    scan &&
    Object.values(scan.stats ?? {}).some(
      (v) => typeof v === "number" && Number.isFinite(v as number)
    );

  return (
    <Card title="Scan execution" className="rounded-xl">
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <div className="space-y-4">
          <div className="space-y-2">
            <div className="text-xs text-muted-foreground">
              Select an agent and run an immediate vulnerability scan.
            </div>
            <SelectInput
              value={scanTargetAgent}
              onChange={(e) => onAgentChange(e.target.value)}
              className="w-full font-mono"
            >
              {agents.map((a) => (
                <option key={a.agent_id} value={a.agent_id}>
                  {a.agent_id}
                </option>
              ))}
            </SelectInput>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="primary"
              size="lg"
              onClick={onRunScan}
              disabled={scanBusy || !scanTargetAgent}
            >
              {scanBusy ? "Queueing…" : "Run Scan Now"}
            </Button>
            <Button
              variant="subtle"
              size="lg"
              onClick={onRefreshScans}
              disabled={recentScansBusy || (onlySelectedAgent && !scanTargetAgent)}
            >
              {recentScansBusy ? "Refreshing…" : "Refresh"}
            </Button>
          </div>

          {scanMsg ? <InlineAlert tone="success" className="text-xs">{scanMsg}</InlineAlert> : null}
          {scanErr ? <InlineAlert tone="danger" className="text-xs">{scanErr}</InlineAlert> : null}

          {scan ? (
            <div
              className={cx(
                "rounded-lg border p-3 space-y-3",
                scanIsLive
                  ? "border-primary/25 bg-primary/5"
                  : scan.lifecycle_state === "failed"
                  ? "border-danger/25 bg-danger/5"
                  : "border-border/50 bg-background/20"
              )}
            >
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <div className="flex items-center gap-2 flex-wrap">
                  <Badge variant={scanVariant(scanState)}>{scanLifecycleLabel(scan.lifecycle_state)}</Badge>
                  {scan.current_phase && scan.current_phase !== scan.lifecycle_state && (
                    <span className={cx(
                      "font-mono text-[11px]",
                      scanIsLive ? "text-primary/80" : "text-muted-foreground"
                    )}>
                      {scanPhaseLabel(scan.current_phase)}
                    </span>
                  )}
                  {scan.trigger_source && (
                    <span
                      className={cx(
                        "rounded border px-1.5 py-0.5 text-[10px] font-mono uppercase tracking-widest",
                        scan.trigger_source === "manual"
                          ? "border-info/30 text-info/70"
                          : "border-border/40 text-muted-foreground/50"
                      )}
                    >
                      {scanTriggerLabel(scan.trigger_source)}
                    </span>
                  )}
                </div>
                <Button variant="subtle" size="sm" onClick={() => onViewScan(scan)} className="flex-none">
                  Details
                </Button>
              </div>

              <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                <div className="rounded border border-border/40 bg-background/20 px-2.5 py-2">
                  <div className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground/70">
                    Reporter
                  </div>
                  <div className="mt-1 font-mono text-[11px] text-foreground">
                    {scan.reporter_agent_id || "—"}
                  </div>
                </div>
                <div className="rounded border border-border/40 bg-background/20 px-2.5 py-2">
                  <div className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground/70">
                    Target
                  </div>
                  <div
                    className="mt-1 truncate font-mono text-[11px] text-foreground"
                    title={scan.target || ""}
                  >
                    {scan.target || "—"}
                  </div>
                </div>
              </div>

              <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
                {scan.queued_at && (
                  <>
                    <dt className="text-[10px] text-muted-foreground/70 whitespace-nowrap">Queued</dt>
                    <dd className="font-mono text-[10px] text-muted-foreground">{fmtWhen(scan.queued_at)}</dd>
                  </>
                )}
                {scan.acknowledged_at && (
                  <>
                    <dt className="text-[10px] text-muted-foreground/70 whitespace-nowrap">Acknowledged</dt>
                    <dd className="font-mono text-[10px] text-muted-foreground">{fmtWhen(scan.acknowledged_at)}</dd>
                  </>
                )}
                {scan.started_at && (
                  <>
                    <dt className="text-[10px] text-muted-foreground/70 whitespace-nowrap">Started</dt>
                    <dd className="font-mono text-[10px] text-muted-foreground">{fmtWhen(scan.started_at)}</dd>
                  </>
                )}
                {scan.finished_at && (
                  <>
                    <dt className="text-[10px] text-muted-foreground/70 whitespace-nowrap">Finished</dt>
                    <dd className="font-mono text-[10px] text-muted-foreground">{fmtWhen(scan.finished_at)}</dd>
                  </>
                )}
                {scan.queued_at && (
                  <>
                    <dt className="text-[10px] text-muted-foreground/70 whitespace-nowrap">Queue wait</dt>
                    <dd className="font-mono text-[10px] text-muted-foreground">
                      <QueueWaitLabel scan={scan} />
                    </dd>
                  </>
                )}
                <dt className="text-[10px] text-muted-foreground/70 whitespace-nowrap">
                  {scanIsLive ? "Elapsed" : "Duration"}
                </dt>
                <dd>
                  <ScanDurationCell scan={scan} isLive={scanIsLive} />
                </dd>
                {scan.last_progress_at && (
                  <>
                    <dt className="text-[10px] text-muted-foreground/70 whitespace-nowrap">Last progress</dt>
                    <dd className="font-mono text-[10px] text-muted-foreground">
                      {fmtAbsoluteAndAge(scan.last_progress_at)}
                    </dd>
                  </>
                )}
              </dl>

              {scan.error_summary && (
                <div className="rounded border border-danger/30 bg-danger/10 px-2.5 py-1.5 text-[11px] text-danger">
                  {scan.error_summary}
                </div>
              )}

              {hasStats && <ScanStats stats={scan.stats} />}
            </div>
          ) : (
            <div className="rounded-lg border border-border/40 bg-background/20 px-3 py-6 text-center text-xs text-muted-foreground">
              No recent scan for this agent.
            </div>
          )}
        </div>

        <div className="space-y-4">
          {hasPhaseTimeline && scan && (
            <div>
              <div className="mb-1.5 text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                Phase timeline
              </div>
              <div className="rounded-lg border border-border/50 bg-background/20 p-2">
                <PhaseTimeline scan={scan} />
              </div>
            </div>
          )}

          <div>
            <div className="mb-1.5 flex items-center justify-between gap-2">
              <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                Recent scans
              </div>
              <Button
                variant={onlySelectedAgent ? "secondary" : "subtle"}
                size="sm"
                onClick={onToggleAgentFilter}
              >
                {onlySelectedAgent ? "Selected agent" : "All agents"}
              </Button>
            </div>
            <RecentScansTable
              scans={recentScans}
              scanTargetAgent={scanTargetAgent}
              onlySelectedAgent={onlySelectedAgent}
              onViewScan={onViewScan}
            />
          </div>
        </div>
      </div>
    </Card>
  );
}
