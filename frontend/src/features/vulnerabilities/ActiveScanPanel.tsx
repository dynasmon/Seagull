import { useEffect, useMemo, useState } from "react";

import { Badge } from "@/shared/components/Badge";
import { Card } from "@/shared/components/Card";
import { cx } from "@/shared/lib/cx";
import type { AgentPublic } from "@/features/agents/types";

import type { VulnScan } from "./types";

const PHASE_SEQ = [
  "queued",
  "acknowledged",
  "running",
  "collecting_inventory",
  "analyzing_exposure",
  "querying_source",
  "normalizing_findings",
  "ingesting_results",
  "completed",
  "failed",
  "cancelled",
];

const STAT_DISPLAY: Array<{ keys: string[]; label: string }> = [
  { keys: ["inventory_packages", "packages_collected"], label: "packages collected" },
  { keys: ["queried_packages", "packages_queried", "packages_analyzed"], label: "packages queried" },
  { keys: ["received_vulns", "vulnerabilities_matched", "vulns_matched"], label: "vulnerabilities matched" },
  { keys: ["emitted_findings", "findings_emitted"], label: "findings emitted" },
  { keys: ["stored_findings", "findings_stored"], label: "findings stored" },
  { keys: ["exposed_ports"], label: "exposed ports" },
  { keys: ["exposure_surface_score"], label: "exposure score" },
  { keys: ["errors_count", "error_count"], label: "errors" },
];

const KNOWN_STAT_KEYS = new Set(STAT_DISPLAY.flatMap((d) => d.keys));

function fmtSec(sec: number): string {
  if (!Number.isFinite(sec) || sec < 0) return "-";
  if (sec < 60) return `${Math.round(sec)}s`;
  const m = Math.floor(sec / 60);
  const r = Math.round(sec % 60);
  if (m < 60) return r ? `${m}m ${r}s` : `${m}m`;
  const h = Math.floor(m / 60);
  const mr = m % 60;
  return mr ? `${h}h ${mr}m` : `${h}h`;
}

function fmtWhen(iso?: string | null): string {
  if (!iso) return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString();
}

function fmtAge(iso?: string | null): string {
  if (!iso) return "-";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return String(iso);
  const delta = Date.now() - t;
  if (delta < 10_000) return "just now";
  const sec = Math.floor(delta / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  return `${Math.floor(hr / 24)}d ago`;
}

function fmtAbsoluteAndAge(iso?: string | null): string {
  if (!iso) return "-";
  return `${fmtWhen(iso)} · ${fmtAge(iso)}`;
}

function scanVariant(state: string): "info" | "neutral" | "critical" {
  const s = String(state || "").toLowerCase();
  if (s === "completed") return "neutral";
  if (s === "failed" || s === "cancelled") return "critical";
  return "info";
}

function isLiveScan(state: string): boolean {
  const s = String(state || "").toLowerCase();
  return s === "queued" || s === "acknowledged" || s === "running";
}

function useLiveElapsed(startIso: string | null | undefined, endIso: string | null | undefined): string {
  const active = Boolean(startIso && !endIso);
  const [, setTick] = useState(0);

  useEffect(() => {
    if (!active) return;
    const id = setInterval(() => setTick((n) => n + 1), 1000);
    return () => clearInterval(id);
  }, [active]);

  const start = Date.parse(startIso ?? "");
  if (Number.isNaN(start)) return "-";
  const end = endIso ? Date.parse(endIso) : Date.now();
  return fmtSec(Math.max(0, Math.floor((end - start) / 1000)));
}

export function ScanStats({ stats }: { stats: Record<string, any> }) {
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
    <div className="flex flex-wrap gap-1.5">
      {chips.map((x) => (
        <span
          key={x.key}
          className="inline-flex items-center gap-1.5 rounded border border-border/50 bg-background/40 px-2 py-0.5"
        >
          <span className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground/70">{x.label}</span>
          <span className="font-mono text-[11px] text-foreground">{x.value}</span>
        </span>
      ))}
    </div>
  );
}

export function PhaseTimeline({ scan }: { scan: VulnScan }) {
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
            {phase.replace(/_/g, " ")}
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
}

function RecentScansTable({
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

  return (
    <div className="max-h-[260px] overflow-auto rounded-lg border border-border/60 bg-background/20">
      <table className="w-full text-[11px]">
        <thead className="sticky top-0 bg-background/90 backdrop-blur">
          <tr className="border-b border-border/40 text-left text-muted-foreground/70">
            <th className="px-2 py-1.5 font-medium">Status</th>
            <th className="px-2 py-1.5 font-medium">Reporter / Target</th>
            <th className="px-2 py-1.5 font-medium">Trigger</th>
            <th className="px-2 py-1.5 font-medium">Started</th>
            <th className="px-2 py-1.5 font-medium">Duration</th>
            <th className="px-2 py-1.5 font-medium">Findings</th>
            <th className="px-2 py-1.5" />
          </tr>
        </thead>
        <tbody>
          {visible.map((s) => {
            const state = String(s.lifecycle_state || "").toLowerCase();
            const live = isLiveScan(state);
            const durMs =
              typeof s.duration_ms === "number" && Number.isFinite(s.duration_ms)
                ? s.duration_ms
                : s.started_at && s.finished_at
                ? Date.parse(s.finished_at) - Date.parse(s.started_at)
                : null;

            return (
              <tr
                key={s.id || s.scan_uuid}
                className="border-b border-border/20 hover:bg-muted/15 cursor-pointer"
                onClick={() => onViewScan(s)}
              >
                <td className="px-2 py-1.5">
                  <div className="flex flex-col gap-0.5">
                    <Badge variant={scanVariant(state)}>{s.lifecycle_state}</Badge>
                    {s.current_phase && s.current_phase !== s.lifecycle_state ? (
                      <span className="text-[10px] text-muted-foreground/70">
                        {s.current_phase.replace(/_/g, " ")}
                      </span>
                    ) : null}
                  </div>
                </td>
                <td className="px-2 py-1.5">
                  <div className="flex flex-col gap-0.5">
                    <span className="font-mono text-[10px] text-foreground">{s.reporter_agent_id || "—"}</span>
                    <span className="truncate font-mono text-[10px] text-muted-foreground/70" title={s.target || ""}>
                      {s.target || "—"}
                    </span>
                  </div>
                </td>
                <td className="px-2 py-1.5">
                  <span
                    className={cx(
                      "rounded border px-1 py-0.5 text-[10px] font-mono uppercase tracking-widest",
                      s.trigger_source === "manual"
                        ? "border-info/30 text-info/70"
                        : "border-border/40 text-muted-foreground/50"
                    )}
                  >
                    {s.trigger_source || "—"}
                  </span>
                </td>
                <td
                  className="px-2 py-1.5 font-mono text-[10px] text-muted-foreground"
                  title={fmtAbsoluteAndAge(s.started_at || s.queued_at)}
                >
                  <div>{fmtWhen(s.started_at || s.queued_at)}</div>
                  <div className="text-muted-foreground/60">{fmtAge(s.started_at || s.queued_at)}</div>
                </td>
                <td className="px-2 py-1.5 font-mono text-[10px] text-muted-foreground">
                  {durMs !== null && Number.isFinite(durMs)
                    ? fmtSec(Math.max(0, durMs / 1000))
                    : live
                    ? "running…"
                    : "—"}
                </td>
                <td className="px-2 py-1.5 font-mono text-[10px] text-muted-foreground">
                  {(s.stats as any)?.findings_emitted ??
                    (s.stats as any)?.emitted_findings ??
                    "—"}
                </td>
                <td className="px-2 py-1.5 text-right">
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      onViewScan(s);
                    }}
                    className="rounded border border-border/60 bg-background/40 px-1.5 py-0.5 text-[10px] font-mono uppercase tracking-widest text-muted-foreground hover:bg-muted/15"
                  >
                    View
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
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

  const elapsed = useLiveElapsed(
    scan?.started_at ?? scan?.queued_at ?? null,
    scan?.finished_at ?? null
  );

  const durationLabel = (() => {
    if (!scan) return "—";
    if (typeof scan.duration_ms === "number" && Number.isFinite(scan.duration_ms)) {
      return fmtSec(scan.duration_ms / 1000);
    }
    if (scan.started_at && scan.finished_at) {
      const ms = Date.parse(scan.finished_at) - Date.parse(scan.started_at);
      return Number.isFinite(ms) ? fmtSec(Math.max(0, ms / 1000)) : "—";
    }
    if (scan.started_at || scan.queued_at) return elapsed;
    return "—";
  })();
  const queueWaitLabel = (() => {
    if (!scan?.queued_at) return "—";
    const queuedAt = Date.parse(scan.queued_at);
    const dequeuedAt = Date.parse(scan.acknowledged_at || scan.started_at || scan.finished_at || "");
    if (Number.isNaN(queuedAt) || Number.isNaN(dequeuedAt)) return "—";
    return fmtSec(Math.max(0, (dequeuedAt - queuedAt) / 1000));
  })();

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
            <select
              value={scanTargetAgent}
              onChange={(e) => onAgentChange(e.target.value)}
              className={cx(
                "w-full rounded-md border border-border/60 bg-background/40 px-3 py-2",
                "text-sm font-mono outline-none focus:ring-2 focus:ring-primary/30"
              )}
            >
              {agents.map((a) => (
                <option key={a.agent_id} value={a.agent_id}>
                  {a.agent_id}
                </option>
              ))}
            </select>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={onRunScan}
              disabled={scanBusy || !scanTargetAgent}
              className={cx(
                "inline-flex h-9 items-center rounded-md border border-border/60 bg-background/40",
                "px-4 text-xs font-mono uppercase tracking-widest text-muted-foreground",
                "hover:bg-muted/15 hover:text-foreground focus:outline-none focus:ring-2 focus:ring-primary/30",
                (scanBusy || !scanTargetAgent) && "opacity-50 cursor-not-allowed"
              )}
            >
              {scanBusy ? "Queueing…" : "Run Scan Now"}
            </button>
            <button
              type="button"
              onClick={onRefreshScans}
              disabled={recentScansBusy || (onlySelectedAgent && !scanTargetAgent)}
              className={cx(
                "inline-flex h-9 items-center rounded-md border border-border/60 bg-background/40",
                "px-4 text-xs font-mono uppercase tracking-widest text-muted-foreground",
                "hover:bg-muted/15 hover:text-foreground focus:outline-none focus:ring-2 focus:ring-primary/30",
                (recentScansBusy || (onlySelectedAgent && !scanTargetAgent)) && "opacity-50 cursor-not-allowed"
              )}
            >
              {recentScansBusy ? "Refreshing…" : "Refresh"}
            </button>
          </div>

          {scanMsg ? <div className="text-xs text-emerald-300">{scanMsg}</div> : null}
          {scanErr ? <div className="text-xs text-red-300">{scanErr}</div> : null}

          {scan ? (
            <div
              className={cx(
                "rounded-lg border p-3 space-y-3",
                scanIsLive
                  ? "border-primary/25 bg-primary/5"
                  : scan.lifecycle_state === "failed"
                  ? "border-red-500/25 bg-red-500/5"
                  : "border-border/50 bg-background/20"
              )}
            >
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <div className="flex items-center gap-2 flex-wrap">
                  <Badge variant={scanVariant(scanState)}>{scan.lifecycle_state}</Badge>
                  {scan.current_phase && scan.current_phase !== scan.lifecycle_state && (
                    <span className="font-mono text-[11px] text-muted-foreground">
                      {scan.current_phase.replace(/_/g, " ")}
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
                      {scan.trigger_source}
                    </span>
                  )}
                </div>
                <button
                  type="button"
                  onClick={() => onViewScan(scan)}
                  className="rounded border border-border/60 bg-background/40 px-2 py-1 text-[10px] font-mono uppercase tracking-widest text-muted-foreground hover:bg-muted/15 flex-none"
                >
                  Details
                </button>
              </div>

              <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                <div className="rounded border border-border/40 bg-background/20 px-2.5 py-2">
                  <div className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground/70">Reporter</div>
                  <div className="mt-1 font-mono text-[11px] text-foreground">{scan.reporter_agent_id || "—"}</div>
                </div>
                <div className="rounded border border-border/40 bg-background/20 px-2.5 py-2">
                  <div className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground/70">Target</div>
                  <div className="mt-1 truncate font-mono text-[11px] text-foreground" title={scan.target || ""}>
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
                    <dd className="font-mono text-[10px] text-muted-foreground">{queueWaitLabel}</dd>
                  </>
                )}
                <dt className="text-[10px] text-muted-foreground/70 whitespace-nowrap">
                  {scanIsLive ? "Elapsed" : "Duration"}
                </dt>
                <dd
                  className={cx(
                    "font-mono text-[12px] font-semibold",
                    scanIsLive ? "text-primary" : "text-foreground"
                  )}
                >
                  {durationLabel}
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
                <div className="rounded border border-red-500/30 bg-red-500/10 px-2.5 py-1.5 text-[11px] text-red-200">
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
              <button
                type="button"
                onClick={onToggleAgentFilter}
                className={cx(
                  "rounded border border-border/50 bg-background/40 px-2 py-0.5",
                  "text-[10px] font-mono uppercase tracking-widest",
                  onlySelectedAgent ? "text-foreground" : "text-muted-foreground",
                  "hover:bg-muted/15 hover:text-foreground"
                )}
              >
                {onlySelectedAgent ? "Selected agent" : "All agents"}
              </button>
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
