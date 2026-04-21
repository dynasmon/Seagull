import { useMemo } from "react";

import Drawer from "@/shared/components/Drawer";
import { Badge } from "@/shared/components/Badge";
import { Card } from "@/shared/components/Card";
import { cx } from "@/shared/lib/cx";

import type { VulnScan } from "./types";

function safeJson(v: any): string {
  try {
    return JSON.stringify(v ?? null, null, 2);
  } catch {
    return String(v);
  }
}

function fmtWhen(iso?: string | null): string {
  if (!iso) return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString();
}

function fmtSeconds(sec: number): string {
  if (!Number.isFinite(sec) || sec < 0) return "-";
  if (sec < 60) return `${Math.round(sec)}s`;
  const m = Math.floor(sec / 60);
  const r = Math.round(sec % 60);
  if (m < 60) return r ? `${m}m ${r}s` : `${m}m`;
  const h = Math.floor(m / 60);
  const mr = m % 60;
  return mr ? `${h}h ${mr}m` : `${h}h`;
}

function lifecycleVariant(state: string) {
  const s = String(state || "").toLowerCase();
  if (s === "completed") return "neutral";
  if (s === "failed" || s === "cancelled") return "critical";
  return "info";
}

function pickStatChips(stats: Record<string, any>): Array<{ k: string; v: string }> {
  const out: Array<{ k: string; v: string }> = [];
  for (const k of Object.keys(stats || {})) {
    const v = (stats as any)[k];
    if (typeof v === "number" && Number.isFinite(v)) out.push({ k, v: String(v) });
    if (typeof v === "string" && v.length <= 18) out.push({ k, v });
  }
  out.sort((a, b) => a.k.localeCompare(b.k));
  return out.slice(0, 8);
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
  const duration = useMemo(() => {
    if (!scan) return null;
    if (typeof scan.duration_ms === "number" && Number.isFinite(scan.duration_ms)) {
      return Math.max(0, scan.duration_ms / 1000);
    }
    const start = Date.parse(scan.started_at || "");
    const end = scan.finished_at ? Date.parse(scan.finished_at) : Date.now();
    if (Number.isNaN(start) || Number.isNaN(end)) return null;
    return Math.max(0, (end - start) / 1000);
  }, [scan]);

  const statChips = useMemo(() => {
    if (!scan) return [];
    return pickStatChips(scan.stats || {});
  }, [scan]);

  if (!scan) return null;

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title={`Scan #${scan.id}`}
      description={`${scan.tool}${scan.tool_version ? ` v${scan.tool_version}` : ""} • ${scan.scan_uuid}`}
      widthClassName="w-[900px]"
    >
      <div className="space-y-4">
        <Card title="Overview" className="rounded-xl">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <div>
              <div className="text-xs text-muted-foreground">Lifecycle</div>
              <div className="mt-1 flex flex-wrap items-center gap-2">
                <Badge variant={lifecycleVariant(scan.lifecycle_state)}>{scan.lifecycle_state}</Badge>
                <Badge variant="neutral">{scan.current_phase}</Badge>
                <span className="text-xs text-muted-foreground font-mono">
                  duration {duration === null ? "-" : fmtSeconds(duration)}
                </span>
              </div>
            </div>

            <div>
              <div className="text-xs text-muted-foreground">Trigger</div>
              <div className="mt-1 font-mono text-sm">{scan.trigger_source}</div>
            </div>

            <div>
              <div className="text-xs text-muted-foreground">Reporter</div>
              <div className="mt-1 font-mono text-sm">{scan.reporter_agent_id || "-"}</div>
            </div>

            <div>
              <div className="text-xs text-muted-foreground">Target</div>
              <div className="mt-1 font-mono text-sm truncate" title={scan.target || ""}>
                {scan.target || "-"}
              </div>
              <div className="mt-1 text-xs text-muted-foreground">
                profile {(scan.config as any)?.analysis_profile || (scan.scope as any)?.analysis_profile || "-"}
              </div>
            </div>
          </div>

          <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2">
            <div className="space-y-1 text-sm text-muted-foreground">
              <div>queued {fmtWhen(scan.queued_at)}</div>
              <div>acknowledged {fmtWhen(scan.acknowledged_at)}</div>
              <div>started {fmtWhen(scan.started_at)}</div>
            </div>
            <div className="space-y-1 text-sm text-muted-foreground">
              <div>last progress {fmtWhen(scan.last_progress_at)}</div>
              <div>finished {fmtWhen(scan.finished_at)}</div>
              <div>exposure score {(scan.stats as any)?.exposure_surface_score ?? "-"}</div>
            </div>
          </div>

          {scan.error_summary ? (
            <div className="mt-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-200">
              {scan.error_summary}
            </div>
          ) : null}

          {statChips.length ? (
            <div className="mt-4 flex flex-wrap gap-2">
              {statChips.map((x) => (
                <span
                  key={x.k}
                  className={cx(
                    "inline-flex items-center gap-2 rounded-md border border-border/60 bg-background/40",
                    "px-2 py-1"
                  )}
                >
                  <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{x.k}</span>
                  <span className="font-mono text-[12px]">{x.v}</span>
                </span>
              ))}
            </div>
          ) : null}
        </Card>

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
          <Card title="Phase Timestamps" className="rounded-xl lg:col-span-1">
            <pre className="text-xs whitespace-pre-wrap break-words text-muted-foreground">
              {safeJson(scan.phase_timestamps)}
            </pre>
          </Card>
          <Card title="Scope" className="rounded-xl lg:col-span-1">
            <pre className="text-xs whitespace-pre-wrap break-words text-muted-foreground">{safeJson(scan.scope)}</pre>
          </Card>
          <Card title="Config" className="rounded-xl lg:col-span-1">
            <pre className="text-xs whitespace-pre-wrap break-words text-muted-foreground">{safeJson(scan.config)}</pre>
          </Card>
          <Card title="Stats" className="rounded-xl lg:col-span-1">
            <pre className="text-xs whitespace-pre-wrap break-words text-muted-foreground">{safeJson(scan.stats)}</pre>
          </Card>
        </div>

        <Card title="Raw" right="copy" className="rounded-xl">
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
          <pre className="text-xs whitespace-pre-wrap break-words text-muted-foreground">{safeJson(scan)}</pre>
        </Card>
      </div>
    </Drawer>
  );
}
