import { useEffect, useMemo, useRef, useState } from "react";

import { Badge } from "@/shared/components/Badge";
import { Card } from "@/shared/components/Card";
import DraftNumberInput from "@/shared/components/DraftNumberInput";
import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import PageHeader from "@/shared/components/PageHeader";
import { cx } from "@/shared/lib/cx";

import { useAuth } from "@/features/auth/context";
import { listAgents } from "@/features/agents/api";
import type { AgentPublic } from "@/features/agents/types";

import { getVulnFindingsPage, getVulnPosture, getVulnScansPage, getVulnSummary, triggerVulnScanNow } from "./api";
import VulnFindingDrawer from "./VulnFindingDrawer";
import type { VulnFinding, VulnPosture, VulnScan, VulnSummary } from "./types";

type Density = "comfortable" | "compact";

type Filters = {
  q: string;
  minSeverity: string;
  status: string;
  reporterAgentId: string;
  assetAgentId: string;
  cve: string;
  includeSuppressed: boolean;
};

function sevVariant(sev: string) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "neutral";
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
  const day = Math.floor(hr / 24);
  return `${day}d ago`;
}

function prettyAssetLabel(f: VulnFinding): string {
  if (f.asset_agent_id) return `agent:${f.asset_agent_id}`;
  if (f.asset_key) return f.asset_key;
  if (f.target) return f.target;
  return "-";
}

function fmtRisk(n: number | null | undefined): string {
  const v = Number(n || 0);
  if (!Number.isFinite(v)) return "0.0";
  return v.toFixed(1);
}

function exposureScoreOf(f: VulnFinding): number {
  const a = Number((f.evidence as any)?.analysis?.exposure_score);
  if (Number.isFinite(a)) return a;
  const b = Number((f.asset as any)?.exposure?.surface_score);
  if (Number.isFinite(b)) return b;
  return 0;
}

function serviceHintsOf(f: VulnFinding): string[] {
  const fromAsset = (f.asset as any)?.exposure?.service_hints;
  if (Array.isArray(fromAsset)) return fromAsset.map((x) => String(x || "").trim()).filter(Boolean);
  const fromEvidence = (f.evidence as any)?.exposure?.service_hints;
  if (Array.isArray(fromEvidence)) return fromEvidence.map((x) => String(x || "").trim()).filter(Boolean);
  return [];
}

function scanDurationLabel(s: VulnScan): string {
  const start = Date.parse(s.started_at || "");
  const end = Date.parse(s.finished_at || "");
  if (Number.isNaN(start)) return "-";
  if (Number.isNaN(end)) return s.status === "running" ? "running" : "-";
  const sec = Math.max(0, Math.round((end - start) / 1000));
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60);
  const r = sec % 60;
  return r ? `${m}m ${r}s` : `${m}m`;
}

function Toggle({
  value,
  onChange,
  label,
}: {
  value: boolean;
  onChange: (next: boolean) => void;
  label: string;
}) {
  return (
    <button
      type="button"
      onClick={() => onChange(!value)}
      className={cx(
        "inline-flex items-center gap-2 rounded-md border border-border/60 bg-background/40",
        "px-3 py-2 text-xs font-mono uppercase tracking-widest",
        value ? "text-foreground" : "text-muted-foreground",
        "hover:bg-muted/15 hover:text-foreground focus:outline-none focus:ring-2 focus:ring-primary/30"
      )}
      title={label}
    >
      <span className={cx("h-2.5 w-2.5 rounded-full", value ? "bg-primary" : "bg-muted-foreground/50")} />
      {label}
    </button>
  );
}

function scanStatusHint(status: string): string {
  const s = String(status || "").toLowerCase();
  if (s === "queued") return "queued";
  if (s === "running" || s === "started") return "running";
  if (s === "finished" || s === "done" || s === "completed") return "completed";
  if (s === "failed" || s === "error") return "failed";
  return s || "-";
}

export default function VulnerabilitiesPage() {
  const { user } = useAuth();
  const isAdmin = (user?.role || "").toLowerCase() === "admin";

  const [summary, setSummary] = useState<VulnSummary | null>(null);
  const [summaryBusy, setSummaryBusy] = useState(false);
  const [posture, setPosture] = useState<VulnPosture | null>(null);
  const [postureBusy, setPostureBusy] = useState(false);

  const [items, setItems] = useState<VulnFinding[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(false);

  const [busy, setBusy] = useState(false);
  const [busyMore, setBusyMore] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [density, setDensity] = useState<Density>("comfortable");
  const [pageSize, setPageSize] = useState<number>(50);
  const [activeDays, setActiveDays] = useState<number>(30);

  const [draft, setDraft] = useState<Filters>({
    q: "",
    minSeverity: "all",
    status: "all",
    reporterAgentId: "",
    assetAgentId: "",
    cve: "",
    includeSuppressed: false,
  });

  const [filters, setFilters] = useState<Filters>(draft);

  const [selected, setSelected] = useState<VulnFinding | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [agents, setAgents] = useState<AgentPublic[]>([]);
  const [scanTargetAgent, setScanTargetAgent] = useState<string>("");
  const [scanBusy, setScanBusy] = useState(false);
  const [scanMsg, setScanMsg] = useState<string | null>(null);
  const [scanErr, setScanErr] = useState<string | null>(null);
  const [recentScans, setRecentScans] = useState<VulnScan[]>([]);
  const [recentScansBusy, setRecentScansBusy] = useState(false);
  const [onlySelectedAgentScans, setOnlySelectedAgentScans] = useState(true);

  const reqSeq = useRef(0);
  const itemsRef = useRef<VulnFinding[]>([]);

  useEffect(() => {
    itemsRef.current = items;
  }, [items]);

  async function loadSummary(params?: { includeSuppressed?: boolean }) {
    if (!isAdmin) return;
    setSummaryBusy(true);
    try {
      const out = await getVulnSummary({
        active_within_days: activeDays,
        include_suppressed: params?.includeSuppressed ?? filters.includeSuppressed,
      });
      setSummary(out);
    } catch {
      // Summary is best-effort. Keep the rest of the page functional.
      setSummary(null);
    } finally {
      setSummaryBusy(false);
    }
  }

  async function loadPosture(params?: { includeSuppressed?: boolean }) {
    if (!isAdmin) return;
    setPostureBusy(true);
    try {
      const out = await getVulnPosture({
        active_within_days: activeDays,
        include_suppressed: params?.includeSuppressed ?? filters.includeSuppressed,
        top_n: 15,
      });
      setPosture(out);
    } catch {
      setPosture(null);
    } finally {
      setPostureBusy(false);
    }
  }

  async function loadPage(opts: { reset: boolean; cursor?: string | null }) {
    if (!isAdmin) return;

    const mySeq = ++reqSeq.current;
    if (opts.reset) {
      setBusy(true);
      setError(null);
    } else {
      setBusyMore(true);
      setError(null);
    }

    try {
      const out = await getVulnFindingsPage({
        page_size: pageSize,
        cursor: opts.cursor ?? null,
        q: (filters.q || "").trim() || undefined,
        min_severity: filters.minSeverity !== "all" ? filters.minSeverity : undefined,
        status: filters.status !== "all" ? filters.status : undefined,
        reporter_agent_id: (filters.reporterAgentId || "").trim() || undefined,
        asset_agent_id: (filters.assetAgentId || "").trim() || undefined,
        cve: (filters.cve || "").trim() || undefined,
        include_suppressed: filters.includeSuppressed,
      });

      if (reqSeq.current !== mySeq) return;

      const nextItems = opts.reset ? (out.items || []) : [...itemsRef.current, ...(out.items || [])];
      setItems(nextItems);
      setCursor(out.next_cursor);
      setHasMore(Boolean(out.has_more));

      // Keep selection only if still present.
      setSelected((prev) => {
        if (!prev) return null;
        return nextItems.find((x) => x.id === prev.id) || null;
      });
    } catch (e: any) {
      if (reqSeq.current !== mySeq) return;
      setError(e?.message || "Failed to load findings");
      if (opts.reset) {
        setItems([]);
        setCursor(null);
        setHasMore(false);
        setSelected(null);
        setDrawerOpen(false);
      }
    } finally {
      if (reqSeq.current !== mySeq) return;
      setBusy(false);
      setBusyMore(false);
    }
  }

  function applyFilters() {
    setFilters(draft);
  }

  function resetFilters() {
    const base: Filters = {
      q: "",
      minSeverity: "all",
      status: "all",
      reporterAgentId: "",
      assetAgentId: "",
      cve: "",
      includeSuppressed: false,
    };
    setDraft(base);
    setFilters(base);
  }

  useEffect(() => {
    if (!isAdmin) return;
    loadSummary();
    loadPosture();
    loadPage({ reset: true, cursor: null });
    listAgents()
      .then((rows) => {
        const pick = (rows || []).filter((a) => !a.is_revoked);
        pick.sort((a, b) => a.agent_id.localeCompare(b.agent_id));
        setAgents(pick);
        const preferred =
          pick.find((a) => a.agent_id.includes("vuln"))?.agent_id ||
          pick[0]?.agent_id ||
          "";
        setScanTargetAgent(preferred);
        if (preferred) {
          getVulnScansPage({ page_size: 8, reporter_agent_id: preferred }).then((x) => setRecentScans(x.items || []));
        }
      })
      .catch(() => setAgents([]));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAdmin]);

  async function runManualScan() {
    if (!scanTargetAgent || scanBusy) return;
    setScanBusy(true);
    setScanErr(null);
    setScanMsg(null);
    try {
      const out = await triggerVulnScanNow(scanTargetAgent);
      setScanMsg(`Scan queued (${out.status}) for ${out.agent_id} at ${fmtWhen(out.queued_at)} · id ${out.scan_uuid}`);
      loadPage({ reset: true, cursor: null });
      loadRecentScans(scanTargetAgent);
    } catch (e: any) {
      setScanErr(e?.message || "Failed to trigger manual scan");
    } finally {
      setScanBusy(false);
    }
  }

  async function loadRecentScans(agentId: string) {
    if (!agentId) {
      setRecentScans([]);
      return;
    }
    setRecentScansBusy(true);
    try {
      const out = await getVulnScansPage({ page_size: 8, reporter_agent_id: agentId });
      setRecentScans(out.items || []);
    } catch {
      setRecentScans([]);
    } finally {
      setRecentScansBusy(false);
    }
  }

  useEffect(() => {
    if (!isAdmin || !scanTargetAgent) return;
    loadRecentScans(scanTargetAgent);
  }, [isAdmin, scanTargetAgent]);

  useEffect(() => {
    if (!isAdmin || !scanTargetAgent) return;
    const t = window.setInterval(() => {
      loadRecentScans(scanTargetAgent);
    }, 10000);
    return () => window.clearInterval(t);
  }, [isAdmin, scanTargetAgent]);

  useEffect(() => {
    if (!isAdmin) return;
    loadSummary();
    loadPosture();
    loadPage({ reset: true, cursor: null });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filters, pageSize]);

  useEffect(() => {
    if (!isAdmin) return;
    loadSummary();
    loadPosture();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeDays]);

  const severityBlocks = useMemo(() => {
    const m = summary?.by_severity || {};
    const order = ["critical", "high", "medium", "low", "unknown"];
    const out = order
      .filter((k) => Object.prototype.hasOwnProperty.call(m, k))
      .map((k) => ({ k, v: Number(m[k] || 0) }));

    // Include any unexpected severities at the end.
    Object.keys(m)
      .filter((k) => !order.includes(k))
      .sort()
      .forEach((k) => out.push({ k, v: Number(m[k] || 0) }));

    return out;
  }, [summary]);

  const dense = density === "compact";
  const visibleRecentScans = useMemo(
    () =>
      (recentScans || []).filter((s) =>
        onlySelectedAgentScans ? (s.reporter_agent_id || "") === (scanTargetAgent || "") : true
      ),
    [recentScans, onlySelectedAgentScans, scanTargetAgent]
  );
  const activeFilterCount = useMemo(() => {
    let n = 0;
    if ((filters.q || "").trim()) n++;
    if (filters.minSeverity !== "all") n++;
    if (filters.status !== "all") n++;
    if ((filters.reporterAgentId || "").trim()) n++;
    if ((filters.assetAgentId || "").trim()) n++;
    if ((filters.cve || "").trim()) n++;
    if (filters.includeSuppressed) n++;
    return n;
  }, [filters]);
  const findingsHint = useMemo(() => {
    const scans = visibleRecentScans;
    const hasRunning = scans.some((s) => {
      const st = String(s.status || "").toLowerCase();
      return st === "queued" || st === "running" || st === "started";
    });
    const hasCompleted = scans.some((s) => {
      const st = String(s.status || "").toLowerCase();
      return st === "finished" || st === "done" || st === "completed";
    });
    const totalEmitted = scans.reduce((acc, s) => {
      const v = Number((s.stats as any)?.emitted_findings || 0);
      return acc + (Number.isFinite(v) ? v : 0);
    }, 0);
    if (activeFilterCount > 0) {
      return `No findings match the current filters (${activeFilterCount} active).`;
    }
    if (hasRunning) {
      return "A scan is running/queued. Wait a few seconds and refresh.";
    }
    if (hasCompleted && totalEmitted === 0) {
      return "Completed scans reported no vulnerability findings.";
    }
    if (!scans.length) {
      return "No recent scans for this agent yet.";
    }
    return "No persisted findings for the recent scans yet.";
  }, [visibleRecentScans, activeFilterCount]);

  if (!isAdmin) {
    return (
      <div className="p-6">
        <EmptyState
          title="Admin permissions required"
          description="Vulnerability findings are restricted to administrators."
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Vulnerabilities"
        breadcrumb={["Detection", "Vulnerabilities"]}
        description="Triage vulnerability findings reported by agents."
        tabs={[
          { label: "Findings", to: "/vulnerabilities" },
          { label: "Scans", to: "/vulnerabilities/scans" },
        ]}
        toolbarRight={
          <div className="flex flex-wrap items-center gap-2">
            <Toggle
              value={density === "compact"}
              onChange={(v) => setDensity(v ? "compact" : "comfortable")}
              label={density === "compact" ? "Compact" : "Comfortable"}
            />

            <button
              type="button"
              onClick={() => {
                loadSummary();
                loadPosture();
                loadPage({ reset: true, cursor: null });
              }}
              className={cx(
                "inline-flex items-center rounded-md border border-border/60 bg-background/40",
                "px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground",
                "hover:bg-muted/15 hover:text-foreground focus:outline-none focus:ring-2 focus:ring-primary/30"
              )}
              disabled={busy}
              title="Refresh"
            >
              {busy ? "Refreshing…" : "Refresh"}
            </button>
          </div>
        }
      />

      {/* Summary */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        <Card title="Open" right={summaryBusy ? "loading" : undefined} className="rounded-xl">
          <div className="text-3xl font-semibold">{summary?.total_open ?? "-"}</div>
          <div className="mt-1 text-xs text-muted-foreground">active within {activeDays}d</div>
        </Card>

        <Card title="Suppressed" right={summaryBusy ? "loading" : undefined} className="rounded-xl">
          <div className="text-3xl font-semibold">{summary?.total_suppressed ?? "-"}</div>
          <div className="mt-1 text-xs text-muted-foreground">excluded by default</div>
        </Card>

        <Card title="Severity" right={summaryBusy ? "loading" : undefined} className="rounded-xl lg:col-span-2">
          <div className="flex flex-wrap gap-2">
            {severityBlocks.length ? (
              severityBlocks.map((x) => (
                <span key={x.k} className="inline-flex items-center gap-2 rounded-md border border-border/60 bg-background/40 px-2 py-1">
                  <Badge variant={sevVariant(x.k)}>{x.k}</Badge>
                  <span className="font-mono text-[12px]">{x.v}</span>
                </span>
              ))
            ) : (
              <span className="text-sm text-muted-foreground">-</span>
            )}
          </div>

          <div className="mt-4 flex items-center gap-3">
            <span className="text-xs text-muted-foreground">Window (days)</span>
            <DraftNumberInput
              value={activeDays}
              onCommit={(n) => setActiveDays(n)}
              min={1}
              max={365}
              className={cx(
                "w-24 rounded-md border border-border/60 bg-background/40 px-2 py-1",
                "text-sm font-mono text-foreground outline-none",
                "focus:ring-2 focus:ring-primary/30"
              )}
            />
          </div>
        </Card>
      </div>

      <Card title="Quick Guide" className="rounded-xl">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4 text-xs text-muted-foreground">
          <div className="rounded-md border border-border/50 bg-background/30 p-3">
            <div className="font-mono uppercase tracking-widest text-[10px] mb-1">Open / Suppressed</div>
            <div>
              `Open` are active vulnerabilities. `Suppressed` are hidden from default triage.
            </div>
          </div>
          <div className="rounded-md border border-border/50 bg-background/30 p-3">
            <div className="font-mono uppercase tracking-widest text-[10px] mb-1">Risk Score</div>
            <div>
              Prioritizes severity, confidence, recurrence, and exploitation/exposure signals.
            </div>
          </div>
          <div className="rounded-md border border-border/50 bg-background/30 p-3">
            <div className="font-mono uppercase tracking-widest text-[10px] mb-1">Exposure Score</div>
            <div>
              Measures host exposure surface (detected ports/services). Higher means more urgent.
            </div>
          </div>
          <div className="rounded-md border border-border/50 bg-background/30 p-3">
            <div className="font-mono uppercase tracking-widest text-[10px] mb-1">Manual Scan</div>
            <div>
              After triggering, scan status moves from `queued` to `running` and then `finished`/`failed`.
            </div>
          </div>
        </div>
      </Card>

      {/* Risk posture */}
      <Card title="Manual scan" className="rounded-xl">
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          <div className="space-y-3">
            <div className="text-xs text-muted-foreground">Run an immediate vulnerability scan.</div>
            <select
              value={scanTargetAgent}
              onChange={(e) => setScanTargetAgent(e.target.value)}
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
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={runManualScan}
                disabled={scanBusy || !scanTargetAgent}
                className={cx(
                  "inline-flex h-10 items-center rounded-md border border-border/60 bg-background/40",
                  "px-4 text-xs font-mono uppercase tracking-widest text-muted-foreground",
                  "hover:bg-muted/15 hover:text-foreground focus:outline-none focus:ring-2 focus:ring-primary/30",
                  (scanBusy || !scanTargetAgent) && "opacity-60"
                )}
              >
                {scanBusy ? "Queueing…" : "Run Scan Now"}
              </button>
              <button
                type="button"
                onClick={() => loadRecentScans(scanTargetAgent)}
                disabled={recentScansBusy || !scanTargetAgent}
                className={cx(
                  "inline-flex h-10 items-center rounded-md border border-border/60 bg-background/40",
                  "px-4 text-xs font-mono uppercase tracking-widest text-muted-foreground",
                  "hover:bg-muted/15 hover:text-foreground focus:outline-none focus:ring-2 focus:ring-primary/30",
                  (recentScansBusy || !scanTargetAgent) && "opacity-60"
                )}
              >
                {recentScansBusy ? "Refreshing…" : "Refresh status"}
              </button>
            </div>
            {scanMsg ? <div className="text-xs text-emerald-300">{scanMsg}</div> : null}
            {scanErr ? <div className="text-xs text-red-300">{scanErr}</div> : null}
          </div>

          <div className="rounded-lg border border-border/60 bg-background/30 p-3">
            <div className="mb-2 flex items-center justify-between gap-2">
              <div className="text-xs font-mono uppercase tracking-widest text-muted-foreground">Recent scans ({scanTargetAgent || "-"})</div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setOnlySelectedAgentScans((v) => !v)}
                  className={cx(
                    "rounded-md border border-border/60 bg-background/40 px-2 py-1",
                    "text-[10px] font-mono uppercase tracking-widest",
                    onlySelectedAgentScans ? "text-foreground" : "text-muted-foreground",
                    "hover:bg-muted/15 hover:text-foreground"
                  )}
                >
                  {onlySelectedAgentScans ? "Only selected agent" : "All agents"}
                </button>
                <div className="text-[11px] text-muted-foreground">{visibleRecentScans.length} items</div>
              </div>
            </div>
            {!visibleRecentScans.length ? (
              <div className="text-xs text-muted-foreground">No recent scans for this agent.</div>
            ) : (
              <div className="max-h-[220px] overflow-auto">
                <table className="w-full text-[12px]">
                  <thead className="text-left text-muted-foreground">
                    <tr className="border-b border-border/40">
                      <th className="px-2 py-1">Agent</th>
                      <th className="px-2 py-1">Status</th>
                      <th className="px-2 py-1">Started</th>
                      <th className="px-2 py-1">Duration</th>
                      <th className="px-2 py-1">Findings</th>
                      <th className="px-2 py-1">Exposure</th>
                    </tr>
                  </thead>
                  <tbody>
                    {visibleRecentScans.map((s) => (
                      <tr key={s.id} className="border-b border-border/20 align-top">
                        <td className="px-2 py-1">
                          <span
                            className={cx(
                              "font-mono text-[11px]",
                              s.reporter_agent_id === scanTargetAgent ? "text-foreground" : "text-muted-foreground"
                            )}
                            title={s.reporter_agent_id || "-"}
                          >
                            {s.reporter_agent_id || "-"}
                          </span>
                        </td>
                        <td className="px-2 py-1">
                          <Badge variant={s.status === "finished" ? "neutral" : s.status === "failed" ? "critical" : "info"}>
                            {s.status}
                          </Badge>
                          <div className="mt-1 text-[10px] text-muted-foreground">{scanStatusHint(s.status)}</div>
                        </td>
                        <td className="px-2 py-1 font-mono text-[11px]">{fmtAge(s.started_at)}</td>
                        <td className="px-2 py-1 font-mono text-[11px]">{scanDurationLabel(s)}</td>
                        <td className="px-2 py-1 font-mono">{(s.stats as any)?.emitted_findings ?? "-"}</td>
                        <td className="px-2 py-1 font-mono">{(s.stats as any)?.exposure_surface_score ?? "-"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-5">
        <Card title="Mean risk score" right={postureBusy ? "loading" : undefined} className="rounded-xl">
          <div className="text-3xl font-semibold">{posture ? fmtRisk(posture.mean_risk) : "-"}</div>
          <div className="mt-1 text-xs text-muted-foreground">p95: {posture ? fmtRisk(posture.p95_risk) : "-"}</div>
        </Card>

        <Card title="Critical/High" right={postureBusy ? "loading" : undefined} className="rounded-xl">
          <div className="text-3xl font-semibold">
            {posture ? posture.critical_open + posture.high_open : "-"}
          </div>
          <div className="mt-1 text-xs text-muted-foreground">
            critical {posture?.critical_open ?? "-"} · high {posture?.high_open ?? "-"}
          </div>
        </Card>

        <Card title="Exploitable likely" right={postureBusy ? "loading" : undefined} className="rounded-xl">
          <div className="text-3xl font-semibold">{posture?.exploitable_open ?? "-"}</div>
          <div className="mt-1 text-xs text-muted-foreground">CVE/CVSS/network exposure heuristics</div>
        </Card>

        <Card title="Fix available" right={postureBusy ? "loading" : undefined} className="rounded-xl">
          <div className="text-3xl font-semibold">{posture?.fixable_open ?? "-"}</div>
          <div className="mt-1 text-xs text-muted-foreground">remediation text or OSV fixed version</div>
        </Card>

        <Card title="Stale open (>30d)" right={postureBusy ? "loading" : undefined} className="rounded-xl">
          <div className="text-3xl font-semibold">{posture?.stale_open ?? "-"}</div>
          <div className="mt-1 text-xs text-muted-foreground">needs ownership/escalation</div>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card
          title="Top risky findings"
          right={<span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{posture?.top_risks?.length ?? 0} items</span>}
          className="rounded-xl"
        >
          {!posture || posture.top_risks.length === 0 ? (
            <EmptyState title="No prioritized findings" description="No open findings in the selected window." />
          ) : (
            <div className="w-full overflow-auto">
              <table className="w-full text-sm">
                <thead className="sticky top-0 bg-background/60 backdrop-blur z-10">
                  <tr className="border-b border-border/60 text-muted-foreground">
                    <th className="text-left font-medium px-3 py-2 w-[86px]">Risk</th>
                    <th className="text-left font-medium px-3 py-2">Finding</th>
                    <th className="text-left font-medium px-3 py-2 w-[160px]">Asset</th>
                    <th className="text-left font-medium px-3 py-2 w-[110px]">Fix</th>
                  </tr>
                </thead>
                <tbody>
                  {posture.top_risks.map((x) => (
                    <tr
                      key={x.id}
                      className="border-b border-border/40 hover:bg-muted/30 cursor-pointer"
                      onClick={() => {
                        const row = items.find((it) => it.id === x.id);
                        if (row) {
                          setSelected(row);
                          setDrawerOpen(true);
                        }
                      }}
                    >
                      <td className="px-3 py-2 font-mono text-[12px]">
                        <span className={cx("inline-flex rounded-md border px-2 py-0.5", Number(x.risk_score) >= 80 ? "border-red-500/50 text-red-300" : Number(x.risk_score) >= 65 ? "border-orange-500/50 text-orange-300" : "border-border/60 text-foreground")}>
                          {fmtRisk(x.risk_score)}
                        </span>
                      </td>
                      <td className="px-3 py-2">
                        <div className="font-mono text-[12px] truncate" title={x.title}>
                          {x.cve ? `${x.cve} — ${x.title}` : x.title}
                        </div>
                        <div className="text-[11px] text-muted-foreground">
                          <Badge variant={sevVariant(x.severity)}>{x.severity}</Badge>
                          <span className="ml-2">conf {x.confidence}</span>
                          {x.internet_exposed ? <span className="ml-2">AV:N</span> : null}
                        </div>
                      </td>
                      <td className="px-3 py-2 font-mono text-[12px] truncate" title={x.asset_key}>{x.asset_agent_id ? `agent:${x.asset_agent_id}` : x.asset_key}</td>
                      <td className="px-3 py-2 text-[11px]">{x.has_fix ? "available" : "unknown"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        <Card
          title="Most exposed assets"
          right={<span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{posture?.top_assets?.length ?? 0} assets</span>}
          className="rounded-xl"
        >
          {!posture || posture.top_assets.length === 0 ? (
            <EmptyState title="No exposed assets" description="No asset-level risk found in the selected window." />
          ) : (
            <div className="space-y-2">
              {posture.top_assets.map((a) => (
                <div key={`${a.asset_key}-${a.asset_agent_id || "-"}`} className="rounded-lg border border-border/60 bg-background/40 p-3">
                  <div className="flex items-center justify-between gap-3">
                    <div className="font-mono text-[12px] truncate" title={a.asset_agent_id ? `agent:${a.asset_agent_id}` : a.asset_key}>
                      {a.asset_agent_id ? `agent:${a.asset_agent_id}` : a.asset_key}
                    </div>
                    <div className="font-mono text-[12px] text-muted-foreground">max {fmtRisk(a.max_risk)}</div>
                  </div>
                  <div className="mt-1 text-[11px] text-muted-foreground">
                    open {a.open_findings} · critical/high {a.critical_high} · avg {fmtRisk(a.avg_risk)} · seen {fmtAge(a.last_seen_at)}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      {/* Filters */}
      <Card
        title="Filters"
        right={
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={resetFilters}
              className={cx(
                "rounded-md border border-border/60 bg-background/40 px-3 py-2",
                "text-[10px] font-mono uppercase tracking-widest text-muted-foreground",
                "hover:bg-muted/15 hover:text-foreground focus:outline-none focus:ring-2 focus:ring-primary/30"
              )}
            >
              Reset
            </button>
            <button
              type="button"
              onClick={applyFilters}
              className={cx(
                "rounded-md border border-border/60 bg-background/40 px-3 py-2",
                "text-[10px] font-mono uppercase tracking-widest text-muted-foreground",
                "hover:bg-muted/15 hover:text-foreground focus:outline-none focus:ring-2 focus:ring-primary/30"
              )}
            >
              Apply
            </button>
          </div>
        }
        className="rounded-xl"
      >
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-4">
          <div>
            <div className="text-xs text-muted-foreground">Search</div>
            <input
              value={draft.q}
              onChange={(e) => setDraft((p) => ({ ...p, q: e.target.value }))}
              placeholder="title / cve / external_id"
              className={cx(
                "mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2",
                "text-sm outline-none focus:ring-2 focus:ring-primary/30"
              )}
            />
          </div>

          <div>
            <div className="text-xs text-muted-foreground">Min severity</div>
            <select
              value={draft.minSeverity}
              onChange={(e) => setDraft((p) => ({ ...p, minSeverity: e.target.value }))}
              className={cx(
                "mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2",
                "text-sm outline-none focus:ring-2 focus:ring-primary/30"
              )}
            >
              <option value="all">All</option>
              <option value="low">Low+</option>
              <option value="medium">Medium+</option>
              <option value="high">High+</option>
              <option value="critical">Critical</option>
            </select>
          </div>

          <div>
            <div className="text-xs text-muted-foreground">Status</div>
            <select
              value={draft.status}
              onChange={(e) => setDraft((p) => ({ ...p, status: e.target.value }))}
              className={cx(
                "mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2",
                "text-sm outline-none focus:ring-2 focus:ring-primary/30"
              )}
            >
              <option value="all">All</option>
              <option value="open">Open</option>
              <option value="fixed">Fixed</option>
              <option value="resolved">Resolved</option>
              <option value="ignored">Ignored</option>
            </select>
          </div>

          <div>
            <div className="text-xs text-muted-foreground">CVE</div>
            <input
              value={draft.cve}
              onChange={(e) => setDraft((p) => ({ ...p, cve: e.target.value }))}
              placeholder="CVE-2024-1234"
              className={cx(
                "mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2",
                "text-sm font-mono outline-none focus:ring-2 focus:ring-primary/30"
              )}
            />
          </div>

          <div>
            <div className="text-xs text-muted-foreground">Reporter agent</div>
            <input
              value={draft.reporterAgentId}
              onChange={(e) => setDraft((p) => ({ ...p, reporterAgentId: e.target.value }))}
              placeholder="agent-id"
              className={cx(
                "mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2",
                "text-sm font-mono outline-none focus:ring-2 focus:ring-primary/30"
              )}
            />
          </div>

          <div>
            <div className="text-xs text-muted-foreground">Asset agent</div>
            <input
              value={draft.assetAgentId}
              onChange={(e) => setDraft((p) => ({ ...p, assetAgentId: e.target.value }))}
              placeholder="agent-id"
              className={cx(
                "mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2",
                "text-sm font-mono outline-none focus:ring-2 focus:ring-primary/30"
              )}
            />
          </div>

          <div className="flex items-end">
            <Toggle
              value={draft.includeSuppressed}
              onChange={(v) => setDraft((p) => ({ ...p, includeSuppressed: v }))}
              label={draft.includeSuppressed ? "Including suppressed" : "Exclude suppressed"}
            />
          </div>

          <div className="flex items-end gap-2">
            <span className="text-xs text-muted-foreground">Page size</span>
            <DraftNumberInput
              value={pageSize}
              onCommit={(n) => setPageSize(n)}
              min={1}
              max={200}
              className={cx(
                "w-24 rounded-md border border-border/60 bg-background/40 px-2 py-2",
                "text-sm font-mono text-foreground outline-none",
                "focus:ring-2 focus:ring-primary/30"
              )}
            />
          </div>
        </div>
      </Card>

      {/* Findings */}
      <Card
        title="Findings"
        right={
          <div className="flex items-center gap-3">
            <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
              {items.length} items
            </span>
            <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
              filters {activeFilterCount}
            </span>
          </div>
        }
        className="rounded-xl"
      >
        {busy ? (
          <div className="h-[360px]">
            <Loading label="Loading findings…" />
          </div>
        ) : error ? (
          <EmptyState title="Failed to load" description={error} />
        ) : items.length === 0 ? (
          <div className="h-[360px]">
            <div className="flex h-full flex-col items-center justify-center gap-3">
              <EmptyState title="No findings" description={findingsHint} />
              {activeFilterCount > 0 ? (
                <button
                  type="button"
                  onClick={resetFilters}
                  className={cx(
                    "rounded-md border border-border/60 bg-background/40 px-3 py-2",
                    "text-[10px] font-mono uppercase tracking-widest text-muted-foreground",
                    "hover:bg-muted/15 hover:text-foreground focus:outline-none focus:ring-2 focus:ring-primary/30"
                  )}
                >
                  Clear filters
                </button>
              ) : null}
            </div>
          </div>
        ) : (
          <div className="w-full overflow-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-background/60 backdrop-blur z-10">
                <tr className="border-b border-border/60 text-muted-foreground">
                  <th className="text-left font-medium px-3 py-2 w-[120px] whitespace-nowrap">Severity</th>
                  <th className="text-left font-medium px-3 py-2 min-w-[280px]">Title</th>
                  <th className="text-left font-medium px-3 py-2 w-[190px] whitespace-nowrap">Asset</th>
                  <th className="text-left font-medium px-3 py-2 w-[140px] whitespace-nowrap">Status</th>
                  <th className="text-left font-medium px-3 py-2 w-[170px] whitespace-nowrap">Exposure</th>
                  <th className="text-left font-medium px-3 py-2 w-[150px] whitespace-nowrap">Last seen</th>
                  <th className="text-left font-medium px-3 py-2 w-[110px] whitespace-nowrap">Hits</th>
                  <th className="text-right font-medium px-3 py-2 w-[120px] whitespace-nowrap">Actions</th>
                </tr>
              </thead>

              <tbody>
                {items.map((f) => {
                  const selectedRow = selected?.id === f.id;
                  const rowPad = dense ? "py-1.5" : "py-2";
                  const expScore = exposureScoreOf(f);
                  const svc = serviceHintsOf(f).slice(0, 2);
                  return (
                    <tr
                      key={f.id}
                      className={cx(
                        "border-b border-border/40 hover:bg-muted/30",
                        selectedRow && "bg-muted/40",
                        "align-top"
                      )}
                      onClick={() => {
                        setSelected(f);
                        setDrawerOpen(true);
                      }}
                      role="button"
                      tabIndex={0}
                    >
                      <td className={cx("px-3", rowPad)}>
                        <Badge variant={sevVariant(f.severity)}>{f.severity}</Badge>
                      </td>
                      <td className={cx("px-3", rowPad)}>
                        <div className="font-mono text-[12px] truncate" title={f.title}>
                          {f.cve ? `${f.cve} — ${f.title}` : f.title}
                        </div>
                        <div className="text-[11px] text-muted-foreground truncate">
                          {f.location || f.external_id || f.source} · conf {f.confidence}
                        </div>
                      </td>
                      <td className={cx("px-3", rowPad)}>
                        <div className="font-mono text-[12px] truncate" title={prettyAssetLabel(f)}>
                          {prettyAssetLabel(f)}
                        </div>
                        <div className="text-[11px] text-muted-foreground truncate">
                          {f.reporter_agent_id ? `reported by ${f.reporter_agent_id}` : "-"}
                        </div>
                      </td>
                      <td className={cx("px-3", rowPad)}>
                        <div className="flex flex-wrap items-center gap-2">
                          <Badge variant={f.status === "open" ? "info" : "neutral"}>{f.status}</Badge>
                          {f.is_suppressed ? <Badge variant="neutral">suppressed</Badge> : null}
                        </div>
                      </td>
                      <td className={cx("px-3", rowPad)}>
                        <div className="font-mono text-[12px]">
                          score {expScore}
                        </div>
                        <div className="text-[11px] text-muted-foreground truncate" title={svc.join(", ") || "-"}>
                          {svc.length ? svc.join(", ") : "-"}
                        </div>
                      </td>
                      <td className={cx("px-3 font-mono text-[12px]", rowPad)}>
                        <div title={fmtWhen(f.last_seen_at)}>{fmtAge(f.last_seen_at)}</div>
                      </td>
                      <td className={cx("px-3 font-mono text-[12px]", rowPad)}>{f.occurrences}</td>
                      <td className={cx("px-3 text-right", rowPad)}>
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelected(f);
                            setDrawerOpen(true);
                          }}
                          className={cx(
                            "inline-flex items-center gap-2 rounded-md border border-border/60 bg-background/40",
                            "px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground",
                            "hover:bg-muted/15 hover:text-foreground",
                            "focus:outline-none focus:ring-2 focus:ring-primary/30"
                          )}
                          title="Open drawer"
                        >
                          View
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>

            {hasMore ? (
              <div className="mt-4 flex justify-center">
                <button
                  type="button"
                  disabled={busyMore}
                  onClick={() => loadPage({ reset: false, cursor })}
                  className={cx(
                    "rounded-md border border-border/60 bg-background/40 px-4 py-2",
                    "text-xs font-mono uppercase tracking-widest text-muted-foreground",
                    "hover:bg-muted/15 hover:text-foreground",
                    "focus:outline-none focus:ring-2 focus:ring-primary/30",
                    busyMore && "opacity-60"
                  )}
                >
                  {busyMore ? "Loading…" : "Load more"}
                </button>
              </div>
            ) : null}
          </div>
        )}
      </Card>

      <VulnFindingDrawer
        open={drawerOpen}
        finding={selected}
        onClose={() => setDrawerOpen(false)}
        onPatched={(next) => {
          setSelected(next);
          setItems((prev) => prev.map((x) => (x.id === next.id ? next : x)));

          // If the user is excluding suppressed findings and this item was just suppressed,
          // remove it locally to match server behavior.
          if (!filters.includeSuppressed && next.is_suppressed) {
            setItems((prev) => prev.filter((x) => x.id !== next.id));
            setDrawerOpen(false);
          }

          loadSummary();
          loadPosture();
        }}
      />
    </div>
  );
}
