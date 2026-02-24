import { useEffect, useMemo, useRef, useState } from "react";

import { Badge } from "@/shared/components/Badge";
import { Card } from "@/shared/components/Card";
import DraftNumberInput from "@/shared/components/DraftNumberInput";
import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import PageHeader from "@/shared/components/PageHeader";
import { cx } from "@/shared/lib/cx";

import { useAuth } from "@/features/auth/context";

import { getVulnFindingsPage, getVulnSummary } from "./api";
import VulnFindingDrawer from "./VulnFindingDrawer";
import type { VulnFinding, VulnSummary } from "./types";

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

export default function VulnerabilitiesPage() {
  const { user } = useAuth();
  const isAdmin = (user?.role || "").toLowerCase() === "admin";

  const [summary, setSummary] = useState<VulnSummary | null>(null);
  const [summaryBusy, setSummaryBusy] = useState(false);

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
    loadPage({ reset: true, cursor: null });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAdmin]);

  useEffect(() => {
    if (!isAdmin) return;
    loadSummary();
    loadPage({ reset: true, cursor: null });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filters, pageSize]);

  useEffect(() => {
    if (!isAdmin) return;
    loadSummary();
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
    <div className="p-6 space-y-6">
      <PageHeader
        title="Vulnerabilities"
        breadcrumb={["Detection", "Vulnerabilities"]}
        description="Triage vulnerability findings reported by agents."
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
          <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
            {items.length} items
          </span>
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
            <EmptyState title="No findings" description="Try widening the time window or adjusting filters." />
          </div>
        ) : (
          <div className="w-full overflow-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-background/60 backdrop-blur z-10">
                <tr className="border-b border-border/60 text-muted-foreground">
                  <th className="text-left font-medium px-3 py-2 w-[120px]">Severity</th>
                  <th className="text-left font-medium px-3 py-2">Title</th>
                  <th className="text-left font-medium px-3 py-2 w-[190px]">Asset</th>
                  <th className="text-left font-medium px-3 py-2 w-[140px]">Status</th>
                  <th className="text-left font-medium px-3 py-2 w-[150px]">Last seen</th>
                  <th className="text-left font-medium px-3 py-2 w-[110px]">Hits</th>
                  <th className="text-right font-medium px-3 py-2 w-[120px]">Actions</th>
                </tr>
              </thead>

              <tbody>
                {items.map((f) => {
                  const selectedRow = selected?.id === f.id;
                  const rowPad = dense ? "py-1.5" : "py-2";
                  return (
                    <tr
                      key={f.id}
                      className={cx(
                        "border-b border-border/40 hover:bg-muted/30",
                        selectedRow && "bg-muted/40"
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
                          {f.location || f.external_id || f.source}
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
        }}
      />
    </div>
  );
}
