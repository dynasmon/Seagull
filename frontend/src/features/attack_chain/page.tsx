import type { CSSProperties, ReactNode } from "react";
import { useEffect, useMemo, useRef, useState } from "react";

import PageHeader from "@/shared/components/PageHeader";
import Loading from "@/shared/components/Loading";
import EmptyState from "@/shared/components/EmptyState";
import { Badge } from "@/shared/components/Badge";
import { cx } from "@/shared/lib/cx";

import { listAgents } from "@/features/agents/api";
import type { AgentPublic } from "@/features/agents/types";

import AttackChainDrawer from "./AttackChainDrawer";
import { listAttackChainCases } from "./api";
import { stageLabel } from "./stages";
import type { AttackChainCase } from "./types";
import { loadWorkflow } from "./workflow";

type Density = "comfortable" | "compact";
type SincePreset = "any" | "15m" | "1h" | "6h" | "24h" | "7d" | "custom";

function Panel(props: {
  title: string;
  right?: ReactNode;
  children: ReactNode;
  style?: CSSProperties;
  scrollY?: boolean;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <div
      className={cx(
        "rounded-xl border border-border/60 bg-background/70 backdrop-blur-md flex flex-col min-h-0",
        props.className
      )}
    >
      <div className="flex items-center justify-between px-4 py-3 border-b border-border/60 bg-muted/10">
        <div className="text-sm font-semibold tracking-tight truncate">{props.title}</div>
        {props.right ? <div className="text-xs text-muted-foreground truncate">{props.right}</div> : null}
      </div>

      <div
        className={cx("p-4 min-h-0", props.scrollY && "overflow-y-auto", props.bodyClassName)}
        style={props.style}
      >
        {props.children}
      </div>
    </div>
  );
}

function fmtTs(iso: string) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd} ${hh}:${mi}:${ss}`;
}

function scoreVariant(score: number) {
  // Backend defaults to 0..100.
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  if (score > 0) return "low";
  return "neutral";
}

function statusVariant(status: string) {
  const s = String(status || "").toLowerCase();
  if (s === "open") return "info";
  if (s === "closed") return "neutral";
  return "neutral";
}

function computeSinceIso(preset: SincePreset, customLocal: string): string | undefined {
  if (preset === "any") return undefined;
  if (preset === "custom") {
    const v = customLocal.trim();
    if (!v) return undefined;
    const d = new Date(v);
    if (Number.isNaN(d.getTime())) return undefined;
    return d.toISOString();
  }

  const now = Date.now();
  const deltas: Record<Exclude<SincePreset, "any" | "custom">, number> = {
    "15m": 15 * 60 * 1000,
    "1h": 60 * 60 * 1000,
    "6h": 6 * 60 * 60 * 1000,
    "24h": 24 * 60 * 60 * 1000,
    "7d": 7 * 24 * 60 * 60 * 1000
  };
  const ms = deltas[preset as Exclude<SincePreset, "any" | "custom">];
  return new Date(now - ms).toISOString();
}

type DraftFilters = {
  agentId: string;
  status: "all" | "open" | "closed";
  suspectIp: string;
  minScore: string;
  density: Density;
  sincePreset: SincePreset;
  sinceCustomLocal: string;
  showWorkflow: boolean;
};

type AppliedFilters = {
  agentId?: string;
  status?: "all" | "open" | "closed";
  suspectIp?: string;
  minScore?: number;
  since?: string;
  density: Density;
  showWorkflow: boolean;
};

export default function AttackChainPage() {
  const [agents, setAgents] = useState<AgentPublic[]>([]);
  const [agentsLoading, setAgentsLoading] = useState(false);

  const [draft, setDraft] = useState<DraftFilters>({
    agentId: "",
    status: "open",
    suspectIp: "",
    minScore: "",
    density: "comfortable",
    sincePreset: "24h",
    sinceCustomLocal: "",
    showWorkflow: true
  });

  const [applied, setApplied] = useState<AppliedFilters>({
    agentId: "",
    status: "open",
    suspectIp: "",
    minScore: undefined,
    since: computeSinceIso("24h", ""),
    density: "comfortable",
    showWorkflow: true
  });

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rows, setRows] = useState<AttackChainCase[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(false);

  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const reqSeq = useRef(0);

  // Load agent list once for filters.
  useEffect(() => {
    setAgentsLoading(true);
    listAgents()
      .then((a) => setAgents(a || []))
      .catch(() => setAgents([]))
      .finally(() => setAgentsLoading(false));
  }, []);

  const appliedSummary = useMemo(() => {
    const bits: string[] = [];
    if (applied.status && applied.status !== "all") bits.push(applied.status);
    if (applied.agentId) bits.push(`agent=${applied.agentId}`);
    if (applied.suspectIp) bits.push(`ip=${applied.suspectIp}`);
    if (typeof applied.minScore === "number") bits.push(`min_score=${applied.minScore}`);
    if (applied.since) bits.push(`since=${applied.since}`);
    return bits.length ? bits.join(" · ") : "no filters";
  }, [applied]);

  async function fetchFirstPage(filters: AppliedFilters) {
    const mySeq = ++reqSeq.current;
    setLoading(true);
    setError(null);

    try {
      const out = await listAttackChainCases({
        page_size: 50,
        cursor: null,
        agent_id: filters.agentId || undefined,
        status: filters.status || "open",
        suspect_ip: filters.suspectIp || undefined,
        min_score: typeof filters.minScore === "number" ? filters.minScore : undefined,
        since: filters.since
      });
      if (reqSeq.current !== mySeq) return;
      setRows(out.items || []);
      setNextCursor(out.next_cursor);
      setHasMore(Boolean(out.has_more));
      setLastRefresh(new Date());

      // keep selection only if still present
      setSelectedId((prev) => {
        if (prev === null) return null;
        return (out.items || []).some((x) => x.id === prev) ? prev : null;
      });
    } catch (e: any) {
      if (reqSeq.current !== mySeq) return;
      setError(e?.message || "Failed to load attack chain cases");
      setRows([]);
      setNextCursor(null);
      setHasMore(false);
      setSelectedId(null);
      setDrawerOpen(false);
    } finally {
      if (reqSeq.current !== mySeq) return;
      setLoading(false);
    }
  }

  async function fetchMore() {
    if (!nextCursor) return;
    const mySeq = ++reqSeq.current;
    setLoading(true);
    setError(null);
    try {
      const out = await listAttackChainCases({
        page_size: 50,
        cursor: nextCursor,
        agent_id: applied.agentId || undefined,
        status: applied.status || "open",
        suspect_ip: applied.suspectIp || undefined,
        min_score: typeof applied.minScore === "number" ? applied.minScore : undefined,
        since: applied.since
      });
      if (reqSeq.current !== mySeq) return;
      setRows((prev) => [...prev, ...(out.items || [])]);
      setNextCursor(out.next_cursor);
      setHasMore(Boolean(out.has_more));
      setLastRefresh(new Date());
    } catch (e: any) {
      if (reqSeq.current !== mySeq) return;
      setError(e?.message || "Failed to load more cases");
    } finally {
      if (reqSeq.current !== mySeq) return;
      setLoading(false);
    }
  }

  function applyFilters() {
    const minScoreNum = Number(draft.minScore);
    const minScore = Number.isFinite(minScoreNum) && minScoreNum >= 0 ? minScoreNum : undefined;
    const since = computeSinceIso(draft.sincePreset, draft.sinceCustomLocal);

    const next: AppliedFilters = {
      agentId: draft.agentId || "",
      status: draft.status,
      suspectIp: draft.suspectIp.trim(),
      minScore,
      since,
      density: draft.density,
      showWorkflow: draft.showWorkflow
    };
    setApplied(next);
    fetchFirstPage(next);
  }

  useEffect(() => {
    // initial load
    fetchFirstPage(applied);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function openCase(id: number) {
    setSelectedId(id);
    setDrawerOpen(true);
  }

  const density = applied.density;
  const dense = density === "compact";

  const workflowCache = useMemo(() => {
    if (!applied.showWorkflow) return new Map<number, { triage: string; assignee: string; notes: number; priority: string }>();
    const m = new Map<number, { triage: string; assignee: string; notes: number; priority: string }>();
    for (const r of rows) {
      const wf = loadWorkflow(r.id);
      m.set(r.id, { triage: wf.triage, assignee: wf.assignee, notes: wf.notes.length, priority: wf.priority });
    }
    return m;
  }, [rows, applied.showWorkflow]);

  return (
    <div className="p-6">
      <PageHeader
        title="Attack Chains"
        breadcrumb={["Detection", "Attack Chains"]}
        description={
          <span className="text-muted-foreground">
            ATT&CK-aligned chains built from correlated telemetry. Use as an analyst-friendly timeline and investigation case.
          </span>
        }
        toolbarRight={
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => fetchFirstPage(applied)}
              className={cx(
                "rounded-md border border-border/60 bg-background/40",
                "px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground",
                "hover:bg-muted/15 hover:text-foreground"
              )}
            >
              Refresh
            </button>
            {lastRefresh ? (
              <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                {fmtTs(lastRefresh.toISOString())}
              </div>
            ) : null}
          </div>
        }
      />

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4 min-h-[calc(100vh-220px)]">
        <Panel
          title="Controls"
          right={agentsLoading ? "loading agents" : `${agents.length} agents`}
          className="xl:col-span-4"
          scrollY
        >
          <div className="space-y-4">
            <div className="rounded-xl border border-border/60 bg-background/30 p-4">
              <div className="text-sm font-semibold">Filter scope</div>
              <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Status</div>
                  <select
                    className="mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm"
                    value={draft.status}
                    onChange={(e) => setDraft((p) => ({ ...p, status: e.target.value as any }))}
                  >
                    <option value="open">Open</option>
                    <option value="closed">Closed</option>
                    <option value="all">All</option>
                  </select>
                </div>

                <div>
                  <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Agent</div>
                  <select
                    className="mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm"
                    value={draft.agentId}
                    onChange={(e) => setDraft((p) => ({ ...p, agentId: e.target.value }))}
                  >
                    <option value="">All agents</option>
                    {agents.map((a) => (
                      <option key={a.agent_id} value={a.agent_id}>
                        {a.display_name
                          ? `${a.display_name} · ${a.agent_id}`
                          : (a.metadata as any)?.hostname
                            ? `${String((a.metadata as any).hostname)} · ${a.agent_id}`
                            : a.agent_id}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Suspect IP</div>
                  <input
                    value={draft.suspectIp}
                    onChange={(e) => setDraft((p) => ({ ...p, suspectIp: e.target.value }))}
                    placeholder="e.g. 203.0.113.10"
                    className="mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm font-mono"
                  />
                </div>

                <div>
                  <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Min score</div>
                  <input
                    value={draft.minScore}
                    onChange={(e) => setDraft((p) => ({ ...p, minScore: e.target.value }))}
                    placeholder="0"
                    inputMode="numeric"
                    className="mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm font-mono"
                  />
                </div>
              </div>

              <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Since</div>
                  <select
                    className="mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm"
                    value={draft.sincePreset}
                    onChange={(e) => setDraft((p) => ({ ...p, sincePreset: e.target.value as SincePreset }))}
                  >
                    <option value="any">Any time</option>
                    <option value="15m">Last 15 minutes</option>
                    <option value="1h">Last 1 hour</option>
                    <option value="6h">Last 6 hours</option>
                    <option value="24h">Last 24 hours</option>
                    <option value="7d">Last 7 days</option>
                    <option value="custom">Custom…</option>
                  </select>

                  {draft.sincePreset === "custom" ? (
                    <input
                      value={draft.sinceCustomLocal}
                      onChange={(e) => setDraft((p) => ({ ...p, sinceCustomLocal: e.target.value }))}
                      type="datetime-local"
                      className="mt-2 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm font-mono"
                    />
                  ) : null}
                </div>

                <div>
                  <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Density</div>
                  <select
                    className="mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm"
                    value={draft.density}
                    onChange={(e) => setDraft((p) => ({ ...p, density: e.target.value as Density }))}
                  >
                    <option value="comfortable">Comfortable</option>
                    <option value="compact">Compact</option>
                  </select>

                  <label className="mt-3 flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={draft.showWorkflow}
                      onChange={(e) => setDraft((p) => ({ ...p, showWorkflow: e.target.checked }))}
                    />
                    <span className="text-muted-foreground">Show investigation workflow</span>
                  </label>
                </div>
              </div>

              <div className="mt-4 flex items-center justify-between gap-3">
                <div className="text-[11px] text-muted-foreground">Applied: {appliedSummary}</div>
                <button
                  type="button"
                  onClick={applyFilters}
                  className={cx(
                    "rounded-md border border-border/60 bg-background/40",
                    "px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground",
                    "hover:bg-muted/15 hover:text-foreground"
                  )}
                >
                  Apply & refresh
                </button>
              </div>
            </div>

            <div className="rounded-xl border border-border/60 bg-background/30 p-4">
              <div className="text-sm font-semibold">How to use</div>
              <ul className="mt-2 space-y-2 text-sm text-muted-foreground">
                <li>• Start with <span className="text-foreground">Open</span> cases, sorted by <span className="text-foreground">last seen</span>.</li>
                <li>• Use <span className="text-foreground">since</span> to scope recent campaigns.</li>
                <li>• Open a case to see a stage-by-stage timeline and capture analyst notes.</li>
                <li>• Close is enforced by backend admin role.</li>
              </ul>
            </div>
          </div>
        </Panel>

        <Panel
          title="Cases"
          right={`${rows.length} loaded${hasMore ? " · more available" : ""}`}
          className="xl:col-span-8"
          scrollY
        >
          {loading ? <Loading label="Loading cases" /> : null}
          {!loading && error ? <EmptyState title="FAILED" hint={error} /> : null}

          {!loading && !error && rows.length === 0 ? (
            <EmptyState title="NO CASES" hint="No attack chains matched your filters." />
          ) : null}

          {!error && rows.length > 0 ? (
            <div className="w-full overflow-auto">
              <table className="w-full text-sm">
                <thead className="sticky top-0 bg-background/60 backdrop-blur z-10">
                  <tr className="border-b border-border/60 text-muted-foreground">
                    <th className="text-left font-medium px-3 py-2 w-[110px]">Status</th>
                    <th className="text-left font-medium px-3 py-2 w-[110px]">Score</th>
                    <th className="text-left font-medium px-3 py-2 w-[220px]">Stage</th>
                    <th className="text-left font-medium px-3 py-2 w-[260px]">Suspect</th>
                    <th className="text-left font-medium px-3 py-2 w-[220px]">Last seen</th>
                    {applied.showWorkflow ? (
                      <th className="text-left font-medium px-3 py-2 w-[220px]">Workflow</th>
                    ) : null}
                    <th className="text-right font-medium px-3 py-2 w-[120px]">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => {
                    const selected = selectedId !== null && r.id === selectedId;
                    const wf = applied.showWorkflow ? workflowCache.get(r.id) : null;
                    return (
                      <tr
                        key={r.id}
                        className={cx("border-b border-border/40 hover:bg-muted/30", selected && "bg-muted/40")}
                        onClick={() => openCase(r.id)}
                        role="button"
                        tabIndex={0}
                      >
                        <td className={cx("px-3", dense ? "py-1.5" : "py-2")}
                        >
                          <Badge variant={statusVariant(r.status)}>{r.status}</Badge>
                        </td>
                        <td className={cx("px-3", dense ? "py-1.5" : "py-2")}
                        >
                          <Badge variant={scoreVariant(r.score)}>{r.score}</Badge>
                        </td>
                        <td className={cx("px-3", dense ? "py-1.5" : "py-2")}
                        >
                          <div className="text-sm font-semibold truncate">{stageLabel(r.max_stage)}</div>
                          <div className="text-[11px] text-muted-foreground">{r.step_count} steps · agent {r.agent_id}</div>
                        </td>
                        <td className={cx("px-3", dense ? "py-1.5" : "py-2")}
                        >
                          <div className="font-mono text-[12px] truncate" title={r.suspect_ip || ""}>
                            {r.suspect_ip || "-"}
                          </div>
                        </td>
                        <td className={cx("px-3 font-mono text-[12px]", dense ? "py-1.5" : "py-2")}
                        >
                          {fmtTs(r.last_seen_at)}
                        </td>

                        {applied.showWorkflow ? (
                          <td className={cx("px-3", dense ? "py-1.5" : "py-2")}
                          >
                            {wf ? (
                              <div className="flex items-center gap-2 flex-wrap">
                                <Badge variant="neutral">{wf.triage}</Badge>
                                <Badge variant="neutral">{wf.priority}</Badge>
                                {wf.assignee ? <Badge variant="neutral">{wf.assignee}</Badge> : null}
                                {wf.notes ? <span className="text-[11px] text-muted-foreground">notes {wf.notes}</span> : null}
                              </div>
                            ) : (
                              <span className="text-muted-foreground">-</span>
                            )}
                          </td>
                        ) : null}

                        <td className={cx("px-3 text-right", dense ? "py-1.5" : "py-2")}>
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              openCase(r.id);
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
            </div>
          ) : null}

          {!loading && !error && hasMore ? (
            <div className="mt-4 flex justify-center">
              <button
                type="button"
                onClick={fetchMore}
                className={cx(
                  "rounded-md border border-border/60 bg-background/40",
                  "px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground",
                  "hover:bg-muted/15 hover:text-foreground"
                )}
              >
                Load more
              </button>
            </div>
          ) : null}
        </Panel>
      </div>

      <AttackChainDrawer
        open={drawerOpen}
        caseId={selectedId}
        onClose={() => setDrawerOpen(false)}
        onClosed={(id) => {
          // update list item status on close (optimistic)
          setRows((prev) => prev.map((r) => (r.id === id ? { ...r, status: "closed" } : r)));
        }}
      />
    </div>
  );
}
