import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

import { Button } from "@/shared/components/Button";
import DetectionWorkflowRail from "@/shared/components/DetectionWorkflow";
import PageHeader from "@/shared/components/PageHeader";
import Loading from "@/shared/components/Loading";
import EmptyState from "@/shared/components/EmptyState";
import { DataPaginationFooter, DataQueryStateBanner, DataStatsStrip } from "@/shared/components/DataView";
import { Panel } from "@/shared/components/Panel";
import { SelectInput } from "@/shared/components/SelectInput";
import { SeverityPill } from "@/shared/components/SeverityPill";
import { StatusPill } from "@/shared/components/StatusPill";
import { TextInput } from "@/shared/components/TextInput";
import { cx } from "@/shared/lib/cx";

import { listAgents } from "@/features/agents/api";
import type { AgentPublic } from "@/features/agents/types";

import AttackChainDrawer from "./AttackChainDrawer";
import { listAttackChainCases } from "./api";
import { stageLabel } from "./stages";
import type { AttackChainCase } from "./types";

type Density = "comfortable" | "compact";
type SincePreset = "any" | "15m" | "1h" | "6h" | "24h" | "7d" | "custom";

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

function statusPillVariant(status: string) {
  const s = String(status || "").toLowerCase();
  if (s === "open") return "info" as const;
  if (s === "closed") return "inactive" as const;
  return "neutral" as const;
}

function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{children}</div>
  );
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

function parsePositiveInt(value: string | null): number | null {
  const raw = String(value || "").trim();
  if (!raw) return null;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return null;
  return Math.trunc(n);
}

type DraftFilters = {
  agentId: string;
  status: "all" | "open" | "closed";
  suspectIp: string;
  minScore: string;
  density: Density;
  sincePreset: SincePreset;
  sinceCustomLocal: string;
};

type AppliedFilters = {
  agentId?: string;
  status?: "all" | "open" | "closed";
  suspectIp?: string;
  minScore?: number;
  since?: string;
  density: Density;
};

export default function AttackChainPage() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
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
  });

  const [applied, setApplied] = useState<AppliedFilters>({
    agentId: "",
    status: "open",
    suspectIp: "",
    minScore: undefined,
    since: computeSinceIso("24h", ""),
    density: "comfortable",
  });

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rows, setRows] = useState<AttackChainCase[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(false);

  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [deepLinkStepId, setDeepLinkStepId] = useState<number | null>(null);

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
    };
    setApplied(next);
    fetchFirstPage(next);
  }

  useEffect(() => {
    // initial load
    fetchFirstPage(applied);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function openCase(id: number, stepId?: number | null) {
    setSelectedId(id);
    setDrawerOpen(true);
    setDeepLinkStepId(typeof stepId === "number" && stepId > 0 ? stepId : null);
  }

  function pivotToInvestigations(caseId: number) {
    navigate(`/investigations?linked_case_id=${encodeURIComponent(String(caseId))}&status=open`);
  }

  useEffect(() => {
    const caseId = parsePositiveInt(searchParams.get("case_id"));
    const stepId = parsePositiveInt(searchParams.get("step_id"));
    if (!caseId) return;
    setSelectedId(caseId);
    setDrawerOpen(true);
    setDeepLinkStepId(stepId);
  }, [searchParams]);

  useEffect(() => {
    const next = new URLSearchParams(searchParams);
    if (drawerOpen && selectedId) {
      next.set("case_id", String(selectedId));
      if (deepLinkStepId) next.set("step_id", String(deepLinkStepId));
      else next.delete("step_id");
    } else {
      next.delete("case_id");
      next.delete("step_id");
    }
    if (next.toString() !== searchParams.toString()) {
      setSearchParams(next, { replace: true });
    }
  }, [drawerOpen, selectedId, deepLinkStepId, searchParams, setSearchParams]);

  const density = applied.density;
  const dense = density === "compact";
  const openCases = useMemo(() => rows.filter((row) => String(row.status).toLowerCase() === "open").length, [rows]);
  const closedCases = useMemo(() => rows.filter((row) => String(row.status).toLowerCase() === "closed").length, [rows]);
  const highRiskCases = useMemo(() => rows.filter((row) => Number(row.score) >= 60).length, [rows]);
  const hottestStage = useMemo(() => {
    const counts = new Map<string, number>();
    for (const row of rows) {
      const key = stageLabel(row.max_stage);
      counts.set(key, (counts.get(key) || 0) + 1);
    }
    let winner = "-";
    let winnerCount = 0;
    for (const [label, count] of counts.entries()) {
      if (count > winnerCount) {
        winner = label;
        winnerCount = count;
      }
    }
    return winner;
  }, [rows]);

  return (
    <div className="w-full max-w-none space-y-6">
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
            <Button variant="subtle" size="md" onClick={() => fetchFirstPage(applied)}>
              Refresh
            </Button>
            {lastRefresh ? (
              <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                {fmtTs(lastRefresh.toISOString())}
              </div>
            ) : null}
          </div>
        }
      />

      <DetectionWorkflowRail compact />

      {error ? (
        <DataQueryStateBanner tone="danger" message={error} />
      ) : (
        <DataQueryStateBanner
          tone="neutral"
          message={`filters ${appliedSummary}`}
          right={lastRefresh ? `updated ${fmtTs(lastRefresh.toISOString())}` : "pending first refresh"}
        />
      )}

      <DataStatsStrip
        stats={[
          { label: "Loaded cases", value: rows.length },
          { label: "Open", value: openCases },
          { label: "Closed", value: closedCases },
          { label: "High risk (score >= 60)", value: highRiskCases },
          { label: "Top stage", value: hottestStage },
          { label: "Scope", value: applied.agentId || "all agents", hint: applied.status || "all status" },
          { label: "Timeline", value: applied.since ? "bounded" : "all time" },
          { label: "Density", value: applied.density },
        ]}
      />

      <div className="w-full grid grid-cols-1 xl:grid-cols-12 gap-4 min-h-[calc(100vh-220px)]">
        <Panel
          title="Controls"
          actions={<span className="text-[10px] font-mono text-muted-foreground">{agentsLoading ? "loading agents" : `${agents.length} agents`}</span>}
          className="xl:col-span-4"
          scrollY
        >
          <div className="space-y-4">
            <div className="rounded-md border border-border bg-surface-2/50 p-3">
              <div className="text-sm font-semibold">Filter scope</div>
              <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-2">
                <div>
                  <FieldLabel>Status</FieldLabel>
                  <SelectInput
                    className="mt-1"
                    value={draft.status}
                    onChange={(e) => setDraft((p) => ({ ...p, status: e.target.value as any }))}
                  >
                    <option value="open">Open</option>
                    <option value="closed">Closed</option>
                    <option value="all">All</option>
                  </SelectInput>
                </div>

                <div>
                  <FieldLabel>Agent</FieldLabel>
                  <SelectInput
                    className="mt-1"
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
                  </SelectInput>
                </div>

                <div>
                  <FieldLabel>Suspect IP</FieldLabel>
                  <TextInput
                    value={draft.suspectIp}
                    onChange={(e) => setDraft((p) => ({ ...p, suspectIp: e.target.value }))}
                    placeholder="e.g. 203.0.113.10"
                    className="mt-1 font-mono"
                  />
                </div>

                <div>
                  <FieldLabel>Min score</FieldLabel>
                  <TextInput
                    value={draft.minScore}
                    onChange={(e) => setDraft((p) => ({ ...p, minScore: e.target.value }))}
                    placeholder="0"
                    inputMode="numeric"
                    className="mt-1 font-mono"
                  />
                </div>
              </div>

              <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-2">
                <div>
                  <FieldLabel>Since</FieldLabel>
                  <SelectInput
                    className="mt-1"
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
                  </SelectInput>

                  {draft.sincePreset === "custom" ? (
                    <TextInput
                      value={draft.sinceCustomLocal}
                      onChange={(e) => setDraft((p) => ({ ...p, sinceCustomLocal: e.target.value }))}
                      type="datetime-local"
                      className="mt-2 font-mono"
                    />
                  ) : null}
                </div>

                <div>
                  <FieldLabel>Density</FieldLabel>
                  <SelectInput
                    className="mt-1"
                    value={draft.density}
                    onChange={(e) => setDraft((p) => ({ ...p, density: e.target.value as Density }))}
                  >
                    <option value="comfortable">Comfortable</option>
                    <option value="compact">Compact</option>
                  </SelectInput>
                </div>
              </div>

              <div className="mt-3 flex items-center justify-between gap-3">
                <div className="text-[11px] text-muted-foreground">Applied: {appliedSummary}</div>
                <Button variant="primary" size="md" onClick={applyFilters}>
                  Apply & refresh
                </Button>
              </div>
            </div>

            <div className="rounded-md border border-border bg-surface-2/50 p-3">
              <div className="text-sm font-semibold">How to use</div>
              <ul className="mt-2 space-y-1.5 text-[12px] leading-relaxed text-muted-foreground">
                <li>• Start with <span className="text-foreground">Open</span> cases, sorted by <span className="text-foreground">last seen</span>.</li>
                <li>• Use <span className="text-foreground">since</span> to scope recent campaigns.</li>
                <li>• Open a case to use a persistent investigation workspace with notes and evidence.</li>
                <li>• Close is enforced by backend admin role.</li>
              </ul>
            </div>
          </div>
        </Panel>

        <Panel
          title="Cases"
          actions={<span className="text-[10px] font-mono text-muted-foreground">{rows.length} loaded{hasMore ? " · more available" : ""}</span>}
          className="xl:col-span-8"
          scrollY
        >
          {loading ? <Loading label="Loading cases" /> : null}
          {!loading && error ? <EmptyState title="FAILED" hint={error} /> : null}

          {!loading && !error && rows.length === 0 ? (
            <EmptyState title="NO CASES" hint="No attack chains matched your filters." />
          ) : null}

          {!error && rows.length > 0 ? (
            <div className="w-full">
              <table className="w-full text-sm">
                <thead className="sticky top-0 z-[2] bg-surface-2/95 text-left text-[10px] font-semibold uppercase tracking-[0.08em] text-muted-foreground backdrop-blur-sm">
                  <tr>
                    <th className="border-b border-border px-3 py-2.5">Risk</th>
                    <th className="border-b border-border px-3 py-2.5">Stage / Agent</th>
                    <th className="border-b border-border px-3 py-2.5">Suspect / Seen</th>
                    <th className="border-b border-border px-3 py-2.5 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => {
                    const selected = selectedId !== null && r.id === selectedId;
                    return (
                      <tr
                        key={r.id}
                        className={cx(
                          "cursor-pointer border-t border-border/55 ui-row",
                          selected && "ui-row-selected",
                        )}
                        onClick={() => openCase(r.id)}
                        role="button"
                        tabIndex={0}
                      >
                        <td className={cx("px-3", dense ? "py-1.5" : "py-2.5")}>
                          <div className="flex flex-wrap items-center gap-1.5">
                            <StatusPill variant={statusPillVariant(r.status)} withDot>{r.status}</StatusPill>
                            <SeverityPill variant={scoreVariant(r.score)} withDot>score {r.score}</SeverityPill>
                          </div>
                        </td>
                        <td className={cx("px-3", dense ? "py-1.5" : "py-2.5")}>
                          <div className="text-sm font-semibold">{stageLabel(r.max_stage)}</div>
                          <div className="text-[11px] text-muted-foreground">{r.step_count} steps · agent {r.agent_id}</div>
                        </td>
                        <td className={cx("px-3", dense ? "py-1.5" : "py-2.5")}>
                          <div className="break-all font-mono text-[12px]" title={r.suspect_ip || ""}>
                            {r.suspect_ip || "-"}
                          </div>
                          <div className="font-mono text-[11px] text-muted-foreground">
                            {fmtTs(r.last_seen_at)}
                          </div>
                        </td>
                        <td className={cx("px-3 text-right", dense ? "py-1.5" : "py-2.5")}>
                          <div className="flex flex-wrap items-center justify-end gap-2">
                            <Button
                              variant="subtle"
                              size="sm"
                              onClick={(e) => { e.stopPropagation(); openCase(r.id); }}
                              title="Open attack-chain drawer"
                            >
                              View
                            </Button>
                            <Button
                              variant="subtle"
                              size="sm"
                              onClick={(e) => { e.stopPropagation(); pivotToInvestigations(r.id); }}
                              title="Pivot case into investigations workspace"
                            >
                              Investigate
                            </Button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : null}

          {!error && rows.length > 0 ? (
            <div className="mt-4">
              <DataPaginationFooter
                totalCount={rows.length}
                pageSize={50}
                onPageSizeChange={() => {
                  // fixed page size for attack-chain cursor requests
                }}
                pageSizeOptions={[50]}
                hasMore={hasMore}
                loadingMore={loading}
                onLoadMore={fetchMore}
                loadMoreLabel="Load older cases"
              />
            </div>
          ) : null}
        </Panel>
      </div>

      <AttackChainDrawer
        open={drawerOpen}
        caseId={selectedId}
        initialStepId={deepLinkStepId}
        onClose={() => {
          setDrawerOpen(false);
          setDeepLinkStepId(null);
        }}
        onClosed={(id) => {
          // update list item status on close (optimistic)
          setRows((prev) => prev.map((r) => (r.id === id ? { ...r, status: "closed" } : r)));
        }}
      />
    </div>
  );
}
