import { useEffect, useMemo, useRef, useState } from "react";

import { Badge } from "@/shared/components/Badge";
import Drawer from "@/shared/components/Drawer";
import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { cx } from "@/shared/lib/cx";

import { useAuth } from "@/features/auth/context";

import { closeAttackChainCase, getAttackChainCaseFull } from "./api";
import { stageLabel, stageRank, STAGES } from "./stages";
import type { AttackChainCaseWithSteps, AttackChainStep } from "./types";
import {
  addWorkflowNote,
  clearWorkflow,
  loadWorkflow,
  setWorkflowAssignee,
  setWorkflowPriority,
  setWorkflowTriage,
  type InvestigationWorkflow,
  type Priority,
  type TriageState
} from "./workflow";

type TabKey = "overview" | "timeline" | "investigation";

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

function safeJson(v: any) {
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}

function scoreVariant(score: number) {
  if (score >= 700) return "critical";
  if (score >= 450) return "high";
  if (score >= 200) return "medium";
  if (score > 0) return "low";
  return "neutral";
}

function statusVariant(status: string) {
  const s = String(status || "").toLowerCase();
  if (s === "open") return "info";
  if (s === "closed") return "neutral";
  return "neutral";
}

function TabButton({ active, children, onClick }: { active: boolean; children: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cx(
        "px-3 py-2 text-xs font-mono uppercase tracking-widest border-b-2",
        active
          ? "border-primary text-foreground"
          : "border-transparent text-muted-foreground hover:text-foreground hover:border-border/60"
      )}
    >
      {children}
    </button>
  );
}

function WorkflowBadge({ wf }: { wf: InvestigationWorkflow }) {
  const map: Record<TriageState, { label: string; variant: any }> = {
    untriaged: { label: "Untriaged", variant: "neutral" },
    triage: { label: "Triage", variant: "medium" },
    assigned: { label: "Assigned", variant: "info" },
    investigating: { label: "Investigating", variant: "high" },
    contained: { label: "Contained", variant: "low" },
    closed: { label: "Closed", variant: "neutral" }
  } as any;

  return <Badge variant={map[wf.triage]?.variant || "neutral"}>{map[wf.triage]?.label || "Workflow"}</Badge>;
}

export default function AttackChainDrawer({
  open,
  caseId,
  onClose,
  onClosed
}: {
  open: boolean;
  caseId: number | null;
  onClose: () => void;
  onClosed?: (caseId: number) => void;
}) {
  const { user } = useAuth();
  const isAdmin = (user?.role || "").toLowerCase() === "admin";

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [payload, setPayload] = useState<AttackChainCaseWithSteps | null>(null);
  const [tab, setTab] = useState<TabKey>("overview");

  const [wf, setWf] = useState<InvestigationWorkflow>(() => (caseId ? loadWorkflow(caseId) : loadWorkflow(0)));
  const [noteText, setNoteText] = useState("");
  const [assigneeDraft, setAssigneeDraft] = useState("");

  const [closeBusy, setCloseBusy] = useState(false);
  const [closeError, setCloseError] = useState<string | null>(null);

  const reqSeq = useRef(0);

  useEffect(() => {
    if (!open || !caseId) return;

    const mySeq = ++reqSeq.current;
    setLoading(true);
    setError(null);
    setPayload(null);
    setTab("overview");
    setCloseError(null);

    // Load workflow for this case.
    setWf(loadWorkflow(caseId));
    setAssigneeDraft(loadWorkflow(caseId).assignee || "");
    setNoteText("");

    getAttackChainCaseFull(caseId)
      .then((data) => {
        if (reqSeq.current !== mySeq) return;
        setPayload(data);
      })
      .catch((e: any) => {
        if (reqSeq.current !== mySeq) return;
        setError(e?.message || "Failed to load case");
      })
      .finally(() => {
        if (reqSeq.current !== mySeq) return;
        setLoading(false);
      });
  }, [open, caseId]);

  const title = caseId ? `Attack Chain Case #${caseId}` : "Attack Chain";
  const description = payload
    ? `Agent ${payload.case.agent_id}${payload.case.suspect_ip ? ` · Suspect ${payload.case.suspect_ip}` : ""}`
    : "Attack chain timeline and investigation workflow";

  const maxStageRank = useMemo(() => {
    if (!payload) return 0;
    return stageRank(payload.case.max_stage);
  }, [payload]);

  async function doCloseCase() {
    if (!payload) return;
    setCloseBusy(true);
    setCloseError(null);
    try {
      await closeAttackChainCase(payload.case.id);
      // optimistic UI: update local payload
      setPayload((prev) => {
        if (!prev) return prev;
        return { ...prev, case: { ...prev.case, status: "closed" } };
      });
      if (caseId) {
        const next = setWorkflowTriage(caseId, "closed");
        setWf(next);
      }
      if (onClosed) onClosed(payload.case.id);
    } catch (e: any) {
      setCloseError(e?.message || "Failed to close case (admin required)");
    } finally {
      setCloseBusy(false);
    }
  }

  function applyTriage(t: TriageState) {
    if (!caseId) return;
    const next = setWorkflowTriage(caseId, t);
    setWf(next);
  }

  function applyPriority(p: Priority) {
    if (!caseId) return;
    const next = setWorkflowPriority(caseId, p);
    setWf(next);
  }

  function applyAssignee() {
    if (!caseId) return;
    const next = setWorkflowAssignee(caseId, assigneeDraft);
    // automatically promote triage state when assigning.
    const promoted = next.assignee ? setWorkflowTriage(caseId, "assigned") : next;
    setWf(promoted);
  }

  function addNote() {
    if (!caseId) return;
    const text = noteText.trim();
    if (!text) return;
    const author = user?.username || "analyst";
    const next = addWorkflowNote(caseId, { author, text });
    setWf(next);
    setNoteText("");
  }

  function resetWorkflow() {
    if (!caseId) return;
    clearWorkflow(caseId);
    const next = loadWorkflow(caseId);
    setWf(next);
    setAssigneeDraft(next.assignee || "");
    setNoteText("");
  }

  function StepRow({ s }: { s: AttackChainStep }) {
    return (
      <div className="rounded-xl border border-border/60 bg-background/40 p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <Badge variant="info">{stageLabel(s.stage)}</Badge>
              <div className="text-sm font-semibold truncate">{s.title}</div>
              {s.score_delta ? <Badge variant={scoreVariant(Math.max(0, s.score_delta))}>+{s.score_delta}</Badge> : null}
            </div>
            {s.description ? <div className="mt-1 text-sm text-muted-foreground">{s.description}</div> : null}
            <div className="mt-2 text-[11px] font-mono text-muted-foreground">{fmtTs(s.timestamp)}</div>
          </div>

          <div className="shrink-0 text-right">
            <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Kind</div>
            <div className="text-xs font-mono text-foreground">{s.kind || "-"}</div>
          </div>
        </div>

        {s.details ? (
          <details className="mt-3">
            <summary className="cursor-pointer text-xs text-muted-foreground hover:text-foreground">Details (JSON)</summary>
            <pre className="mt-2 text-[11px] font-mono whitespace-pre-wrap break-words text-muted-foreground bg-background/30 border border-border/60 p-3 rounded-lg">
              {safeJson(s.details)}
            </pre>
          </details>
        ) : null}
      </div>
    );
  }

  return (
    <Drawer open={open} title={title} description={description} onClose={onClose} widthClassName="w-[920px]">
      {loading ? <Loading label="Loading case" /> : null}

      {!loading && error ? (
        <EmptyState title="FAILED" hint={error} />
      ) : null}

      {!loading && !error && payload ? (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant={statusVariant(payload.case.status)}>{payload.case.status}</Badge>
            <Badge variant={scoreVariant(payload.case.score)}>score {payload.case.score}</Badge>
            <Badge variant="neutral">{stageLabel(payload.case.max_stage)}</Badge>
            <WorkflowBadge wf={wf} />
            {wf.assignee ? <Badge variant="neutral">assigned: {wf.assignee}</Badge> : null}
            {wf.notes.length ? <Badge variant="neutral">notes: {wf.notes.length}</Badge> : null}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="rounded-xl border border-border/60 bg-background/40 p-4">
              <div className="text-[10px] font-mono uppercase tracking-[0.35em] text-muted-foreground">Case</div>
              <div className="mt-3 space-y-2 text-sm">
                <div className="flex items-center justify-between gap-3">
                  <div className="text-muted-foreground">Agent</div>
                  <div className="font-mono text-foreground truncate">{payload.case.agent_id}</div>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <div className="text-muted-foreground">Suspect</div>
                  <div className="font-mono text-foreground truncate">{payload.case.suspect_ip || "-"}</div>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <div className="text-muted-foreground">Steps</div>
                  <div className="font-mono text-foreground">{payload.case.step_count}</div>
                </div>
              </div>
            </div>

            <div className="rounded-xl border border-border/60 bg-background/40 p-4">
              <div className="text-[10px] font-mono uppercase tracking-[0.35em] text-muted-foreground">Window</div>
              <div className="mt-3 space-y-2 text-sm">
                <div className="flex items-center justify-between gap-3">
                  <div className="text-muted-foreground">First seen</div>
                  <div className="font-mono text-foreground">{fmtTs(payload.case.first_seen_at)}</div>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <div className="text-muted-foreground">Last seen</div>
                  <div className="font-mono text-foreground">{fmtTs(payload.case.last_seen_at)}</div>
                </div>
                {payload.case.closed_at ? (
                  <div className="flex items-center justify-between gap-3">
                    <div className="text-muted-foreground">Closed at</div>
                    <div className="font-mono text-foreground">{fmtTs(payload.case.closed_at)}</div>
                  </div>
                ) : null}
              </div>
            </div>

            <div className="rounded-xl border border-border/60 bg-background/40 p-4">
              <div className="text-[10px] font-mono uppercase tracking-[0.35em] text-muted-foreground">Stage Progress</div>
              <div className="mt-3 flex flex-wrap gap-2">
                {STAGES.map((st, idx) => {
                  const reached = idx <= maxStageRank;
                  return (
                    <span
                      key={st.key}
                      className={cx(
                        "inline-flex items-center rounded-md border px-2 py-1 text-[11px] font-mono",
                        reached
                          ? "border-primary/40 bg-primary/10 text-foreground"
                          : "border-border/60 bg-background/30 text-muted-foreground"
                      )}
                      title={st.hint}
                    >
                      {st.label}
                    </span>
                  );
                })}
              </div>
              <div className="mt-3 text-[11px] text-muted-foreground">
                Stages are inferred heuristically from telemetry. Confirm with host artifacts before taking action.
              </div>
            </div>
          </div>

          <div className="rounded-xl border border-border/60 bg-background/40">
            <div className="flex items-center gap-2 border-b border-border/60 bg-muted/10 px-4">
              <TabButton active={tab === "overview"} onClick={() => setTab("overview")}>
                Overview
              </TabButton>
              <TabButton active={tab === "timeline"} onClick={() => setTab("timeline")}>
                Timeline
              </TabButton>
              <TabButton active={tab === "investigation"} onClick={() => setTab("investigation")}>
                Investigation
              </TabButton>
              <div className="flex-1" />
              {payload.case.status === "open" ? (
                <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">active</span>
              ) : (
                <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">closed</span>
              )}
            </div>

            <div className="p-4">
              {tab === "overview" ? (
                <div className="space-y-3">
                  <div className="text-sm text-muted-foreground">
                    This case groups multiple signals into a single ATT&CK-aligned chain to reduce noise and speed triage.
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    <div className="rounded-lg border border-border/60 bg-background/30 p-3">
                      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Max stage</div>
                      <div className="mt-1 text-sm font-semibold">{stageLabel(payload.case.max_stage)}</div>
                      <div className="mt-1 text-[11px] text-muted-foreground">
                        {STAGES.find((x) => x.key === payload.case.max_stage)?.hint || "-"}
                      </div>
                    </div>
                    <div className="rounded-lg border border-border/60 bg-background/30 p-3">
                      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Score</div>
                      <div className="mt-1 text-sm font-semibold">{payload.case.score}</div>
                      <div className="mt-1 text-[11px] text-muted-foreground">Higher scores indicate stronger / more correlated signals.</div>
                    </div>
                    <div className="rounded-lg border border-border/60 bg-background/30 p-3">
                      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Steps</div>
                      <div className="mt-1 text-sm font-semibold">{payload.steps.length}</div>
                      <div className="mt-1 text-[11px] text-muted-foreground">Timeline signals used to compute the chain.</div>
                    </div>
                  </div>

                  {payload.case.context ? (
                    <details>
                      <summary className="cursor-pointer text-xs text-muted-foreground hover:text-foreground">Case context (JSON)</summary>
                      <pre className="mt-2 text-[11px] font-mono whitespace-pre-wrap break-words text-muted-foreground bg-background/30 border border-border/60 p-3 rounded-lg">
                        {safeJson(payload.case.context)}
                      </pre>
                    </details>
                  ) : null}
                </div>
              ) : null}

              {tab === "timeline" ? (
                <div className="space-y-3">
                  {payload.steps.length === 0 ? <EmptyState title="NO STEPS" hint="This case has no timeline entries." /> : null}
                  {payload.steps.map((s) => (
                    <StepRow key={s.id} s={s} />
                  ))}
                </div>
              ) : null}

              {tab === "investigation" ? (
                <div className="space-y-4">
                  <div className="rounded-xl border border-border/60 bg-background/30 p-4">
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <div className="text-sm font-semibold">Investigation workflow</div>
                        <div className="text-xs text-muted-foreground">
                          Triage → Assign → Notes → Close. Saved locally in your browser for now.
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={resetWorkflow}
                        className={cx(
                          "rounded-md border border-border/60 bg-background/40",
                          "px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground",
                          "hover:bg-muted/15 hover:text-foreground"
                        )}
                        title="Reset local workflow state"
                      >
                        Reset
                      </button>
                    </div>

                    <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-3">
                      <div>
                        <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Triage</div>
                        <select
                          className="mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm"
                          value={wf.triage}
                          onChange={(e) => applyTriage(e.target.value as TriageState)}
                        >
                          <option value="untriaged">Untriaged</option>
                          <option value="triage">Triage</option>
                          <option value="assigned">Assigned</option>
                          <option value="investigating">Investigating</option>
                          <option value="contained">Contained</option>
                          <option value="closed">Closed</option>
                        </select>
                      </div>

                      <div>
                        <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Priority</div>
                        <select
                          className="mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm"
                          value={wf.priority}
                          onChange={(e) => applyPriority(e.target.value as Priority)}
                        >
                          <option value="p1">P1 (critical)</option>
                          <option value="p2">P2 (high)</option>
                          <option value="p3">P3 (medium)</option>
                          <option value="p4">P4 (low)</option>
                        </select>
                      </div>

                      <div>
                        <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Assignee</div>
                        <div className="mt-1 flex items-center gap-2">
                          <input
                            value={assigneeDraft}
                            onChange={(e) => setAssigneeDraft(e.target.value)}
                            placeholder="e.g. admin"
                            className="flex-1 rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm"
                          />
                          <button
                            type="button"
                            onClick={applyAssignee}
                            className={cx(
                              "rounded-md border border-border/60 bg-background/40",
                              "px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground",
                              "hover:bg-muted/15 hover:text-foreground"
                            )}
                          >
                            Assign
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="rounded-xl border border-border/60 bg-background/30 p-4">
                    <div className="text-sm font-semibold">Notes</div>
                    <div className="mt-3 flex items-start gap-2">
                      <textarea
                        value={noteText}
                        onChange={(e) => setNoteText(e.target.value)}
                        rows={3}
                        placeholder="Add investigation notes, indicators, or next steps..."
                        className="flex-1 rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm font-mono"
                      />
                      <button
                        type="button"
                        onClick={addNote}
                        className={cx(
                          "rounded-md border border-border/60 bg-background/40",
                          "px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground",
                          "hover:bg-muted/15 hover:text-foreground"
                        )}
                      >
                        Add
                      </button>
                    </div>

                    <div className="mt-4 space-y-2">
                      {wf.notes.length === 0 ? (
                        <div className="text-sm text-muted-foreground">No notes yet.</div>
                      ) : (
                        wf.notes.map((n) => (
                          <div key={n.id} className="rounded-lg border border-border/60 bg-background/40 p-3">
                            <div className="flex items-center justify-between gap-3">
                              <div className="text-[11px] font-mono text-muted-foreground">
                                {n.author ? `${n.author} · ` : ""}{fmtTs(n.at)}
                              </div>
                            </div>
                            <div className="mt-2 whitespace-pre-wrap break-words text-sm font-mono">{n.text}</div>
                          </div>
                        ))
                      )}
                    </div>
                  </div>

                  <div className="flex items-center justify-between gap-3">
                    <div className="text-xs text-muted-foreground">
                      Closing a case requires admin privileges (backend enforcement).
                    </div>
                    <button
                      type="button"
                      onClick={doCloseCase}
                      disabled={!isAdmin || payload.case.status !== "open" || closeBusy}
                      className={cx(
                        "rounded-md border border-border/60",
                        closeBusy ? "opacity-60" : "",
                        !isAdmin || payload.case.status !== "open"
                          ? "bg-muted/10 text-muted-foreground"
                          : "bg-red-500/10 text-red-400 border-red-500/30 hover:bg-red-500/15",
                        "px-3 py-2 text-xs font-mono uppercase tracking-widest"
                      )}
                      title={!isAdmin ? "Admin required" : payload.case.status !== "open" ? "Already closed" : "Close case"}
                    >
                      {closeBusy ? "Closing..." : "Close case"}
                    </button>
                  </div>
                  {closeError ? <div className="text-xs text-red-400">{closeError}</div> : null}
                </div>
              ) : null}
            </div>
          </div>
        </div>
      ) : null}
    </Drawer>
  );
}
