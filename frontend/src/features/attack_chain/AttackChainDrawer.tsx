import { useEffect, useMemo, useRef, useState } from "react";

import { Badge } from "@/shared/components/Badge";
import Drawer from "@/shared/components/Drawer";
import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { cx } from "@/shared/lib/cx";
import PinToWorkspaceDrawer from "@/features/investigations/PinToWorkspaceDrawer";
import {
  createInvestigationNote,
  createInvestigationWorkspace,
  linkAttackChainCaseToWorkspace,
  listInvestigationNotes,
  listInvestigationWorkspaces,
  pinAttackChainCaseToWorkspace,
  pinAttackChainStepToWorkspace,
  updateInvestigationWorkspace,
} from "@/features/investigations/api";
import type {
  InvestigationNote,
  InvestigationWorkspace,
  InvestigationWorkspacePriority,
  InvestigationWorkspaceTriage,
} from "@/features/investigations/types";

import { useAuth } from "@/features/auth/context";

import { closeAttackChainCase, getAttackChainCaseFull } from "./api";
import { stageLabel, stageRank, STAGES } from "./stages";
import type { AttackChainCaseWithSteps, AttackChainStep } from "./types";

type TabKey = "overview" | "timeline" | "investigation";

type StepView = {
  id: number;
  stage: string;
  at: string;
  title: string;
  description: string;
  scoreDelta: number;
  kind: string;
  confidence: number;
  techniqueId: string;
  evidenceClass: "observed" | "strongly_supported" | "inferred" | "weakly_inferred";
  evidenceNature: "direct" | "inferred";
  confidenceFactors: string[];
  missingEvidence: string[];
  transition: { allowed: boolean; promoted: boolean; reason: string };
  raw: AttackChainStep;
};

type TriageState = InvestigationWorkspaceTriage;
type Priority = InvestigationWorkspacePriority;

type InvestigationWorkflow = {
  triage: TriageState;
  priority: Priority;
  assignee: string;
  notes: InvestigationNote[];
  workspaceId: number | null;
  workspaceKey: string;
};

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

function confidenceLabel(c: number) {
  const v = Number.isFinite(c) ? c : 0;
  if (v >= 80) return "High";
  if (v >= 55) return "Medium";
  if (v > 0) return "Low";
  return "-";
}

function confidenceVariant(c: number) {
  const v = Number.isFinite(c) ? c : 0;
  if (v >= 80) return "high";
  if (v >= 55) return "medium";
  if (v > 0) return "low";
  return "neutral";
}

function normalizeEvidenceClass(v: any): "observed" | "strongly_supported" | "inferred" | "weakly_inferred" {
  const s = String(v || "").trim().toLowerCase();
  if (s === "observed") return "observed";
  if (s === "strongly_supported") return "strongly_supported";
  if (s === "inferred") return "inferred";
  return "weakly_inferred";
}

function evidenceLabel(level: StepView["evidenceClass"]) {
  if (level === "observed") return "Observed";
  if (level === "strongly_supported") return "Strongly Supported";
  if (level === "inferred") return "Inferred";
  return "Weakly Inferred";
}

function evidenceVariant(level: StepView["evidenceClass"]) {
  if (level === "observed") return "high";
  if (level === "strongly_supported") return "medium";
  if (level === "inferred") return "low";
  return "neutral";
}

function buildStepView(s: AttackChainStep): StepView {
  const d = (s.details && typeof s.details === "object") ? s.details : {};
  const title = String((s as any).label || "").trim() || "Step";
  const desc = String(d.description || "").trim();
  const kind = String(d.kind || s.event_type || "").trim() || "signal";
  const confidence = Number(d.confidence);
  const techniqueId = String(d.technique_id || "").trim();
  const evidenceClass = normalizeEvidenceClass(d.evidence_class);
  const evidenceNature = String(d.evidence_nature || "").trim().toLowerCase() === "inferred" ? "inferred" : "direct";
  const confidenceFactors = Array.isArray(d.confidence_factors)
    ? d.confidence_factors.map((x: any) => String(x || "").trim()).filter(Boolean).slice(0, 4)
    : [];
  const missingEvidence = Array.isArray(d.missing_evidence)
    ? d.missing_evidence.map((x: any) => String(x || "").trim()).filter(Boolean).slice(0, 4)
    : [];
  const tr = (d.transition && typeof d.transition === "object") ? d.transition : {};
  const transition = {
    allowed: Boolean((tr as any).allowed),
    promoted: Boolean((tr as any).promoted),
    reason: String((tr as any).reason || "").trim(),
  };

  // Operator-friendly fallbacks for common evidence.
  let description = desc;
  if (!description) {
    if (kind.startsWith("ssh")) {
      const u = String(d.username || "").trim();
      const ip = String(d.src_ip || s.src_ip || "").trim();
      const fc = Number(d.fail_count);
      if (Number.isFinite(fc) && fc > 0) description = `${fc} failures from ${ip || "-"}${u ? ` as ${u}` : ""}`;
      else if (ip || u) description = `${ip || "-"}${u ? ` as ${u}` : ""}`;
    } else if (kind.startsWith("sudo") || kind === "context") {
      const u = String(d.username || "").trim();
      const tu = String(d.target_user || "").trim();
      const cmd = String(d.command || "").trim();
      const bits = [] as string[];
      if (u) bits.push(`user=${u}`);
      if (tu) bits.push(`as=${tu}`);
      if (cmd) bits.push(cmd.length > 140 ? cmd.slice(0, 140) + "…" : cmd);
      description = bits.join(" · ");
    }
  }

  return {
    id: s.id,
    stage: s.stage,
    at: s.timestamp,
    title,
    description,
    scoreDelta: Number(s.score_delta) || 0,
    kind,
    confidence: Number.isFinite(confidence) ? confidence : 0,
    techniqueId,
    evidenceClass,
    evidenceNature,
    confidenceFactors,
    missingEvidence,
    transition,
    raw: s,
  };
}

function assessCase(payload: AttackChainCaseWithSteps): { verdict: string; hint: string } {
  const backendVerdict = String(payload.reasoning?.overall?.verdict || "").trim();
  const backendHint = String(payload.reasoning?.overall?.analyst_hint || "").trim();
  if (backendVerdict || backendHint) {
    return {
      verdict: backendVerdict || "Assessment",
      hint: backendHint || "Review supporting evidence before taking remediation action.",
    };
  }

  const score = Number(payload.case.score) || 0;
  const steps = (payload.steps || []).map(buildStepView);
  const observed = steps.filter((s) => s.evidenceClass === "observed").length;
  const strong = steps.filter((s) => s.evidenceClass === "strongly_supported").length;
  const inferred = steps.filter((s) => s.evidenceClass === "inferred").length;

  if (observed > 0 || (strong >= 2 && score >= 55)) {
    return { verdict: "Observed-led chain", hint: "Direct telemetry supports core stages. Validate scope and begin containment." };
  }
  if (strong > 0 || (inferred >= 2 && score >= 40)) {
    return { verdict: "Strongly supported chain", hint: "Signals converge with useful confidence. Confirm artifacts before escalation." };
  }
  if (inferred > 0 || score > 0) {
    return { verdict: "Inferred chain", hint: "Evidence exists but remains indirect. Seek direct host and network confirmation." };
  }
  return { verdict: "Weakly inferred chain", hint: "Evidence is sparse or weak. Avoid high-confidence conclusions." };
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
  initialStepId,
  onClose,
  onClosed
}: {
  open: boolean;
  caseId: number | null;
  initialStepId?: number | null;
  onClose: () => void;
  onClosed?: (caseId: number) => void;
}) {
  const { user } = useAuth();
  const isAdmin = (user?.role || "").toLowerCase() === "admin";

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [payload, setPayload] = useState<AttackChainCaseWithSteps | null>(null);
  const [tab, setTab] = useState<TabKey>("overview");

  const [workspace, setWorkspace] = useState<InvestigationWorkspace | null>(null);
  const [workspaceNotes, setWorkspaceNotes] = useState<InvestigationNote[]>([]);
  const [workspaceChoices, setWorkspaceChoices] = useState<InvestigationWorkspace[]>([]);
  const [attachWorkspaceId, setAttachWorkspaceId] = useState<number | null>(null);
  const [wfBusy, setWfBusy] = useState(false);
  const [wfError, setWfError] = useState<string | null>(null);
  const [pinResultText, setPinResultText] = useState<string | null>(null);
  const [pinStepId, setPinStepId] = useState<number | null>(null);
  const [pinCaseOpen, setPinCaseOpen] = useState(false);
  const [focusedStepId, setFocusedStepId] = useState<number | null>(null);

  const [wf, setWf] = useState<InvestigationWorkflow>({
    triage: "untriaged",
    priority: "p3",
    assignee: "",
    notes: [],
    workspaceId: null,
    workspaceKey: "",
  });
  const [noteText, setNoteText] = useState("");
  const [assigneeDraft, setAssigneeDraft] = useState("");

  const [closeBusy, setCloseBusy] = useState(false);
  const [closeError, setCloseError] = useState<string | null>(null);

  const reqSeq = useRef(0);

  function setWorkflowFromWorkspace(ws: InvestigationWorkspace | null, notes: InvestigationNote[]) {
    if (!ws) {
      const empty: InvestigationWorkflow = {
        triage: "untriaged",
        priority: "p3",
        assignee: "",
        notes: [],
        workspaceId: null,
        workspaceKey: "",
      };
      setWf(empty);
      setAssigneeDraft("");
      return;
    }
    const next: InvestigationWorkflow = {
      triage: ws.triage_state,
      priority: ws.priority,
      assignee: ws.assignee || "",
      notes: notes.slice(),
      workspaceId: ws.id,
      workspaceKey: ws.workspace_key,
    };
    setWf(next);
    setAssigneeDraft(next.assignee);
  }

  async function loadWorkspaceState(caseIdValue: number) {
    const [linked, allChoices] = await Promise.all([
      listInvestigationWorkspaces({ page_size: 1, linked_attack_chain_case_id: caseIdValue }),
      listInvestigationWorkspaces({ page_size: 100 }),
    ]);
    const ws = (linked.items || [])[0] || null;
    setWorkspace(ws);
    setWorkspaceChoices(allChoices.items || []);
    setAttachWorkspaceId((allChoices.items || [])[0]?.id ?? null);
    if (!ws) {
      setWorkspaceNotes([]);
      setWorkflowFromWorkspace(null, []);
      return;
    }
    const notes = await listInvestigationNotes(ws.id, { limit: 300 });
    setWorkspaceNotes(notes || []);
    setWorkflowFromWorkspace(ws, notes || []);
  }

  useEffect(() => {
    if (!open || !caseId) return;

    const mySeq = ++reqSeq.current;
    setLoading(true);
    setError(null);
    setPayload(null);
    setTab("overview");
    setCloseError(null);
    setWfError(null);
    setPinResultText(null);
    setPinStepId(null);
    setPinCaseOpen(false);
    setFocusedStepId(initialStepId || null);

    setNoteText("");

    Promise.all([getAttackChainCaseFull(caseId), loadWorkspaceState(caseId)])
      .then(([data]) => {
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
  }, [open, caseId, initialStepId]);

  useEffect(() => {
    if (!open || !payload || !focusedStepId) return;
    if (!payload.steps.some((s) => s.id === focusedStepId)) return;
    setTab("timeline");
    const t = window.setTimeout(() => {
      const el = document.getElementById(`attack-step-${focusedStepId}`);
      if (el) el.scrollIntoView({ block: "center" });
    }, 80);
    return () => window.clearTimeout(t);
  }, [open, payload, focusedStepId]);

  const title = caseId ? `Attack Chain Case #${caseId}` : "Attack Chain";
  const description = payload
    ? `Agent ${payload.case.agent_id}${payload.case.suspect_ip ? ` · Suspect ${payload.case.suspect_ip}` : ""}`
    : "Attack chain timeline and investigation workflow";

  const assessment = payload ? assessCase(payload) : null;

  const maxStageRank = useMemo(() => {
    if (!payload) return 0;
    return stageRank(payload.case.max_stage);
  }, [payload]);

  const stageReasoning = useMemo(() => {
    if (!payload?.reasoning?.stages || !Array.isArray(payload.reasoning.stages)) return [];
    return payload.reasoning.stages;
  }, [payload]);

  const qualityCounts = useMemo(() => {
    const q = payload?.reasoning?.overall?.quality_counts || {};
    return {
      observed: Number((q as any).observed) || 0,
      stronglySupported: Number((q as any).strongly_supported) || 0,
      inferred: Number((q as any).inferred) || 0,
      weaklyInferred: Number((q as any).weakly_inferred) || 0,
    };
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
      if (workspace) {
        const nextWs = await updateInvestigationWorkspace(workspace.id, { status: "closed", triage_state: "closed" });
        const notes = await listInvestigationNotes(workspace.id, { limit: 300 });
        setWorkspace(nextWs);
        setWorkspaceNotes(notes || []);
        setWorkflowFromWorkspace(nextWs, notes || []);
      } else {
        setWorkflowFromWorkspace(null, []);
      }
      if (onClosed) onClosed(payload.case.id);
    } catch (e: any) {
      setCloseError(e?.message || "Failed to close case (admin required)");
    } finally {
      setCloseBusy(false);
    }
  }

  async function applyTriage(t: TriageState) {
    if (!workspace) return;
    setWfBusy(true);
    setWfError(null);
    try {
      const next = await updateInvestigationWorkspace(workspace.id, { triage_state: t });
      setWorkspace(next);
      setWorkflowFromWorkspace(next, workspaceNotes);
    } catch (e: any) {
      setWfError(e?.message || "Failed to update triage state");
    } finally {
      setWfBusy(false);
    }
  }

  async function applyPriority(p: Priority) {
    if (!workspace) return;
    setWfBusy(true);
    setWfError(null);
    try {
      const next = await updateInvestigationWorkspace(workspace.id, { priority: p });
      setWorkspace(next);
      setWorkflowFromWorkspace(next, workspaceNotes);
    } catch (e: any) {
      setWfError(e?.message || "Failed to update priority");
    } finally {
      setWfBusy(false);
    }
  }

  async function applyAssignee() {
    if (!workspace) return;
    setWfBusy(true);
    setWfError(null);
    try {
      const next = await updateInvestigationWorkspace(workspace.id, {
        assignee: assigneeDraft || "",
        triage_state: assigneeDraft.trim() ? "assigned" : wf.triage,
      });
      setWorkspace(next);
      setWorkflowFromWorkspace(next, workspaceNotes);
    } catch (e: any) {
      setWfError(e?.message || "Failed to update assignee");
    } finally {
      setWfBusy(false);
    }
  }

  async function addNote() {
    if (!workspace) return;
    const text = noteText.trim();
    if (!text) return;
    setWfBusy(true);
    setWfError(null);
    try {
      await createInvestigationNote(workspace.id, text);
      const notes = await listInvestigationNotes(workspace.id, { limit: 300 });
      setWorkspaceNotes(notes || []);
      setWorkflowFromWorkspace(workspace, notes || []);
      setNoteText("");
    } catch (e: any) {
      setWfError(e?.message || "Failed to add note");
    } finally {
      setWfBusy(false);
    }
  }

  async function createWorkspaceFromCase() {
    if (!payload) return;
    setWfBusy(true);
    setWfError(null);
    try {
      const ws = await createInvestigationWorkspace({
        title: `Attack Chain Case #${payload.case.id}`,
        description: `Workspace created from attack chain case #${payload.case.id}.`,
        linked_attack_chain_case_id: payload.case.id,
        primary_agent_id: payload.case.agent_id,
        triage_state: "triage",
        priority: "p2",
        severity: payload.case.score >= 80 ? "critical" : payload.case.score >= 60 ? "high" : "medium",
      });
      const notes = await listInvestigationNotes(ws.id, { limit: 300 });
      setWorkspace(ws);
      setWorkspaceNotes(notes || []);
      setWorkflowFromWorkspace(ws, notes || []);
      setPinResultText("Workspace created and linked to this case.");
    } catch (e: any) {
      setWfError(e?.message || "Failed to create workspace");
    } finally {
      setWfBusy(false);
    }
  }

  async function attachWorkspace() {
    if (!payload || !attachWorkspaceId) return;
    setWfBusy(true);
    setWfError(null);
    try {
      const next = await linkAttackChainCaseToWorkspace(attachWorkspaceId, payload.case.id, payload.case.agent_id);
      const notes = await listInvestigationNotes(next.id, { limit: 300 });
      setWorkspace(next);
      setWorkspaceNotes(notes || []);
      setWorkflowFromWorkspace(next, notes || []);
      setPinResultText(`Workspace ${next.workspace_key} linked to this case.`);
    } catch (e: any) {
      setWfError(e?.message || "Failed to attach workspace");
    } finally {
      setWfBusy(false);
    }
  }

  function StepRow({ s }: { s: StepView }) {
    const isFocused = focusedStepId === s.id;
    return (
      <div
        id={`attack-step-${s.id}`}
        className={cx(
          "rounded-xl border border-border/60 bg-background/40 p-4",
          isFocused && "border-primary/60 bg-primary/10"
        )}
      >
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <Badge variant="info">{stageLabel(s.stage)}</Badge>
              <div className="text-sm font-semibold truncate">{s.title}</div>
              {s.scoreDelta ? <Badge variant={scoreVariant(Math.max(0, s.scoreDelta))}>+{s.scoreDelta}</Badge> : null}
              {s.techniqueId ? <Badge variant="neutral">{s.techniqueId}</Badge> : null}
              <Badge variant={evidenceVariant(s.evidenceClass) as any}>{evidenceLabel(s.evidenceClass)}</Badge>
              <Badge variant={s.evidenceNature === "direct" ? "info" : "neutral"}>{s.evidenceNature}</Badge>
              {s.confidence ? <Badge variant={confidenceVariant(s.confidence)}>{confidenceLabel(s.confidence)}</Badge> : null}
            </div>
            {s.description ? <div className="mt-1 text-sm text-muted-foreground">{s.description}</div> : null}
            {s.confidenceFactors.length ? (
              <div className="mt-2 flex flex-wrap gap-2">
                {s.confidenceFactors.map((f) => (
                  <span
                    key={f}
                    className="inline-flex items-center rounded-md border border-border/60 bg-background/30 px-2 py-1 text-[10px] text-muted-foreground"
                  >
                    {f}
                  </span>
                ))}
              </div>
            ) : null}
            {s.missingEvidence.length ? (
              <div className="mt-2 text-xs text-yellow-500">
                Missing for stronger confidence: {s.missingEvidence.join(" · ")}
              </div>
            ) : null}
            <div className="mt-2 text-[11px] font-mono text-muted-foreground">{fmtTs(s.at)}</div>
          </div>

          <div className="shrink-0 text-right">
            <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Kind</div>
            <div className="text-xs font-mono text-foreground">{s.kind || "-"}</div>
            <button
              type="button"
              onClick={() => setPinStepId(s.id)}
              className={cx(
                "mt-2 rounded-md border border-border/60 bg-background/40",
                "px-2 py-1 text-[10px] font-mono uppercase tracking-widest text-muted-foreground",
                "hover:bg-muted/15 hover:text-foreground"
              )}
            >
              Pin step
            </button>
            {s.transition.reason ? (
              <div className="mt-2 text-[10px] text-muted-foreground max-w-[240px]">{s.transition.reason}</div>
            ) : null}
          </div>
        </div>

        {s.raw?.details ? (
          <details className="mt-3">
            <summary className="cursor-pointer text-xs text-muted-foreground hover:text-foreground">Details (JSON)</summary>
            <pre className="mt-2 text-[11px] font-mono whitespace-pre-wrap break-words text-muted-foreground bg-background/30 border border-border/60 p-3 rounded-lg">
              {safeJson(s.raw.details)}
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
            {qualityCounts.observed > 0 ? <Badge variant="high">observed {qualityCounts.observed}</Badge> : null}
            {qualityCounts.stronglySupported > 0 ? (
              <Badge variant="medium">strong {qualityCounts.stronglySupported}</Badge>
            ) : null}
            {qualityCounts.inferred > 0 ? <Badge variant="low">inferred {qualityCounts.inferred}</Badge> : null}
            {qualityCounts.weaklyInferred > 0 ? (
              <Badge variant="neutral">weak {qualityCounts.weaklyInferred}</Badge>
            ) : null}
            {workspace ? <WorkflowBadge wf={wf} /> : <Badge variant="neutral">no workspace</Badge>}
            {workspace?.workspace_key ? <Badge variant="neutral">{workspace.workspace_key}</Badge> : null}
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
                Stage progression is evidence-gated. Weak inferred signals are kept visible but do not auto-promote the chain.
              </div>
            </div>
          </div>

          {assessment ? (
            <div className="rounded-xl border border-border/60 bg-background/40 p-4">
              <div className="text-[10px] font-mono uppercase tracking-[0.35em] text-muted-foreground">Assessment</div>
              <div className="mt-2 flex items-center gap-2 flex-wrap">
                <Badge variant={scoreVariant(payload.case.score)}>{assessment.verdict}</Badge>
                <span className="text-sm text-muted-foreground">{assessment.hint}</span>
              </div>
            </div>
          ) : null}

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
                    This case links telemetry into an ATT&CK-aligned chain while preserving evidence quality and transition guardrails.
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
                      <div className="mt-1 text-[11px] text-muted-foreground">
                        Score is weighted by evidence quality. Weak inferred signals are intentionally capped.
                      </div>
                    </div>
                    <div className="rounded-lg border border-border/60 bg-background/30 p-3">
                      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Steps</div>
                      <div className="mt-1 text-sm font-semibold">{payload.steps.length}</div>
                      <div className="mt-1 text-[11px] text-muted-foreground">Timeline signals used to compute the chain.</div>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <div className="rounded-lg border border-border/60 bg-background/30 p-3">
                      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Observed</div>
                      <div className="mt-1 text-sm font-semibold">{qualityCounts.observed}</div>
                    </div>
                    <div className="rounded-lg border border-border/60 bg-background/30 p-3">
                      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Strong</div>
                      <div className="mt-1 text-sm font-semibold">{qualityCounts.stronglySupported}</div>
                    </div>
                    <div className="rounded-lg border border-border/60 bg-background/30 p-3">
                      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Inferred</div>
                      <div className="mt-1 text-sm font-semibold">{qualityCounts.inferred}</div>
                    </div>
                    <div className="rounded-lg border border-border/60 bg-background/30 p-3">
                      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Weakly inferred</div>
                      <div className="mt-1 text-sm font-semibold">{qualityCounts.weaklyInferred}</div>
                    </div>
                  </div>

                  <div className="rounded-xl border border-border/60 bg-background/30 p-4">
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <div className="text-sm font-semibold">Stage Evidence</div>
                        <div className="text-xs text-muted-foreground">
                          Each stage shows support level, evidence families, and missing evidence for stronger confidence.
                        </div>
                      </div>
                      <Badge variant={scoreVariant(payload.case.score)}>{assessment?.verdict || "Assessment"}</Badge>
                    </div>

                    <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-3">
                      {stageReasoning.length === 0 ? (
                        <div className="text-sm text-muted-foreground">No stage reasoning metadata available yet.</div>
                      ) : (
                        stageReasoning.map((st) => (
                          <div key={st.stage} className="rounded-lg border border-border/60 bg-background/40 p-3">
                            <div className="flex items-center justify-between gap-2">
                              <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                                {stageLabel(st.stage) || st.label || st.stage}
                              </div>
                              <div className="flex items-center gap-2">
                                <Badge variant={evidenceVariant(normalizeEvidenceClass(st.support_level)) as any}>
                                  {evidenceLabel(normalizeEvidenceClass(st.support_level))}
                                </Badge>
                                <Badge variant={Boolean(st.promoted) ? "info" : "neutral"}>
                                  {Boolean(st.promoted) ? "promoted" : "held"}
                                </Badge>
                              </div>
                            </div>
                            <div className="mt-2 text-[11px] text-muted-foreground">
                              confidence {Number(st.confidence) || 0}% · support {Number(st.support_score || 0).toFixed(2)} ·
                              events {Number(st.evidence_count) || 0}
                            </div>
                            {(st.families || []).length ? (
                              <div className="mt-2 flex flex-wrap gap-2">
                                {(st.families || []).map((fam) => (
                                  <span
                                    key={`${st.stage}_${fam}`}
                                    className="inline-flex items-center rounded-md border border-border/60 bg-background/30 px-2 py-1 text-[10px] text-muted-foreground"
                                  >
                                    {fam}
                                  </span>
                                ))}
                              </div>
                            ) : null}
                            {(st.missing_evidence || []).length ? (
                              <div className="mt-2 text-xs text-yellow-500">
                                Missing: {(st.missing_evidence || []).join(" · ")}
                              </div>
                            ) : null}
                          </div>
                        ))
                      )}
                    </div>
                  </div>

                  <div className="rounded-xl border border-border/60 bg-background/30 p-4">
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <div className="text-sm font-semibold">MITRE ATT&CK Coverage</div>
                        <div className="text-xs text-muted-foreground">
                          Summary derived from the case timeline (tactics + techniques + confidence).
                        </div>
                      </div>
                      <Badge variant={confidenceVariant(payload.mitre?.tactics?.[0]?.max_confidence || 0)}>
                        {payload.mitre?.tactics?.reduce((acc, t) => acc + (Number(t.total) || 0), 0) || 0}
                      </Badge>
                    </div>

                    <div className="mt-4">
                      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Progression</div>
                      <div className="mt-2 flex flex-wrap items-center gap-2">
                        {(payload.mitre?.progression || []).length === 0 ? (
                          <div className="text-sm text-muted-foreground">No technique metadata attached to this case yet.</div>
                        ) : (
                          (payload.mitre?.progression || []).map((k) => (
                            <Badge key={k} variant={"neutral" as any}>
                              {stageLabel(k) || k}
                            </Badge>
                          ))
                        )}
                      </div>
                    </div>

                    <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-3">
                      {(payload.mitre?.tactics || []).map((t) => (
                        <div key={t.tactic} className="rounded-lg border border-border/60 bg-background/40 p-3">
                          <div className="flex items-center justify-between gap-2">
                            <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                              {stageLabel(t.tactic) || t.tactic}
                            </div>
                            <div className="flex items-center gap-2">
                              <Badge variant={confidenceVariant(Number(t.max_confidence) || 0) as any}>
                                {Number(t.max_confidence) || 0}%
                              </Badge>
                              <Badge variant={"info" as any}>{Number(t.total) || 0}</Badge>
                            </div>
                          </div>

                          <div className="mt-2 flex flex-wrap gap-2">
                            {(t.techniques || []).slice(0, 12).map((x) => (
                              <div
                                key={x.technique_id}
                                className="inline-flex items-center gap-1 rounded-md border border-border/60 bg-background/50 px-2 py-1"
                                title={x.technique || x.technique_id}
                              >
                                <span className="text-[11px] font-mono text-foreground">{x.technique_id}</span>
                                <span className="text-[11px] text-muted-foreground">×{Number(x.count) || 0}</span>
                              </div>
                            ))}
                            {(t.techniques || []).length > 12 ? (
                              <div className="text-[11px] text-muted-foreground">+{(t.techniques || []).length - 12} more</div>
                            ) : null}
                          </div>
                        </div>
                      ))}
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
                  {payload.steps.map((raw) => (
                    <StepRow key={raw.id} s={buildStepView(raw)} />
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
                          Triage → Assign → Notes → Close. Persisted in the server-backed investigation workspace.
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {workspace ? (
                          <div className="text-[11px] text-muted-foreground font-mono">workspace {workspace.workspace_key}</div>
                        ) : (
                          <div className="text-[11px] text-amber-300 font-mono">no workspace linked</div>
                        )}
                        <button
                          type="button"
                          onClick={() => setPinCaseOpen(true)}
                          className={cx(
                            "rounded-md border border-border/60 bg-background/40",
                            "px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground",
                            "hover:bg-muted/15 hover:text-foreground"
                          )}
                        >
                          Pin case
                        </button>
                      </div>
                    </div>

                    {!workspace ? (
                      <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-3">
                        <button
                          type="button"
                          disabled={wfBusy}
                          onClick={createWorkspaceFromCase}
                          className={cx(
                            "rounded-md border border-border/60 bg-background/40 px-3 py-2 text-xs font-mono uppercase tracking-widest",
                            "hover:bg-muted/15 hover:text-foreground",
                            wfBusy && "opacity-60 cursor-not-allowed"
                          )}
                        >
                          Create workspace from this case
                        </button>
                        <div className="flex items-center gap-2">
                          <select
                            value={attachWorkspaceId ? String(attachWorkspaceId) : ""}
                            onChange={(e) => setAttachWorkspaceId(Number(e.target.value) || null)}
                            className="flex-1 rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm"
                          >
                            <option value="">Select workspace to attach</option>
                            {workspaceChoices.map((ws) => (
                              <option key={ws.id} value={ws.id}>
                                {ws.title} · {ws.workspace_key}
                              </option>
                            ))}
                          </select>
                          <button
                            type="button"
                            disabled={wfBusy || !attachWorkspaceId}
                            onClick={attachWorkspace}
                            className={cx(
                              "rounded-md border border-border/60 bg-background/40 px-3 py-2 text-xs font-mono uppercase tracking-widest",
                              "hover:bg-muted/15 hover:text-foreground",
                              (wfBusy || !attachWorkspaceId) && "opacity-60 cursor-not-allowed"
                            )}
                          >
                            Attach
                          </button>
                        </div>
                      </div>
                    ) : (
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
                              disabled={wfBusy}
                              className={cx(
                                "rounded-md border border-border/60 bg-background/40",
                                "px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground",
                                "hover:bg-muted/15 hover:text-foreground",
                                wfBusy && "opacity-60 cursor-not-allowed"
                              )}
                            >
                              Assign
                            </button>
                          </div>
                        </div>
                      </div>
                    )}
                    {wfError ? <div className="mt-2 text-xs text-red-400">{wfError}</div> : null}
                    {pinResultText ? <div className="mt-2 text-xs text-emerald-400">{pinResultText}</div> : null}
                  </div>

                  {workspace ? (
                    <div className="rounded-xl border border-border/60 bg-background/30 p-4">
                      <div className="flex items-center justify-between gap-3">
                        <div className="text-sm font-semibold">Notes</div>
                      </div>
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
                          disabled={wfBusy}
                          className={cx(
                            "rounded-md border border-border/60 bg-background/40",
                            "px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground",
                            "hover:bg-muted/15 hover:text-foreground",
                            wfBusy && "opacity-60 cursor-not-allowed"
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
                                  {n.author ? `${n.author} · ` : ""}{fmtTs(n.created_at)}
                                </div>
                              </div>
                              <div className="mt-2 whitespace-pre-wrap break-words text-sm font-mono">{n.body}</div>
                            </div>
                          ))
                        )}
                      </div>
                    </div>
                  ) : null}

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

      {payload ? (
        <PinToWorkspaceDrawer
          open={pinCaseOpen}
          onClose={() => setPinCaseOpen(false)}
          title={`attack chain case #${payload.case.id}`}
          defaultWorkspaceTitle={`Attack Chain Case #${payload.case.id}`}
          workspaceDefaults={{
            linked_attack_chain_case_id: payload.case.id,
            primary_agent_id: payload.case.agent_id,
            triage_state: "triage",
            priority: "p2",
            severity: payload.case.score >= 80 ? "critical" : payload.case.score >= 60 ? "high" : "medium",
          }}
          onPin={async (workspaceId, options) => {
            const result = await pinAttackChainCaseToWorkspace(workspaceId, payload.case.id, {
              ...options,
              source_module: "attack_chain",
            });
            setPinResultText(result.created ? "Case pinned to workspace." : "Case already pinned in this workspace.");
            await loadWorkspaceState(payload.case.id);
            return result;
          }}
        />
      ) : null}

      {payload && pinStepId ? (
        <PinToWorkspaceDrawer
          open={Boolean(pinStepId)}
          onClose={() => setPinStepId(null)}
          title={`attack chain step #${pinStepId}`}
          defaultWorkspaceTitle={`Attack Chain Case #${payload.case.id}`}
          workspaceDefaults={{
            linked_attack_chain_case_id: payload.case.id,
            primary_agent_id: payload.case.agent_id,
            triage_state: "triage",
            priority: "p2",
            severity: payload.case.score >= 80 ? "critical" : payload.case.score >= 60 ? "high" : "medium",
          }}
          onPin={async (workspaceId, options) => {
            const stepId = pinStepId;
            if (!stepId) {
              return { created: false, duplicate_of_id: null };
            }
            const result = await pinAttackChainStepToWorkspace(workspaceId, stepId, {
              ...options,
              source_module: "attack_chain",
            });
            setPinResultText(result.created ? `Step #${stepId} pinned to workspace.` : `Step #${stepId} is already pinned.`);
            await loadWorkspaceState(payload.case.id);
            return result;
          }}
        />
      ) : null}
    </Drawer>
  );
}
