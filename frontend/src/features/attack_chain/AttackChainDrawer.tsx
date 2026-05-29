import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { Badge } from "@/shared/components/Badge";
import { Button } from "@/shared/components/Button";
import Drawer from "@/shared/components/Drawer";
import { InlineAlert } from "@/shared/components/InlineAlert";
import { JsonBlock } from "@/shared/components/JsonBlock";
import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { SelectInput } from "@/shared/components/SelectInput";
import { SeverityPill } from "@/shared/components/SeverityPill";
import { StatusPill } from "@/shared/components/StatusPill";
import { TextArea } from "@/shared/components/TextArea";
import { TextInput } from "@/shared/components/TextInput";
import {
  InvestigationActionBar,
  InvestigationActionButton,
  InvestigationListItem,
  InvestigationMetaStrip,
  InvestigationSection,
  InvestigationShell,
  InvestigationTabs,
  formatInvestigationTimestamp,
} from "@/shared/components/investigation";
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
  return formatInvestigationTimestamp(iso);
}

function scoreVariant(score: number) {
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

  const setWorkflowFromWorkspace = useCallback((ws: InvestigationWorkspace | null, notes: InvestigationNote[]) => {
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
  }, []);

  const loadWorkspaceState = useCallback(async (caseIdValue: number) => {
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
  }, [setWorkflowFromWorkspace]);

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
  }, [open, caseId, initialStepId, loadWorkspaceState]);

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
      <div id={`attack-step-${s.id}`}>
        <InvestigationListItem
          title={s.title}
          description={s.description || undefined}
          active={isFocused}
          badges={[
            { label: stageLabel(s.stage), variant: "info" },
            ...(s.scoreDelta ? [{ label: `+${s.scoreDelta}`, variant: scoreVariant(Math.max(0, s.scoreDelta)) as any }] : []),
            ...(s.techniqueId ? [{ label: s.techniqueId, variant: "neutral" as const }] : []),
            { label: evidenceLabel(s.evidenceClass), variant: evidenceVariant(s.evidenceClass) as any },
            { label: s.evidenceNature, variant: s.evidenceNature === "direct" ? "info" : "neutral" },
            ...(s.confidence ? [{ label: confidenceLabel(s.confidence), variant: confidenceVariant(s.confidence) as any }] : []),
          ]}
          meta={[
            { label: "time", value: fmtTs(s.at) },
            { label: "kind", value: s.kind || "-" },
          ]}
          actions={
            <div className="space-y-2 text-right">
              <Button variant="subtle" size="sm" onClick={() => setPinStepId(s.id)}>
                Pin step
              </Button>
              {s.transition.reason ? (
                <div className="max-w-[220px] text-[10px] text-muted-foreground">{s.transition.reason}</div>
              ) : null}
            </div>
          }
        >
          {s.confidenceFactors.length ? (
            <div className="flex flex-wrap gap-1.5">
              {s.confidenceFactors.map((f) => (
                <span
                  key={f}
                  className="inline-flex items-center rounded-md border border-border bg-surface-2 px-2 py-0.5 font-mono text-[10.5px] text-muted-foreground"
                >
                  {f}
                </span>
              ))}
            </div>
          ) : null}
          {s.missingEvidence.length ? (
            <div className="mt-2 text-xs text-warning">
              Missing for stronger confidence: {s.missingEvidence.join(" · ")}
            </div>
          ) : null}
          {s.raw?.details ? (
            <details className="mt-3">
              <summary className="cursor-pointer text-xs text-muted-foreground hover:text-foreground">Details (JSON)</summary>
              <JsonBlock value={s.raw.details} showControls={false} className="mt-2" />
            </details>
          ) : null}
        </InvestigationListItem>
      </div>
    );
  }

  return (
    <Drawer open={open} title={title} description={description} onClose={onClose} widthClassName="w-[920px]" headerLabel="Attack chain">
      {loading ? <Loading label="Loading case" /> : null}

      {!loading && error ? (
        <EmptyState title="FAILED" hint={error} />
      ) : null}

      {!loading && !error && payload ? (
        <InvestigationShell>
          <InvestigationMetaStrip
            items={[
              { label: "Status", value: <StatusPill variant={statusPillVariant(payload.case.status)} withDot>{payload.case.status}</StatusPill> },
              { label: "Score", value: <SeverityPill variant={scoreVariant(payload.case.score)} withDot>{payload.case.score}</SeverityPill> },
              { label: "Max stage", value: stageLabel(payload.case.max_stage) },
              { label: "Agent", value: payload.case.agent_id },
              { label: "Suspect", value: payload.case.suspect_ip || "-" },
              { label: "Observed", value: String(qualityCounts.observed) },
              { label: "Strong", value: String(qualityCounts.stronglySupported) },
              { label: "Inferred", value: String(qualityCounts.inferred) },
              { label: "Workflow", value: workspace ? <WorkflowBadge wf={wf} /> : "no workspace" },
              { label: "Workspace key", value: workspace?.workspace_key || "-" },
              { label: "Assignee", value: wf.assignee || "-" },
              { label: "Notes", value: String(wf.notes.length) },
            ]}
          />

          <InvestigationActionBar>
            <InvestigationActionButton onClick={() => setPinCaseOpen(true)} tone="primary">
              Pin case
            </InvestigationActionButton>
            <InvestigationActionButton
              onClick={doCloseCase}
              disabled={!isAdmin || payload.case.status !== "open" || closeBusy}
            >
              {closeBusy ? "Closing..." : "Close case"}
            </InvestigationActionButton>
          </InvestigationActionBar>

          <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
            <div className="ui-card-shell p-4">
              <FieldLabel>Case</FieldLabel>
              <div className="mt-2 space-y-1.5 text-sm">
                <div className="flex items-center justify-between gap-3">
                  <div className="text-muted-foreground">Agent</div>
                  <div className="truncate font-mono text-foreground">{payload.case.agent_id}</div>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <div className="text-muted-foreground">Suspect</div>
                  <div className="truncate font-mono text-foreground">{payload.case.suspect_ip || "-"}</div>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <div className="text-muted-foreground">Steps</div>
                  <div className="font-mono text-foreground">{payload.case.step_count}</div>
                </div>
              </div>
            </div>

            <div className="ui-card-shell p-4">
              <FieldLabel>Window</FieldLabel>
              <div className="mt-2 space-y-1.5 text-sm">
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

            <div className="ui-card-shell p-4">
              <FieldLabel>Stage progress</FieldLabel>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {STAGES.map((st, idx) => {
                  const reached = idx <= maxStageRank;
                  return (
                    <span
                      key={st.key}
                      className={cx(
                        "inline-flex items-center rounded-md border px-2 py-1 font-mono text-[11px]",
                        reached
                          ? "border-primary/45 bg-primary/12 text-foreground"
                          : "border-border bg-surface-2 text-muted-foreground",
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
            <InvestigationSection title="Assessment">
              <div className="mt-2 flex items-center gap-2 flex-wrap">
                <Badge variant={scoreVariant(payload.case.score)}>{assessment.verdict}</Badge>
                <span className="text-sm text-muted-foreground">{assessment.hint}</span>
              </div>
            </InvestigationSection>
          ) : null}

          <InvestigationTabs
            value={tab}
            onChange={setTab}
            tabs={[
              { key: "overview", label: "Overview" },
              { key: "timeline", label: "Timeline" },
              { key: "investigation", label: "Investigation" },
            ]}
          />

          <div>
              {tab === "overview" ? (
                <div className="space-y-3">
                  <div className="text-sm text-muted-foreground">
                    This case links telemetry into an ATT&CK-aligned chain while preserving evidence quality and transition guardrails.
                  </div>

                  <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
                    <div className="ui-card-shell p-3">
                      <FieldLabel>Max stage</FieldLabel>
                      <div className="mt-1 text-sm font-semibold">{stageLabel(payload.case.max_stage)}</div>
                      <div className="mt-1 text-[11px] text-muted-foreground">
                        {STAGES.find((x) => x.key === payload.case.max_stage)?.hint || "-"}
                      </div>
                    </div>
                    <div className="ui-card-shell p-3">
                      <FieldLabel>Score</FieldLabel>
                      <div className="mt-1 text-sm font-semibold">{payload.case.score}</div>
                      <div className="mt-1 text-[11px] text-muted-foreground">
                        Score is weighted by evidence quality. Weak inferred signals are intentionally capped.
                      </div>
                    </div>
                    <div className="ui-card-shell p-3">
                      <FieldLabel>Steps</FieldLabel>
                      <div className="mt-1 text-sm font-semibold">{payload.steps.length}</div>
                      <div className="mt-1 text-[11px] text-muted-foreground">Timeline signals used to compute the chain.</div>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
                    <div className="ui-card-shell p-3">
                      <FieldLabel>Observed</FieldLabel>
                      <div className="mt-1 text-sm font-semibold text-success">{qualityCounts.observed}</div>
                    </div>
                    <div className="ui-card-shell p-3">
                      <FieldLabel>Strong</FieldLabel>
                      <div className="mt-1 text-sm font-semibold">{qualityCounts.stronglySupported}</div>
                    </div>
                    <div className="ui-card-shell p-3">
                      <FieldLabel>Inferred</FieldLabel>
                      <div className="mt-1 text-sm font-semibold text-warning">{qualityCounts.inferred}</div>
                    </div>
                    <div className="ui-card-shell p-3">
                      <FieldLabel>Weakly inferred</FieldLabel>
                      <div className="mt-1 text-sm font-semibold text-muted-foreground">{qualityCounts.weaklyInferred}</div>
                    </div>
                  </div>

                  <div className="ui-card-shell p-4">
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <div className="text-sm font-semibold">Stage evidence</div>
                        <div className="text-xs text-muted-foreground">
                          Each stage shows support level, evidence families, and missing evidence for stronger confidence.
                        </div>
                      </div>
                      <SeverityPill variant={scoreVariant(payload.case.score)}>{assessment?.verdict || "Assessment"}</SeverityPill>
                    </div>

                    <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2">
                      {stageReasoning.length === 0 ? (
                        <div className="text-sm text-muted-foreground">No stage reasoning metadata available yet.</div>
                      ) : (
                        stageReasoning.map((st) => (
                          <div key={st.stage} className="rounded-md border border-border bg-surface-2/50 p-3">
                            <div className="flex items-center justify-between gap-2">
                              <FieldLabel>{stageLabel(st.stage) || st.label || st.stage}</FieldLabel>
                              <div className="flex items-center gap-1.5">
                                <SeverityPill variant={evidenceVariant(normalizeEvidenceClass(st.support_level)) as any}>
                                  {evidenceLabel(normalizeEvidenceClass(st.support_level))}
                                </SeverityPill>
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
                              <div className="mt-2 flex flex-wrap gap-1.5">
                                {(st.families || []).map((fam) => (
                                  <span
                                    key={`${st.stage}_${fam}`}
                                    className="inline-flex items-center rounded-md border border-border bg-card px-2 py-0.5 font-mono text-[10.5px] text-muted-foreground"
                                  >
                                    {fam}
                                  </span>
                                ))}
                              </div>
                            ) : null}
                            {(st.missing_evidence || []).length ? (
                              <div className="mt-2 text-xs text-warning">
                                Missing: {(st.missing_evidence || []).join(" · ")}
                              </div>
                            ) : null}
                          </div>
                        ))
                      )}
                    </div>
                  </div>

                  <div className="ui-card-shell p-4">
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <div className="text-sm font-semibold">MITRE ATT&CK coverage</div>
                        <div className="text-xs text-muted-foreground">
                          Summary derived from the case timeline (tactics + techniques + confidence).
                        </div>
                      </div>
                      <SeverityPill variant={confidenceVariant(payload.mitre?.tactics?.[0]?.max_confidence || 0)}>
                        {payload.mitre?.tactics?.reduce((acc, t) => acc + (Number(t.total) || 0), 0) || 0} events
                      </SeverityPill>
                    </div>

                    <div className="mt-3">
                      <FieldLabel>Progression</FieldLabel>
                      <div className="mt-2 flex flex-wrap items-center gap-1.5">
                        {(payload.mitre?.progression || []).length === 0 ? (
                          <div className="text-sm text-muted-foreground">No technique metadata attached to this case yet.</div>
                        ) : (
                          (payload.mitre?.progression || []).map((k) => (
                            <Badge key={k} variant="neutral">
                              {stageLabel(k) || k}
                            </Badge>
                          ))
                        )}
                      </div>
                    </div>

                    <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-2">
                      {(payload.mitre?.tactics || []).map((t) => (
                        <div key={t.tactic} className="rounded-md border border-border bg-surface-2/50 p-3">
                          <div className="flex items-center justify-between gap-2">
                            <FieldLabel>{stageLabel(t.tactic) || t.tactic}</FieldLabel>
                            <div className="flex items-center gap-1.5">
                              <SeverityPill variant={confidenceVariant(Number(t.max_confidence) || 0) as any}>
                                {Number(t.max_confidence) || 0}%
                              </SeverityPill>
                              <Badge variant="info">{Number(t.total) || 0}</Badge>
                            </div>
                          </div>

                          <div className="mt-2 flex flex-wrap gap-1.5">
                            {(t.techniques || []).slice(0, 12).map((x) => (
                              <div
                                key={x.technique_id}
                                className="inline-flex items-center gap-1 rounded-md border border-border bg-card px-2 py-0.5"
                                title={x.technique || x.technique_id}
                              >
                                <span className="font-mono text-[11px] text-foreground">{x.technique_id}</span>
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
                      <JsonBlock value={payload.case.context} showControls={false} className="mt-2" />
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
                  <div className="ui-card-shell p-4">
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <div className="text-sm font-semibold">Investigation workflow</div>
                        <div className="text-xs text-muted-foreground">
                          Triage → Assign → Notes → Close. Persisted in the server-backed investigation workspace.
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {workspace ? (
                          <span className="font-mono text-[11px] text-muted-foreground">workspace {workspace.workspace_key}</span>
                        ) : (
                          <span className="font-mono text-[11px] text-warning">no workspace linked</span>
                        )}
                        <Button variant="secondary" size="md" onClick={() => setPinCaseOpen(true)}>
                          Pin case
                        </Button>
                      </div>
                    </div>

                    {!workspace ? (
                      <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2">
                        <Button variant="primary" size="md" disabled={wfBusy} onClick={createWorkspaceFromCase}>
                          Create workspace from this case
                        </Button>
                        <div className="flex items-center gap-2">
                          <SelectInput
                            value={attachWorkspaceId ? String(attachWorkspaceId) : ""}
                            onChange={(e) => setAttachWorkspaceId(Number(e.target.value) || null)}
                            className="flex-1"
                          >
                            <option value="">Select workspace to attach</option>
                            {workspaceChoices.map((ws) => (
                              <option key={ws.id} value={ws.id}>
                                {ws.title} · {ws.workspace_key}
                              </option>
                            ))}
                          </SelectInput>
                          <Button variant="secondary" size="md" disabled={wfBusy || !attachWorkspaceId} onClick={attachWorkspace}>
                            Attach
                          </Button>
                        </div>
                      </div>
                    ) : (
                      <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-3">
                        <div>
                          <FieldLabel>Triage</FieldLabel>
                          <SelectInput
                            className="mt-1"
                            value={wf.triage}
                            onChange={(e) => applyTriage(e.target.value as TriageState)}
                          >
                            <option value="untriaged">Untriaged</option>
                            <option value="triage">Triage</option>
                            <option value="assigned">Assigned</option>
                            <option value="investigating">Investigating</option>
                            <option value="contained">Contained</option>
                            <option value="closed">Closed</option>
                          </SelectInput>
                        </div>

                        <div>
                          <FieldLabel>Priority</FieldLabel>
                          <SelectInput
                            className="mt-1"
                            value={wf.priority}
                            onChange={(e) => applyPriority(e.target.value as Priority)}
                          >
                            <option value="p1">P1 (critical)</option>
                            <option value="p2">P2 (high)</option>
                            <option value="p3">P3 (medium)</option>
                            <option value="p4">P4 (low)</option>
                          </SelectInput>
                        </div>

                        <div>
                          <FieldLabel>Assignee</FieldLabel>
                          <div className="mt-1 flex items-center gap-2">
                            <TextInput
                              value={assigneeDraft}
                              onChange={(e) => setAssigneeDraft(e.target.value)}
                              placeholder="e.g. admin"
                              className="flex-1"
                            />
                            <Button variant="secondary" size="md" onClick={applyAssignee} disabled={wfBusy}>
                              Assign
                            </Button>
                          </div>
                        </div>
                      </div>
                    )}
                    {wfError ? <InlineAlert tone="danger" className="mt-3 text-xs">{wfError}</InlineAlert> : null}
                    {pinResultText ? <InlineAlert tone="success" className="mt-3 text-xs">{pinResultText}</InlineAlert> : null}
                  </div>

                  {workspace ? (
                    <div className="ui-card-shell p-4">
                      <div className="text-sm font-semibold">Notes</div>
                      <div className="mt-3 flex items-start gap-2">
                        <TextArea
                          value={noteText}
                          onChange={(e) => setNoteText(e.target.value)}
                          rows={3}
                          placeholder="Add investigation notes, indicators, or next steps..."
                          className="flex-1 font-mono"
                        />
                        <Button variant="primary" size="md" onClick={addNote} disabled={wfBusy}>
                          Add
                        </Button>
                      </div>

                      <div className="mt-4 space-y-2">
                        {wf.notes.length === 0 ? (
                          <div className="text-sm text-muted-foreground">No notes yet.</div>
                        ) : (
                          wf.notes.map((n) => (
                            <div key={n.id} className="rounded-md border border-border bg-surface-2/50 p-3">
                              <div className="font-mono text-[11px] text-muted-foreground">
                                {n.author ? `${n.author} · ` : ""}{fmtTs(n.created_at)}
                              </div>
                              <div className="mt-2 whitespace-pre-wrap break-words font-mono text-sm">{n.body}</div>
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
                    <Button
                      variant={!isAdmin || payload.case.status !== "open" ? "subtle" : "danger"}
                      size="md"
                      onClick={doCloseCase}
                      disabled={!isAdmin || payload.case.status !== "open" || closeBusy}
                      title={!isAdmin ? "Admin required" : payload.case.status !== "open" ? "Already closed" : "Close case"}
                    >
                      {closeBusy ? "Closing…" : "Close case"}
                    </Button>
                  </div>
                  {closeError ? <InlineAlert tone="danger" className="text-xs">{closeError}</InlineAlert> : null}
                </div>
              ) : null}
          </div>
        </InvestigationShell>
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
