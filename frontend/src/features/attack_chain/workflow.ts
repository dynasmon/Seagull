export type TriageState = "untriaged" | "triage" | "assigned" | "investigating" | "contained" | "closed";
export type Priority = "p1" | "p2" | "p3" | "p4";

export type WorkflowNote = {
  id: string;
  at: string; // ISO
  author: string;
  text: string;
};

export type InvestigationWorkflow = {
  version: 1;
  triage: TriageState;
  priority: Priority;
  assignee: string;
  notes: WorkflowNote[];
  updated_at: string; // ISO
};

const KEY_PREFIX = "nw.attack_chain.workflow.v1.";

function nowIso() {
  return new Date().toISOString();
}

function safeParseJson(s: string | null): any {
  if (!s) return null;
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}

function normalizeNote(n: any): WorkflowNote | null {
  if (!n || typeof n !== "object") return null;
  const id = String((n as any).id || "").trim();
  const at = String((n as any).at || "").trim();
  const author = String((n as any).author || "").trim();
  const text = String((n as any).text || "").trim();
  if (!id || !at || !text) return null;
  return { id, at, author, text };
}

function normalizeWorkflow(x: any): InvestigationWorkflow {
  const triage = String((x as any)?.triage || "untriaged") as TriageState;
  const priority = String((x as any)?.priority || "p3") as Priority;
  const assignee = String((x as any)?.assignee || "");
  const notesRaw = Array.isArray((x as any)?.notes) ? (x as any).notes : [];
  const notes = notesRaw.map(normalizeNote).filter(Boolean) as WorkflowNote[];
  const updated_at = String((x as any)?.updated_at || "") || nowIso();

  const triageOk: TriageState[] = ["untriaged", "triage", "assigned", "investigating", "contained", "closed"];
  const prioOk: Priority[] = ["p1", "p2", "p3", "p4"];

  return {
    version: 1,
    triage: triageOk.includes(triage) ? triage : "untriaged",
    priority: prioOk.includes(priority) ? priority : "p3",
    assignee,
    notes,
    updated_at,
  };
}

function uuid(): string {
  // Use crypto.randomUUID when available.
  // Fallback keeps collisions extremely unlikely for our use case.
  const c = (globalThis as any).crypto;
  if (c && typeof c.randomUUID === "function") return c.randomUUID();
  return `note_${Math.random().toString(16).slice(2)}_${Date.now().toString(16)}`;
}

export function loadWorkflow(caseId: number): InvestigationWorkflow {
  try {
    const raw = localStorage.getItem(KEY_PREFIX + String(caseId));
    const parsed = safeParseJson(raw);
    return normalizeWorkflow(parsed);
  } catch {
    return normalizeWorkflow(null);
  }
}

export function saveWorkflow(caseId: number, wf: InvestigationWorkflow) {
  try {
    localStorage.setItem(KEY_PREFIX + String(caseId), JSON.stringify({ ...wf, updated_at: nowIso() }));
  } catch {
    // no-op
  }
}

export function clearWorkflow(caseId: number) {
  try {
    localStorage.removeItem(KEY_PREFIX + String(caseId));
  } catch {
    // no-op
  }
}

export function setWorkflowTriage(caseId: number, triage: TriageState) {
  const wf = loadWorkflow(caseId);
  const next: InvestigationWorkflow = { ...wf, triage, updated_at: nowIso() };
  saveWorkflow(caseId, next);
  return next;
}

export function setWorkflowPriority(caseId: number, priority: Priority) {
  const wf = loadWorkflow(caseId);
  const next: InvestigationWorkflow = { ...wf, priority, updated_at: nowIso() };
  saveWorkflow(caseId, next);
  return next;
}

export function setWorkflowAssignee(caseId: number, assignee: string) {
  const wf = loadWorkflow(caseId);
  const next: InvestigationWorkflow = { ...wf, assignee: assignee.trim(), updated_at: nowIso() };
  saveWorkflow(caseId, next);
  return next;
}

export function addWorkflowNote(caseId: number, note: { author: string; text: string }) {
  const wf = loadWorkflow(caseId);
  const n: WorkflowNote = {
    id: uuid(),
    at: nowIso(),
    author: (note.author || "").trim(),
    text: (note.text || "").trim(),
  };
  const next: InvestigationWorkflow = { ...wf, notes: [n, ...wf.notes], updated_at: nowIso() };
  saveWorkflow(caseId, next);
  return next;
}
