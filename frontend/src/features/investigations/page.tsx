import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import Drawer from "@/shared/components/Drawer";
import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import PageHeader from "@/shared/components/PageHeader";
import { Badge } from "@/shared/components/Badge";
import { cx } from "@/shared/lib/cx";
import { usePortalRealtimeSubscription } from "@/shared/realtime";

import {
  closeInvestigationWorkspace,
  createInvestigationNote,
  createInvestigationWorkspace,
  deleteInvestigationBookmark,
  getInvestigationWorkspace,
  listInvestigationActivity,
  listInvestigationBookmarks,
  listInvestigationNotes,
  listInvestigationWorkspaces,
  reopenInvestigationWorkspace,
  updateInvestigationNote,
  updateInvestigationWorkspace,
} from "./api";
import type {
  InvestigationActivityEntry,
  InvestigationBookmark,
  InvestigationNote,
  InvestigationWorkspaceUpdateIn,
  InvestigationWorkspace,
  InvestigationWorkspacePriority,
  InvestigationWorkspaceSeverity,
  InvestigationWorkspaceStatus,
  InvestigationWorkspaceTriage,
} from "./types";

type Filters = {
  status: "all" | InvestigationWorkspaceStatus;
  severity: "all" | InvestigationWorkspaceSeverity;
  priority: "all" | InvestigationWorkspacePriority;
  assignee: string;
  agentId: string;
  linkedCaseId: string;
  search: string;
};
const INVESTIGATIONS_RT_BURST_WINDOW_MS = 1000;
const INVESTIGATIONS_RT_BURST_LIMIT = 80;

function fmtTs(iso?: string | null) {
  if (!iso) return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")} ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
}

function severityVariant(v: string) {
  if (v === "critical") return "critical";
  if (v === "high") return "high";
  if (v === "medium") return "medium";
  if (v === "low") return "low";
  return "neutral";
}

function statusVariant(v: string) {
  if (v === "open") return "info";
  if (v === "contained") return "low";
  if (v === "resolved") return "medium";
  return "neutral";
}

function evidenceVariant(v: string) {
  if (v === "attack_chain_step" || v === "attack_chain_case") return "high";
  if (v === "response_action_result") return "info";
  if (v === "protocol_intel") return "medium";
  if (v === "inventory_snapshot") return "low";
  return "neutral";
}

function parseOptionalPositiveInt(raw: string): number | null {
  const text = String(raw || "").trim();
  if (!text) return null;
  const n = Number(text);
  if (!Number.isFinite(n) || n <= 0) return null;
  return Math.trunc(n);
}

function activityVariant(activityType: InvestigationActivityEntry["activity_type"]) {
  if (activityType === "workspace_closed") return "critical";
  if (activityType === "workspace_reopened") return "info";
  if (activityType === "attack_chain_case_linked" || activityType === "attack_chain_step_pinned") return "high";
  if (activityType === "bookmark_created" || activityType === "note_created") return "medium";
  if (activityType === "bookmark_deleted") return "low";
  return "neutral";
}

function activityLabel(activityType: InvestigationActivityEntry["activity_type"]) {
  if (activityType === "workspace_created") return "Workspace created";
  if (activityType === "workspace_updated") return "Workspace updated";
  if (activityType === "workspace_closed") return "Workspace closed";
  if (activityType === "workspace_reopened") return "Workspace reopened";
  if (activityType === "note_created") return "Note created";
  if (activityType === "note_updated") return "Note updated";
  if (activityType === "bookmark_created") return "Bookmark created";
  if (activityType === "bookmark_deleted") return "Bookmark deleted";
  if (activityType === "attack_chain_case_linked") return "Attack chain case linked";
  if (activityType === "attack_chain_step_pinned") return "Attack chain step pinned";
  return "Workspace action";
}

function normalizeActivityType(value: unknown): InvestigationActivityEntry["activity_type"] {
  const v = String(value || "").trim();
  if (v === "workspace_created") return "workspace_created";
  if (v === "workspace_updated") return "workspace_updated";
  if (v === "workspace_closed") return "workspace_closed";
  if (v === "workspace_reopened") return "workspace_reopened";
  if (v === "note_created") return "note_created";
  if (v === "note_updated") return "note_updated";
  if (v === "bookmark_created") return "bookmark_created";
  if (v === "bookmark_deleted") return "bookmark_deleted";
  if (v === "attack_chain_case_linked") return "attack_chain_case_linked";
  if (v === "attack_chain_step_pinned") return "attack_chain_step_pinned";
  return "workspace_action";
}

function parseCaseId(raw: string): number | undefined {
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return undefined;
  return Math.trunc(n);
}

function asRecord(value: unknown): Record<string, unknown> {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return {};
}

function str(value: unknown, fallback = "-"): string {
  if (value === null || value === undefined) return fallback;
  return String(value);
}

function renderEvidenceCardContent(b: InvestigationBookmark) {
  const p = asRecord(b.payload_snapshot);

  if (b.evidence_type === "net_event") {
    return (
      <div className="text-[11px] text-muted-foreground">
        <div>{fmtTs(str(p["timestamp"], ""))}</div>
        <div>agent {str(p["agent_id"])} · {str(p["event_type"])}</div>
        <div>{str(p["src_ip"])}:{str(p["src_port"])} → {str(p["dst_ip"])}:{str(p["dst_port"])} · {str(p["proto"])}</div>
      </div>
    );
  }

  if (b.evidence_type === "protocol_intel") {
    return (
      <div className="text-[11px] text-muted-foreground">
        <div>{fmtTs(str(p["timestamp"], ""))}</div>
        <div>app {str(p["app_proto"])} · agent {str(p["agent_id"])}</div>
        <div>host {str(p["http_host"] || p["dns_qname"] || p["tls_sni"])}</div>
        <div>ja3 {str(p["ja3"])} · ja4 {str(p["ja4"])}</div>
      </div>
    );
  }

  if (b.evidence_type === "inventory_snapshot") {
    const os = asRecord(p["os_summary"]);
    return (
      <div className="text-[11px] text-muted-foreground">
        <div>{fmtTs(str(p["collected_at"], ""))}</div>
        <div>agent {str(p["agent_id"])} · manager {str(p["manager"])}</div>
        <div>packages {str(p["packages_count"])} · hash {str(p["packages_hash"])}</div>
        <div>os {str(os["pretty_name"] || os["name"] || os["id"])}</div>
      </div>
    );
  }

  if (b.evidence_type === "response_action_result") {
    return (
      <div className="text-[11px] text-muted-foreground">
        <div>action {str(p["action_type"])} · result {str(p["result_status"])}</div>
        <div>agent {str(p["agent_id"])} · started {fmtTs(str(p["started_at"], ""))}</div>
        <div>finished {fmtTs(str(p["finished_at"], ""))}</div>
        <div>{str(p["error"], "") || "No error"}</div>
      </div>
    );
  }

  if (b.evidence_type === "attack_chain_case") {
    return (
      <div className="text-[11px] text-muted-foreground">
        <div>case #{str(p["case_id"])} · status {str(p["status"])}</div>
        <div>score {str(p["score"])} · stage {str(p["max_stage"])}</div>
        <div>agent {str(p["agent_id"])} · suspect {str(p["suspect_ip"])}</div>
      </div>
    );
  }

  if (b.evidence_type === "attack_chain_step") {
    return (
      <div className="text-[11px] text-muted-foreground">
        <div>step #{str(p["step_id"])} · case #{str(p["case_id"])}</div>
        <div>stage {str(p["stage"])} · {str(p["label"])}</div>
        <div>{fmtTs(str(p["timestamp"], ""))}</div>
      </div>
    );
  }

  return <div className="text-[11px] text-muted-foreground">Unsupported evidence payload.</div>;
}

function WorkspaceDrawer({
  workspaceId,
  open,
  onClose,
  onUpdated,
}: {
  workspaceId: number | null;
  open: boolean;
  onClose: () => void;
  onUpdated: (next: InvestigationWorkspace) => void;
}) {
  const [tab, setTab] = useState<"overview" | "notes" | "evidence" | "timeline">("overview");

  const [workspace, setWorkspace] = useState<InvestigationWorkspace | null>(null);
  const [notes, setNotes] = useState<InvestigationNote[]>([]);
  const [bookmarks, setBookmarks] = useState<InvestigationBookmark[]>([]);
  const [activity, setActivity] = useState<InvestigationActivityEntry[]>([]);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [noteText, setNoteText] = useState("");
  const [noteEditId, setNoteEditId] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [saveBusy, setSaveBusy] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saveSuccess, setSaveSuccess] = useState<string | null>(null);
  const realtimeBurstWindowStartRef = useRef(0);
  const realtimeBurstCountRef = useRef(0);
  const realtimeRefreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [edit, setEdit] = useState<{
    title: string;
    description: string;
    status: InvestigationWorkspaceStatus;
    severity: InvestigationWorkspaceSeverity;
    priority: InvestigationWorkspacePriority;
    assignee: string;
    primaryAgentId: string;
    linkedCaseId: string;
  }>({
    title: "",
    description: "",
    status: "open",
    severity: "medium",
    priority: "p3",
    assignee: "",
    primaryAgentId: "",
    linkedCaseId: "",
  });

  const syncEditForm = useCallback((ws: InvestigationWorkspace) => {
    setEdit({
      title: ws.title || "",
      description: ws.description || "",
      status: ws.status,
      severity: ws.severity,
      priority: ws.priority,
      assignee: ws.assignee || "",
      primaryAgentId: ws.primary_agent_id || "",
      linkedCaseId: ws.linked_attack_chain_case_id ? String(ws.linked_attack_chain_case_id) : "",
    });
  }, []);

  useEffect(() => {
    if (!open || !workspaceId) return;

    setLoading(true);
    setError(null);
    setTab("overview");
    setSaveError(null);
    setSaveSuccess(null);

    Promise.all([
      getInvestigationWorkspace(workspaceId),
      listInvestigationNotes(workspaceId, { limit: 300 }),
      listInvestigationBookmarks(workspaceId, { page_size: 200 }),
      listInvestigationActivity(workspaceId, { page_size: 200 }),
    ])
      .then(([ws, ns, bs, feed]) => {
        setWorkspace(ws);
        syncEditForm(ws);
        setNotes(ns || []);
        setBookmarks(bs.items || []);
        setActivity(feed.items || []);
      })
      .catch((e: any) => {
        setError(e?.message || "Failed to load workspace");
        setWorkspace(null);
        setNotes([]);
        setBookmarks([]);
        setActivity([]);
      })
      .finally(() => setLoading(false));
  }, [open, workspaceId, syncEditForm]);

  async function refresh() {
    if (!workspaceId) return;
    const [ws, ns, bs, feed] = await Promise.all([
      getInvestigationWorkspace(workspaceId),
      listInvestigationNotes(workspaceId, { limit: 300 }),
      listInvestigationBookmarks(workspaceId, { page_size: 200 }),
      listInvestigationActivity(workspaceId, { page_size: 200 }),
    ]);
    setWorkspace(ws);
    syncEditForm(ws);
    setNotes(ns || []);
    setBookmarks(bs.items || []);
    setActivity(feed.items || []);
    onUpdated(ws);
  }

  const scheduleRealtimeRefresh = useCallback(() => {
    if (realtimeRefreshTimerRef.current) return;
    realtimeRefreshTimerRef.current = window.setTimeout(() => {
      realtimeRefreshTimerRef.current = null;
      void refresh();
    }, 300);
  }, [refresh]);

  useEffect(() => {
    return () => {
      if (!realtimeRefreshTimerRef.current) return;
      window.clearTimeout(realtimeRefreshTimerRef.current);
      realtimeRefreshTimerRef.current = null;
    };
  }, []);

  usePortalRealtimeSubscription("ui.investigations.timeline.append", (event) => {
    const now = Date.now();
    if ((now - realtimeBurstWindowStartRef.current) > INVESTIGATIONS_RT_BURST_WINDOW_MS) {
      realtimeBurstWindowStartRef.current = now;
      realtimeBurstCountRef.current = 0;
    }
    realtimeBurstCountRef.current += 1;
    if (realtimeBurstCountRef.current > INVESTIGATIONS_RT_BURST_LIMIT) {
      scheduleRealtimeRefresh();
      return;
    }

    const activeWorkspaceId = workspaceId ? Number(workspaceId) : 0;
    if (activeWorkspaceId <= 0) return;
    const eventWorkspaceId = Number(event.payload?.workspace_id ?? 0);
    if (eventWorkspaceId !== activeWorkspaceId) return;

    const activityPatch = event.payload?.activity;
    const activityId = String(activityPatch?.id || "").trim();
    const createdAt = String(activityPatch?.created_at || "").trim();
    if (activityId && createdAt) {
      const appended: InvestigationActivityEntry = {
        id: activityId,
        workspace_id: activeWorkspaceId,
        activity_type: normalizeActivityType(activityPatch?.activity_type),
        action: String(activityPatch?.action || "workspace.action"),
        actor_username: activityPatch?.actor_username ? String(activityPatch.actor_username) : null,
        created_at: createdAt,
        outcome: String(activityPatch?.outcome || "success"),
        target_type: activityPatch?.target_type ? String(activityPatch.target_type) : null,
        target_id: activityPatch?.target_id ? String(activityPatch.target_id) : null,
        summary: String(activityPatch?.summary || "Workspace activity"),
        changed_fields: Array.isArray(activityPatch?.changed_fields)
          ? activityPatch.changed_fields.map((field) => String(field)).slice(0, 12)
          : [],
        context: {},
      };
      setActivity((prev) => {
        if (prev.some((row) => row.id === appended.id)) return prev;
        return [appended, ...prev].slice(0, 300);
      });
    }

    const patch = event.payload?.workspace_patch;
    const patchId = Number(patch?.id ?? 0);
    if (patchId === activeWorkspaceId) {
      setWorkspace((prev) => {
        if (!prev) return prev;
        return {
          ...prev,
          updated_at: patch?.updated_at ? String(patch.updated_at) : prev.updated_at,
          status: patch?.status ? (patch.status as InvestigationWorkspaceStatus) : prev.status,
          severity: patch?.severity ? (patch.severity as InvestigationWorkspaceSeverity) : prev.severity,
          priority: patch?.priority ? (patch.priority as InvestigationWorkspacePriority) : prev.priority,
          triage_state: patch?.triage_state ? (patch.triage_state as InvestigationWorkspaceTriage) : prev.triage_state,
          assignee: patch?.assignee === undefined ? prev.assignee : (patch.assignee ?? null),
          updated_by: patch?.updated_by ? String(patch.updated_by) : prev.updated_by,
          notes_count: typeof patch?.notes_count === "number" ? patch.notes_count : prev.notes_count,
          bookmarks_count: typeof patch?.bookmarks_count === "number" ? patch.bookmarks_count : prev.bookmarks_count,
          evidence_type_counts: patch?.evidence_type_counts || prev.evidence_type_counts,
        };
      });
    }
  });

  usePortalRealtimeSubscription("ui.investigations.invalidate", (event) => {
    const activeWorkspaceId = workspaceId ? Number(workspaceId) : 0;
    if (activeWorkspaceId <= 0) return;
    const eventWorkspaceId = Number(event.payload?.workspace_id ?? 0);
    if (eventWorkspaceId > 0 && eventWorkspaceId !== activeWorkspaceId) return;
    scheduleRealtimeRefresh();
  });

  async function submitNote() {
    if (!workspaceId) return;
    const body = noteText.trim();
    if (!body) return;

    setBusy(true);
    try {
      if (noteEditId) {
        await updateInvestigationNote(noteEditId, body);
      } else {
        await createInvestigationNote(workspaceId, body);
      }
      setNoteText("");
      setNoteEditId(null);
      await refresh();
    } catch (e: any) {
      setError(e?.message || "Failed to save note");
    } finally {
      setBusy(false);
    }
  }

  async function onCloseWorkspace() {
    if (!workspaceId) return;
    setBusy(true);
    try {
      const next = await closeInvestigationWorkspace(workspaceId);
      setWorkspace(next);
      syncEditForm(next);
      onUpdated(next);
      const feed = await listInvestigationActivity(workspaceId, { page_size: 200 });
      setActivity(feed.items || []);
    } catch (e: any) {
      setError(e?.message || "Failed to close workspace");
    } finally {
      setBusy(false);
    }
  }

  async function onReopenWorkspace() {
    if (!workspaceId) return;
    setBusy(true);
    try {
      const next = await reopenInvestigationWorkspace(workspaceId);
      setWorkspace(next);
      syncEditForm(next);
      onUpdated(next);
      const feed = await listInvestigationActivity(workspaceId, { page_size: 200 });
      setActivity(feed.items || []);
    } catch (e: any) {
      setError(e?.message || "Failed to reopen workspace");
    } finally {
      setBusy(false);
    }
  }

  async function onDeleteBookmark(bookmarkId: number) {
    if (!workspaceId) return;
    setBusy(true);
    try {
      await deleteInvestigationBookmark(bookmarkId);
      await refresh();
    } catch (e: any) {
      setError(e?.message || "Failed to delete bookmark");
    } finally {
      setBusy(false);
    }
  }

  const editDirty = useMemo(() => {
    if (!workspace) return false;
    return (
      workspace.title !== edit.title ||
      (workspace.description || "") !== edit.description ||
      workspace.status !== edit.status ||
      workspace.severity !== edit.severity ||
      workspace.priority !== edit.priority ||
      (workspace.assignee || "") !== edit.assignee ||
      (workspace.primary_agent_id || "") !== edit.primaryAgentId ||
      String(workspace.linked_attack_chain_case_id || "") !== edit.linkedCaseId.trim()
    );
  }, [workspace, edit]);

  async function saveWorkspaceMetadata() {
    if (!workspaceId || !workspace) return;
    const title = edit.title.trim();
    if (!title) {
      setSaveError("Title is required.");
      setSaveSuccess(null);
      return;
    }
    const linkedCaseId = parseOptionalPositiveInt(edit.linkedCaseId);
    if (edit.linkedCaseId.trim() && linkedCaseId === null) {
      setSaveError("Linked attack case must be a positive numeric ID.");
      setSaveSuccess(null);
      return;
    }
    setSaveBusy(true);
    setSaveError(null);
    setSaveSuccess(null);
    try {
      const payload: InvestigationWorkspaceUpdateIn = {
        title,
        description: edit.description.trim() || "",
        status: edit.status,
        severity: edit.severity,
        priority: edit.priority,
        assignee: edit.assignee.trim() || null,
        primary_agent_id: edit.primaryAgentId.trim() || null,
        linked_attack_chain_case_id: linkedCaseId,
      };
      const next = await updateInvestigationWorkspace(workspaceId, payload);
      setWorkspace(next);
      syncEditForm(next);
      setSaveSuccess("Workspace details saved.");
      onUpdated(next);
      const feed = await listInvestigationActivity(workspaceId, { page_size: 200 });
      setActivity(feed.items || []);
    } catch (e: any) {
      setSaveError(e?.message || "Failed to save workspace details");
    } finally {
      setSaveBusy(false);
    }
  }

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title={workspace ? `${workspace.title}` : "Workspace"}
      description={workspace ? `Key ${workspace.workspace_key}` : "Workspace details"}
      widthClassName="w-[980px]"
    >
      {loading ? <Loading label="Loading workspace" /> : null}
      {!loading && error ? <div className="text-sm text-red-400">{error}</div> : null}

      {!loading && !error && !workspace ? <EmptyState title="Workspace not found" /> : null}

      {!loading && workspace ? (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant={statusVariant(workspace.status) as any}>{workspace.status}</Badge>
            <Badge variant={severityVariant(workspace.severity) as any}>{workspace.severity}</Badge>
            <Badge variant="neutral">{workspace.priority}</Badge>
            <Badge variant="neutral">{workspace.triage_state}</Badge>
            {workspace.assignee ? <Badge variant="neutral">assignee: {workspace.assignee}</Badge> : null}
            {workspace.linked_attack_chain_case_id ? (
              <Badge variant="info">linked case #{workspace.linked_attack_chain_case_id}</Badge>
            ) : null}
            {workspace.primary_agent_id ? <Badge variant="neutral">agent {workspace.primary_agent_id}</Badge> : null}
          </div>

          <div className="flex items-center gap-2 border-b border-border/60">
            {([
              ["overview", "Overview"],
              ["notes", "Notes"],
              ["evidence", "Evidence"],
              ["timeline", "Timeline"],
            ] as const).map(([k, label]) => (
              <button
                key={k}
                type="button"
                onClick={() => setTab(k)}
                className={cx(
                  "px-3 py-2 text-xs font-mono uppercase tracking-widest border-b-2",
                  tab === k ? "border-primary text-foreground" : "border-transparent text-muted-foreground hover:text-foreground"
                )}
              >
                {label}
              </button>
            ))}
          </div>

          {tab === "overview" ? (
            <div className="space-y-3">
              <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-2">
                <div className="rounded-md border border-border/60 bg-background/30 px-2 py-2">
                  <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Notes</div>
                  <div className="mt-1 text-lg font-semibold font-mono">{workspace.notes_count}</div>
                </div>
                <div className="rounded-md border border-border/60 bg-background/30 px-2 py-2">
                  <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Evidence</div>
                  <div className="mt-1 text-lg font-semibold font-mono">{workspace.bookmarks_count}</div>
                </div>
                {Object.entries(workspace.evidence_type_counts || {}).map(([k, v]) => (
                  <div key={k} className="rounded-md border border-border/60 bg-background/30 px-2 py-2">
                    <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground truncate">{k}</div>
                    <div className="mt-1 text-lg font-semibold font-mono">{v}</div>
                  </div>
                ))}
              </div>

              <div className="rounded-lg border border-border/60 bg-background/30 p-3 space-y-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Workspace details</div>
                  <div className="text-[11px] text-muted-foreground font-mono">
                    Created by {workspace.created_by} · {fmtTs(workspace.created_at)}
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div>
                    <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Title</div>
                    <input
                      value={edit.title}
                      onChange={(e) => setEdit((prev) => ({ ...prev, title: e.target.value }))}
                      className="mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm"
                    />
                  </div>
                  <div>
                    <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Assignee</div>
                    <input
                      value={edit.assignee}
                      onChange={(e) => setEdit((prev) => ({ ...prev, assignee: e.target.value }))}
                      placeholder="Unassigned"
                      className="mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm"
                    />
                  </div>
                  <div className="md:col-span-2">
                    <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Description</div>
                    <textarea
                      value={edit.description}
                      onChange={(e) => setEdit((prev) => ({ ...prev, description: e.target.value }))}
                      rows={3}
                      className="mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm"
                    />
                  </div>
                  <div>
                    <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Status</div>
                    <select
                      value={edit.status}
                      onChange={(e) => setEdit((prev) => ({ ...prev, status: e.target.value as InvestigationWorkspaceStatus }))}
                      className="mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm"
                    >
                      <option value="open">Open</option>
                      <option value="contained">Contained</option>
                      <option value="resolved">Resolved</option>
                      <option value="closed">Closed</option>
                    </select>
                  </div>
                  <div>
                    <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Severity</div>
                    <select
                      value={edit.severity}
                      onChange={(e) => setEdit((prev) => ({ ...prev, severity: e.target.value as InvestigationWorkspaceSeverity }))}
                      className="mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm"
                    >
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                      <option value="critical">Critical</option>
                    </select>
                  </div>
                  <div>
                    <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Priority</div>
                    <select
                      value={edit.priority}
                      onChange={(e) => setEdit((prev) => ({ ...prev, priority: e.target.value as InvestigationWorkspacePriority }))}
                      className="mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm"
                    >
                      <option value="p1">P1</option>
                      <option value="p2">P2</option>
                      <option value="p3">P3</option>
                      <option value="p4">P4</option>
                    </select>
                  </div>
                  <div>
                    <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Primary agent</div>
                    <input
                      value={edit.primaryAgentId}
                      onChange={(e) => setEdit((prev) => ({ ...prev, primaryAgentId: e.target.value }))}
                      placeholder="agent-id"
                      className="mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm font-mono"
                    />
                  </div>
                  <div>
                    <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Linked attack case</div>
                    <input
                      value={edit.linkedCaseId}
                      onChange={(e) => setEdit((prev) => ({ ...prev, linkedCaseId: e.target.value }))}
                      placeholder="case id"
                      className="mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm font-mono"
                    />
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    onClick={saveWorkspaceMetadata}
                    disabled={saveBusy || !editDirty}
                    className={cx(
                      "rounded-md border border-border/60 bg-background/40 px-3 py-2 text-xs font-mono uppercase tracking-widest",
                      "hover:bg-muted/15",
                      (saveBusy || !editDirty) && "opacity-60 cursor-not-allowed"
                    )}
                  >
                    {saveBusy ? "Saving..." : "Save workspace details"}
                  </button>
                  {workspace.status === "closed" ? (
                    <button
                      type="button"
                      disabled={busy}
                      onClick={onReopenWorkspace}
                      className="rounded-md border border-border/60 bg-background/40 px-3 py-2 text-xs font-mono uppercase tracking-widest hover:bg-muted/15"
                    >
                      Reopen workspace
                    </button>
                  ) : (
                    <button
                      type="button"
                      disabled={busy}
                      onClick={onCloseWorkspace}
                      className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs font-mono uppercase tracking-widest text-red-300 hover:bg-red-500/15"
                    >
                      Close workspace
                    </button>
                  )}
                  <div className="text-[11px] text-muted-foreground font-mono">
                    Updated by {workspace.updated_by} · {fmtTs(workspace.updated_at)}
                  </div>
                </div>
                {saveError ? <div className="text-sm text-red-400">{saveError}</div> : null}
                {saveSuccess ? <div className="text-sm text-emerald-400">{saveSuccess}</div> : null}
              </div>
            </div>
          ) : null}

          {tab === "notes" ? (
            <div className="space-y-3">
              <div className="flex items-start gap-2">
                <textarea
                  value={noteText}
                  onChange={(e) => setNoteText(e.target.value)}
                  rows={3}
                  placeholder="Add a case note..."
                  className="flex-1 rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm"
                />
                <button
                  type="button"
                  onClick={submitNote}
                  disabled={busy}
                  className="rounded-md border border-border/60 bg-background/40 px-3 py-2 text-xs font-mono uppercase tracking-widest hover:bg-muted/15"
                >
                  {noteEditId ? "Save" : "Add"}
                </button>
              </div>

              {notes.length === 0 ? <EmptyState title="No notes" hint="Add your first note." /> : null}
              {notes.map((n) => (
                <div key={n.id} className="rounded-lg border border-border/60 bg-background/30 p-3">
                  <div className="flex items-center justify-between gap-2">
                    <div className="text-[11px] text-muted-foreground font-mono">{n.author} · {fmtTs(n.created_at)}{n.edited ? " · edited" : ""}</div>
                    <button
                      type="button"
                      onClick={() => {
                        setNoteEditId(n.id);
                        setNoteText(n.body);
                      }}
                      className="rounded border border-border/60 bg-background/40 px-2 py-1 text-[10px] font-mono uppercase tracking-widest text-muted-foreground hover:text-foreground"
                    >
                      Edit
                    </button>
                  </div>
                  <div className="mt-2 whitespace-pre-wrap break-words text-sm">{n.body}</div>
                </div>
              ))}
            </div>
          ) : null}

          {tab === "evidence" ? (
            <div className="space-y-3">
              {bookmarks.length === 0 ? <EmptyState title="No evidence" hint="Pin evidence from source views." /> : null}
              {bookmarks.map((b) => (
                <div key={b.id} className="rounded-lg border border-border/60 bg-background/30 p-3">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <Badge variant={evidenceVariant(b.evidence_type) as any}>{b.evidence_type}</Badge>
                      <div className="text-sm font-semibold">{b.title}</div>
                    </div>
                    <button
                      type="button"
                      onClick={() => onDeleteBookmark(b.id)}
                      className="rounded border border-border/60 bg-background/40 px-2 py-1 text-[10px] font-mono uppercase tracking-widest text-muted-foreground hover:text-foreground"
                    >
                      Remove
                    </button>
                  </div>

                  {b.summary ? <div className="mt-1 text-sm text-muted-foreground">{b.summary}</div> : null}
                  <div className="mt-2 rounded-md border border-border/50 bg-background/20 p-2">{renderEvidenceCardContent(b)}</div>

                  <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
                    <span>pinned {fmtTs(b.created_at)} by {b.created_by}</span>
                    {b.tags.length ? <span>tags: {b.tags.join(", ")}</span> : null}
                    {b.payload_snapshot?.deep_link ? (
                      <a href={String(b.payload_snapshot.deep_link)} className="rounded border border-border/60 px-2 py-1 text-primary hover:underline">
                        Open source
                      </a>
                    ) : null}
                  </div>
                </div>
              ))}
            </div>
          ) : null}

          {tab === "timeline" ? (
            <div className="space-y-2">
              {activity.length === 0 ? <EmptyState title="No activity" /> : null}
              {activity.map((a) => (
                <div key={a.id} className="rounded-lg border border-border/60 bg-background/30 p-2 text-sm">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant={activityVariant(a.activity_type) as any}>{activityLabel(a.activity_type)}</Badge>
                    <span className="text-[11px] text-muted-foreground font-mono">{fmtTs(a.created_at)}</span>
                    <span className="text-[11px] text-muted-foreground font-mono">
                      {a.actor_username ? `by ${a.actor_username}` : "by system"}
                    </span>
                  </div>
                  <div className="mt-1 break-words">{a.summary}</div>
                  <div className="mt-1 flex flex-wrap gap-2 text-[11px] text-muted-foreground font-mono">
                    {a.target_type ? <span>{a.target_type}{a.target_id ? ` #${a.target_id}` : ""}</span> : null}
                    {a.changed_fields?.length ? <span>fields: {a.changed_fields.slice(0, 4).join(", ")}</span> : null}
                  </div>
                </div>
              ))}
            </div>
          ) : null}
        </div>
      ) : null}
    </Drawer>
  );
}

export default function InvestigationsPage() {
  const [filters, setFilters] = useState<Filters>({
    status: "all",
    severity: "all",
    priority: "all",
    assignee: "",
    agentId: "",
    linkedCaseId: "",
    search: "",
  });

  const [rows, setRows] = useState<InvestigationWorkspace[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(false);

  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  const [createOpen, setCreateOpen] = useState(false);
  const [newTitle, setNewTitle] = useState("");
  const [newDescription, setNewDescription] = useState("");
  const [newSeverity, setNewSeverity] = useState<InvestigationWorkspaceSeverity>("medium");
  const [newPriority, setNewPriority] = useState<InvestigationWorkspacePriority>("p3");
  const invalidateRefreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const realtimeBurstWindowStartRef = useRef(0);
  const realtimeBurstCountRef = useRef(0);

  async function fetchFirst() {
    setLoading(true);
    setError(null);
    try {
      const out = await listInvestigationWorkspaces({
        page_size: 50,
        status: filters.status === "all" ? undefined : filters.status,
        severity: filters.severity === "all" ? undefined : filters.severity,
        priority: filters.priority === "all" ? undefined : filters.priority,
        assignee: filters.assignee.trim() || undefined,
        agent_id: filters.agentId.trim() || undefined,
        linked_attack_chain_case_id: parseCaseId(filters.linkedCaseId),
        search: filters.search.trim() || undefined,
      });
      setRows(out.items || []);
      setNextCursor(out.next_cursor || null);
      setHasMore(Boolean(out.has_more));
    } catch (e: any) {
      setRows([]);
      setNextCursor(null);
      setHasMore(false);
      setError(e?.message || "Failed to load workspaces");
    } finally {
      setLoading(false);
    }
  }

  async function fetchMore() {
    if (!nextCursor) return;
    setLoading(true);
    try {
      const out = await listInvestigationWorkspaces({
        page_size: 50,
        cursor: nextCursor,
        status: filters.status === "all" ? undefined : filters.status,
        severity: filters.severity === "all" ? undefined : filters.severity,
        priority: filters.priority === "all" ? undefined : filters.priority,
        assignee: filters.assignee.trim() || undefined,
        agent_id: filters.agentId.trim() || undefined,
        linked_attack_chain_case_id: parseCaseId(filters.linkedCaseId),
        search: filters.search.trim() || undefined,
      });
      setRows((prev) => [...prev, ...(out.items || [])]);
      setNextCursor(out.next_cursor || null);
      setHasMore(Boolean(out.has_more));
    } catch (e: any) {
      setError(e?.message || "Failed to load more workspaces");
    } finally {
      setLoading(false);
    }
  }

  usePortalRealtimeSubscription("ui.investigations.timeline.append", (event) => {
    const now = Date.now();
    if ((now - realtimeBurstWindowStartRef.current) > INVESTIGATIONS_RT_BURST_WINDOW_MS) {
      realtimeBurstWindowStartRef.current = now;
      realtimeBurstCountRef.current = 0;
    }
    realtimeBurstCountRef.current += 1;
    if (realtimeBurstCountRef.current > INVESTIGATIONS_RT_BURST_LIMIT) {
      if (invalidateRefreshTimerRef.current) return;
      invalidateRefreshTimerRef.current = window.setTimeout(() => {
        invalidateRefreshTimerRef.current = null;
        void fetchFirst();
      }, 300);
      return;
    }

    const patch = event.payload?.workspace_patch;
    const patchId = Number(patch?.id ?? 0);
    if (patchId <= 0) return;
    setRows((prev) =>
      prev.map((row) => {
        if (row.id !== patchId) return row;
        return {
          ...row,
          updated_at: patch?.updated_at ? String(patch.updated_at) : row.updated_at,
          status: patch?.status ? (patch.status as InvestigationWorkspaceStatus) : row.status,
          severity: patch?.severity ? (patch.severity as InvestigationWorkspaceSeverity) : row.severity,
          priority: patch?.priority ? (patch.priority as InvestigationWorkspacePriority) : row.priority,
          triage_state: patch?.triage_state ? (patch.triage_state as InvestigationWorkspaceTriage) : row.triage_state,
          assignee: patch?.assignee === undefined ? row.assignee : (patch.assignee ?? null),
          updated_by: patch?.updated_by ? String(patch.updated_by) : row.updated_by,
          notes_count: typeof patch?.notes_count === "number" ? patch.notes_count : row.notes_count,
          bookmarks_count: typeof patch?.bookmarks_count === "number" ? patch.bookmarks_count : row.bookmarks_count,
          evidence_type_counts: patch?.evidence_type_counts || row.evidence_type_counts,
        };
      }),
    );
  });

  usePortalRealtimeSubscription("ui.investigations.invalidate", () => {
    if (invalidateRefreshTimerRef.current) return;
    invalidateRefreshTimerRef.current = window.setTimeout(() => {
      invalidateRefreshTimerRef.current = null;
      void fetchFirst();
    }, 300);
  });

  useEffect(() => {
    fetchFirst();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    return () => {
      if (!invalidateRefreshTimerRef.current) return;
      window.clearTimeout(invalidateRefreshTimerRef.current);
      invalidateRefreshTimerRef.current = null;
    };
  }, []);

  async function createWorkspaceInline() {
    const title = newTitle.trim();
    if (!title) return;
    setLoading(true);
    setError(null);
    try {
      await createInvestigationWorkspace({
        title,
        description: newDescription.trim() || undefined,
        severity: newSeverity,
        priority: newPriority,
      });
      setNewTitle("");
      setNewDescription("");
      setCreateOpen(false);
      await fetchFirst();
    } catch (e: any) {
      setError(e?.message || "Failed to create workspace");
    } finally {
      setLoading(false);
    }
  }

  const summary = useMemo(() => {
    return `${rows.length} loaded${hasMore ? " · more available" : ""}`;
  }, [rows.length, hasMore]);

  return (
    <div className="space-y-5">
      <PageHeader
        title="Investigations"
        breadcrumb={["Detection", "Investigations"]}
        description="Persistent case workspaces with notes and pinned evidence."
        toolbarRight={
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => fetchFirst()}
              className="rounded-md border border-border/60 bg-background/40 px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground hover:bg-muted/15 hover:text-foreground"
            >
              Refresh
            </button>
            <button
              type="button"
              onClick={() => setCreateOpen((v) => !v)}
              className="rounded-md border border-border/60 bg-background/40 px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground hover:bg-muted/15 hover:text-foreground"
            >
              {createOpen ? "Hide create" : "New workspace"}
            </button>
          </div>
        }
      />

      <div className="rounded-xl border border-border/60 bg-background/40 p-4 space-y-3">
        <div className="grid grid-cols-1 md:grid-cols-3 xl:grid-cols-6 gap-3">
          <select value={filters.status} onChange={(e) => setFilters((p) => ({ ...p, status: e.target.value as any }))} className="rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm">
            <option value="all">All status</option>
            <option value="open">Open</option>
            <option value="contained">Contained</option>
            <option value="resolved">Resolved</option>
            <option value="closed">Closed</option>
          </select>

          <select value={filters.severity} onChange={(e) => setFilters((p) => ({ ...p, severity: e.target.value as any }))} className="rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm">
            <option value="all">All severity</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>

          <select value={filters.priority} onChange={(e) => setFilters((p) => ({ ...p, priority: e.target.value as any }))} className="rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm">
            <option value="all">All priority</option>
            <option value="p1">P1</option>
            <option value="p2">P2</option>
            <option value="p3">P3</option>
            <option value="p4">P4</option>
          </select>

          <input value={filters.assignee} onChange={(e) => setFilters((p) => ({ ...p, assignee: e.target.value }))} placeholder="Assignee" className="rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm" />
          <input value={filters.agentId} onChange={(e) => setFilters((p) => ({ ...p, agentId: e.target.value }))} placeholder="Primary agent" className="rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm" />
          <input value={filters.linkedCaseId} onChange={(e) => setFilters((p) => ({ ...p, linkedCaseId: e.target.value }))} placeholder="Linked case ID" className="rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm font-mono" />
        </div>

        <div className="flex items-center gap-3">
          <input value={filters.search} onChange={(e) => setFilters((p) => ({ ...p, search: e.target.value }))} placeholder="Search title, key, description" className="flex-1 rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm" />
          <button type="button" onClick={() => fetchFirst()} className="rounded-md border border-border/60 bg-background/40 px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground hover:bg-muted/15 hover:text-foreground">Apply</button>
        </div>

        {createOpen ? (
          <div className="rounded-lg border border-border/60 bg-background/20 p-3 grid grid-cols-1 md:grid-cols-4 gap-3">
            <input value={newTitle} onChange={(e) => setNewTitle(e.target.value)} placeholder="Workspace title" className="md:col-span-2 rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm" />
            <select value={newSeverity} onChange={(e) => setNewSeverity(e.target.value as any)} className="rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm">
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
            <select value={newPriority} onChange={(e) => setNewPriority(e.target.value as any)} className="rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm">
              <option value="p1">P1</option>
              <option value="p2">P2</option>
              <option value="p3">P3</option>
              <option value="p4">P4</option>
            </select>
            <textarea value={newDescription} onChange={(e) => setNewDescription(e.target.value)} rows={2} placeholder="Description" className="md:col-span-3 rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm" />
            <button type="button" onClick={createWorkspaceInline} className="rounded-md border border-border/60 bg-background/40 px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground hover:bg-muted/15 hover:text-foreground">Create</button>
          </div>
        ) : null}
      </div>

      <div className="rounded-xl border border-border/60 bg-background/40">
        <div className="flex items-center justify-between border-b border-border/60 px-4 py-3">
          <div className="text-sm font-semibold">Workspaces</div>
          <div className="text-xs text-muted-foreground">{summary}</div>
        </div>

        <div className="p-0">
          {loading && rows.length === 0 ? <Loading label="Loading workspaces" /> : null}
          {!loading && error ? <EmptyState title="Failed" hint={error} /> : null}
          {!loading && !error && rows.length === 0 ? <EmptyState title="No workspaces" hint="Create the first workspace to begin." /> : null}

          {rows.length > 0 ? (
            <div className="overflow-auto">
              <table className="w-full text-sm">
                <thead className="sticky top-0 bg-background/60">
                  <tr className="border-b border-border/60 text-muted-foreground">
                    <th className="text-left px-3 py-2 w-[240px]">Workspace</th>
                    <th className="text-left px-3 py-2 w-[130px]">Status</th>
                    <th className="text-left px-3 py-2 w-[120px]">Severity</th>
                    <th className="text-left px-3 py-2 w-[90px]">Priority</th>
                    <th className="text-left px-3 py-2 w-[140px]">Assignee</th>
                    <th className="text-left px-3 py-2 w-[150px]">Linked case</th>
                    <th className="text-left px-3 py-2 w-[180px]">Updated</th>
                    <th className="text-left px-3 py-2 w-[160px]">Counts</th>
                    <th className="text-right px-3 py-2 w-[100px]">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((ws) => (
                    <tr key={ws.id} className="border-b border-border/40 hover:bg-muted/20">
                      <td className="px-3 py-2">
                        <div className="font-semibold truncate">{ws.title}</div>
                        <div className="text-[11px] text-muted-foreground font-mono truncate">{ws.workspace_key}</div>
                      </td>
                      <td className="px-3 py-2"><Badge variant={statusVariant(ws.status) as any}>{ws.status}</Badge></td>
                      <td className="px-3 py-2"><Badge variant={severityVariant(ws.severity) as any}>{ws.severity}</Badge></td>
                      <td className="px-3 py-2"><Badge variant="neutral">{ws.priority}</Badge></td>
                      <td className="px-3 py-2 text-[12px]">{ws.assignee || "-"}</td>
                      <td className="px-3 py-2 text-[12px] font-mono">{ws.linked_attack_chain_case_id ? `#${ws.linked_attack_chain_case_id}` : "-"}</td>
                      <td className="px-3 py-2 text-[12px] font-mono">{fmtTs(ws.updated_at)}</td>
                      <td className="px-3 py-2 text-[12px]">{ws.notes_count} notes · {ws.bookmarks_count} evidence</td>
                      <td className="px-3 py-2 text-right">
                        <button
                          type="button"
                          onClick={() => {
                            setSelectedId(ws.id);
                            setDrawerOpen(true);
                          }}
                          className="rounded-md border border-border/60 bg-background/40 px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground hover:bg-muted/15 hover:text-foreground"
                        >
                          Open
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}

          {!loading && hasMore ? (
            <div className="p-4 flex justify-center">
              <button
                type="button"
                onClick={() => fetchMore()}
                className="rounded-md border border-border/60 bg-background/40 px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground hover:bg-muted/15 hover:text-foreground"
              >
                Load more
              </button>
            </div>
          ) : null}
        </div>
      </div>

      <WorkspaceDrawer
        workspaceId={selectedId}
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        onUpdated={(next) => {
          setRows((prev) => prev.map((x) => (x.id === next.id ? next : x)));
        }}
      />
    </div>
  );
}
