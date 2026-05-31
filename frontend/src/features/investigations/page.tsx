import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import Drawer from "@/shared/components/Drawer";
import { Button } from "@/shared/components/Button";
import { DataPaginationFooter, DataQueryStateBanner, DataStatsStrip, DataViewToolbar, DebouncedSearchInput } from "@/shared/components/DataView";
import DetectionWorkflowRail from "@/shared/components/DetectionWorkflow";
import EmptyState from "@/shared/components/EmptyState";
import { InlineAlert } from "@/shared/components/InlineAlert";
import { IpAddressPill } from "@/shared/components/IpAddressPill";
import { Panel } from "@/shared/components/Panel";
import Loading from "@/shared/components/Loading";
import PageHeader from "@/shared/components/PageHeader";
import { Badge } from "@/shared/components/Badge";
import { SelectInput } from "@/shared/components/SelectInput";
import { SeverityPill } from "@/shared/components/SeverityPill";
import { StatusPill } from "@/shared/components/StatusPill";
import { Table, type Column } from "@/shared/components/Table";
import { TextArea } from "@/shared/components/TextArea";
import { TextInput } from "@/shared/components/TextInput";
import {
  InvestigationListItem,
  InvestigationMetaStrip,
  InvestigationSection,
  InvestigationShell,
  InvestigationTabs,
  formatInvestigationTimestamp,
} from "@/shared/components/investigation";
import { useUrlQueryState } from "@/shared/hooks/useUrlQueryState";
import { getFlowIpContext } from "@/shared/lib/ipClassification";
import { getIntParam, getStringParam, setOptionalParam } from "@/shared/lib/urlParams";
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

type InvestigationsQueryState = Filters & {
  workspace_id: number | null;
};

const FILTER_DEFAULTS: Filters = {
  status: "all",
  severity: "all",
  priority: "all",
  assignee: "",
  agentId: "",
  linkedCaseId: "",
  search: "",
};

const INVESTIGATIONS_RT_BURST_WINDOW_MS = 1000;
const INVESTIGATIONS_RT_BURST_LIMIT = 80;

function fmtTs(iso?: string | null) {
  return formatInvestigationTimestamp(iso);
}

function severityVariant(v: string) {
  if (v === "critical") return "critical";
  if (v === "high") return "high";
  if (v === "medium") return "medium";
  if (v === "low") return "low";
  return "neutral";
}

function statusPillVariant(v: string) {
  if (v === "open") return "info";
  if (v === "contained") return "warning";
  if (v === "resolved") return "active";
  if (v === "closed") return "inactive";
  return "neutral";
}

function evidenceVariant(v: string) {
  if (v === "attack_chain_step" || v === "attack_chain_case") return "high";
  if (v === "response_action_result") return "info";
  if (v === "protocol_intel") return "medium";
  if (v === "inventory_snapshot") return "low";
  return "neutral";
}

function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{children}</div>
  );
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

function applyWorkspacePatch(
  workspace: InvestigationWorkspace,
  patch: Record<string, any> | null | undefined,
): InvestigationWorkspace {
  return {
    ...workspace,
    updated_at: patch?.updated_at ? String(patch.updated_at) : workspace.updated_at,
    status: patch?.status ? (patch.status as InvestigationWorkspaceStatus) : workspace.status,
    severity: patch?.severity ? (patch.severity as InvestigationWorkspaceSeverity) : workspace.severity,
    priority: patch?.priority ? (patch.priority as InvestigationWorkspacePriority) : workspace.priority,
    triage_state: patch?.triage_state ? (patch.triage_state as InvestigationWorkspaceTriage) : workspace.triage_state,
    assignee: patch?.assignee === undefined ? workspace.assignee : (patch.assignee ?? null),
    updated_by: patch?.updated_by ? String(patch.updated_by) : workspace.updated_by,
    notes_count: typeof patch?.notes_count === "number" ? patch.notes_count : workspace.notes_count,
    bookmarks_count: typeof patch?.bookmarks_count === "number" ? patch.bookmarks_count : workspace.bookmarks_count,
    evidence_type_counts: patch?.evidence_type_counts || workspace.evidence_type_counts,
  };
}

function parseCaseId(raw: string): number | undefined {
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return undefined;
  return Math.trunc(n);
}

function parseStatusFilter(raw: string): Filters["status"] {
  const value = String(raw || "").trim().toLowerCase();
  if (value === "open" || value === "contained" || value === "resolved" || value === "closed") return value;
  return "all";
}

function parseSeverityFilter(raw: string): Filters["severity"] {
  const value = String(raw || "").trim().toLowerCase();
  if (value === "low" || value === "medium" || value === "high" || value === "critical") return value;
  return "all";
}

function parsePriorityFilter(raw: string): Filters["priority"] {
  const value = String(raw || "").trim().toLowerCase();
  if (value === "p1" || value === "p2" || value === "p3" || value === "p4") return value;
  return "all";
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

function renderPayloadEndpoint(payload: Record<string, unknown>, side: "src" | "dst") {
  const ip = str(payload[`${side}_ip`], "");
  const port = str(payload[`${side}_port`], "");
  const extra = asRecord(payload["extra"]);
  const ipContext = getFlowIpContext((payload["ip_context"] || extra["ip_context"]) as any, side);
  return (
    <span className="inline-flex max-w-full flex-wrap items-center gap-0.5">
      <IpAddressPill ip={ip} ipContext={ipContext} compact />
      {port ? <span className="text-muted-foreground">:{port}</span> : null}
    </span>
  );
}

function renderEvidenceCardContent(b: InvestigationBookmark) {
  const p = asRecord(b.payload_snapshot);

  if (b.evidence_type === "net_event") {
    return (
      <div className="text-[11px] text-muted-foreground">
        <div>{fmtTs(str(p["timestamp"], ""))}</div>
        <div>agent {str(p["agent_id"])} · {str(p["event_type"])}</div>
        <div className="inline-flex max-w-full flex-wrap items-center gap-1.5">
          {renderPayloadEndpoint(p, "src")}
          <span className="text-muted-foreground">→</span>
          {renderPayloadEndpoint(p, "dst")}
          <span className="text-muted-foreground">· {str(p["proto"])}</span>
        </div>
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

  const refresh = useCallback(async () => {
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
  }, [onUpdated, syncEditForm, workspaceId]);

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
        return applyWorkspacePatch(prev, patch);
      });
    }
  });

  usePortalRealtimeSubscription("ui.investigations.workspace.patch", (event) => {
    const activeWorkspaceId = workspaceId ? Number(workspaceId) : 0;
    if (activeWorkspaceId <= 0) return;
    const patch = event.payload?.workspace_patch;
    const patchId = Number(patch?.id ?? event.payload?.workspace_id ?? 0);
    if (patchId !== activeWorkspaceId) return;
    setWorkspace((prev) => (prev ? applyWorkspacePatch(prev, patch as Record<string, any>) : prev));
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
      headerLabel="Investigation"
    >
      {loading ? <Loading label="Loading workspace" /> : null}
      {!loading && error ? <div className="text-sm text-danger">{error}</div> : null}

      {!loading && !error && !workspace ? <EmptyState title="Workspace not found" /> : null}

      {!loading && workspace ? (
        <InvestigationShell>
          <InvestigationMetaStrip
            items={[
              { label: "Status", value: <StatusPill variant={statusPillVariant(workspace.status)} withDot>{workspace.status}</StatusPill> },
              { label: "Severity", value: <SeverityPill variant={severityVariant(workspace.severity)} withDot>{workspace.severity}</SeverityPill> },
              { label: "Priority", value: workspace.priority },
              { label: "Triage", value: workspace.triage_state },
              { label: "Workspace key", value: workspace.workspace_key },
              { label: "Assignee", value: workspace.assignee || "-" },
              { label: "Primary agent", value: workspace.primary_agent_id || "-" },
              {
                label: "Linked case",
                value: workspace.linked_attack_chain_case_id ? `#${workspace.linked_attack_chain_case_id}` : "-",
              },
            ]}
          />

          <InvestigationTabs
            value={tab}
            onChange={setTab}
            tabs={[
              { key: "overview", label: "Overview" },
              { key: "notes", label: "Notes" },
              { key: "evidence", label: "Evidence" },
              { key: "timeline", label: "Timeline" },
            ]}
          />

          {tab === "overview" ? (
            <div className="space-y-4">
              <InvestigationSection title="Workspace counts" subtitle="Notes, bookmarks, and evidence mix preserved from the workspace record.">
                <div className="grid grid-cols-2 gap-2 md:grid-cols-4 lg:grid-cols-8">
                  <div className="rounded-md border border-border bg-surface-2/50 px-3 py-2">
                    <FieldLabel>Notes</FieldLabel>
                    <div className="mt-1 font-mono text-lg font-semibold">{workspace.notes_count}</div>
                  </div>
                  <div className="rounded-md border border-border bg-surface-2/50 px-3 py-2">
                    <FieldLabel>Evidence</FieldLabel>
                    <div className="mt-1 font-mono text-lg font-semibold">{workspace.bookmarks_count}</div>
                  </div>
                  {Object.entries(workspace.evidence_type_counts || {}).map(([k, v]) => (
                    <div key={k} className="rounded-md border border-border bg-surface-2/50 px-3 py-2">
                      <FieldLabel>{k}</FieldLabel>
                      <div className="mt-1 font-mono text-lg font-semibold">{v}</div>
                    </div>
                  ))}
                </div>
              </InvestigationSection>

              <InvestigationSection
                title="Workspace details"
                subtitle={`Created by ${workspace.created_by} · ${fmtTs(workspace.created_at)}`}
              >
                <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                  <div>
                    <FieldLabel>Title</FieldLabel>
                    <TextInput
                      value={edit.title}
                      onChange={(e) => setEdit((prev) => ({ ...prev, title: e.target.value }))}
                      className="mt-1"
                    />
                  </div>
                  <div>
                    <FieldLabel>Assignee</FieldLabel>
                    <TextInput
                      value={edit.assignee}
                      onChange={(e) => setEdit((prev) => ({ ...prev, assignee: e.target.value }))}
                      placeholder="Unassigned"
                      className="mt-1"
                    />
                  </div>
                  <div className="md:col-span-2">
                    <FieldLabel>Description</FieldLabel>
                    <TextArea
                      value={edit.description}
                      onChange={(e) => setEdit((prev) => ({ ...prev, description: e.target.value }))}
                      rows={3}
                      className="mt-1"
                    />
                  </div>
                  <div>
                    <FieldLabel>Status</FieldLabel>
                    <SelectInput
                      value={edit.status}
                      onChange={(e) => setEdit((prev) => ({ ...prev, status: e.target.value as InvestigationWorkspaceStatus }))}
                      className="mt-1"
                    >
                      <option value="open">Open</option>
                      <option value="contained">Contained</option>
                      <option value="resolved">Resolved</option>
                      <option value="closed">Closed</option>
                    </SelectInput>
                  </div>
                  <div>
                    <FieldLabel>Severity</FieldLabel>
                    <SelectInput
                      value={edit.severity}
                      onChange={(e) => setEdit((prev) => ({ ...prev, severity: e.target.value as InvestigationWorkspaceSeverity }))}
                      className="mt-1"
                    >
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                      <option value="critical">Critical</option>
                    </SelectInput>
                  </div>
                  <div>
                    <FieldLabel>Priority</FieldLabel>
                    <SelectInput
                      value={edit.priority}
                      onChange={(e) => setEdit((prev) => ({ ...prev, priority: e.target.value as InvestigationWorkspacePriority }))}
                      className="mt-1"
                    >
                      <option value="p1">P1</option>
                      <option value="p2">P2</option>
                      <option value="p3">P3</option>
                      <option value="p4">P4</option>
                    </SelectInput>
                  </div>
                  <div>
                    <FieldLabel>Primary agent</FieldLabel>
                    <TextInput
                      value={edit.primaryAgentId}
                      onChange={(e) => setEdit((prev) => ({ ...prev, primaryAgentId: e.target.value }))}
                      placeholder="agent-id"
                      className="mt-1 font-mono"
                    />
                  </div>
                  <div>
                    <FieldLabel>Linked attack case</FieldLabel>
                    <TextInput
                      value={edit.linkedCaseId}
                      onChange={(e) => setEdit((prev) => ({ ...prev, linkedCaseId: e.target.value }))}
                      placeholder="case id"
                      className="mt-1 font-mono"
                    />
                  </div>
                </div>

                <div className="mt-4 flex flex-wrap items-center gap-2">
                  <Button variant="primary" size="md" onClick={saveWorkspaceMetadata} disabled={saveBusy || !editDirty}>
                    {saveBusy ? "Saving…" : "Save workspace details"}
                  </Button>
                  {workspace.status === "closed" ? (
                    <Button variant="success" size="md" disabled={busy} onClick={onReopenWorkspace}>
                      Reopen workspace
                    </Button>
                  ) : (
                    <Button variant="danger" size="md" disabled={busy} onClick={onCloseWorkspace}>
                      Close workspace
                    </Button>
                  )}
                  <div className="font-mono text-[11px] text-muted-foreground">
                    Updated by {workspace.updated_by} · {fmtTs(workspace.updated_at)}
                  </div>
                </div>
                {saveError ? <InlineAlert tone="danger" className="mt-3 text-xs">{saveError}</InlineAlert> : null}
                {saveSuccess ? <InlineAlert tone="success" className="mt-3 text-xs">{saveSuccess}</InlineAlert> : null}
              </InvestigationSection>
            </div>
          ) : null}

          {tab === "notes" ? (
            <InvestigationSection title="Notes" subtitle="Operator notes remain editable without leaving the drawer.">
              <div className="flex items-start gap-2">
                <TextArea
                  value={noteText}
                  onChange={(e) => setNoteText(e.target.value)}
                  rows={3}
                  placeholder="Add a case note..."
                  className="flex-1"
                />
                <Button variant="primary" size="md" onClick={submitNote} disabled={busy}>
                  {noteEditId ? "Save" : "Add"}
                </Button>
              </div>

              <div className="mt-4 space-y-3">
                {notes.length === 0 ? <EmptyState title="No notes" hint="Add your first note." /> : null}
                {notes.map((n) => (
                  <InvestigationListItem
                    key={n.id}
                    title={n.author || "Workspace note"}
                    description={n.body}
                    meta={[
                      { label: "time", value: fmtTs(n.created_at) },
                      { label: "state", value: n.edited ? "edited" : "created" },
                    ]}
                    actions={
                      <Button
                        variant="subtle"
                        size="sm"
                        onClick={() => {
                          setNoteEditId(n.id);
                          setNoteText(n.body);
                        }}
                      >
                        Edit
                      </Button>
                    }
                  />
                ))}
              </div>
            </InvestigationSection>
          ) : null}

          {tab === "evidence" ? (
            <InvestigationSection title="Evidence" subtitle="Pinned investigation evidence remains fully visible, including deep links and tags.">
              <div className="space-y-3">
                {bookmarks.length === 0 ? <EmptyState title="No evidence" hint="Pin evidence from source views." /> : null}
                {bookmarks.map((b) => (
                  <InvestigationListItem
                    key={b.id}
                    title={b.title}
                    description={b.summary || undefined}
                    badges={[{ label: b.evidence_type, variant: evidenceVariant(b.evidence_type) as any }]}
                    meta={[
                      { label: "pinned", value: `${fmtTs(b.created_at)} by ${b.created_by}` },
                      ...(b.tags.length ? [{ label: "tags", value: b.tags.join(", ") }] : []),
                    ]}
                    actions={
                      <Button variant="danger" size="sm" onClick={() => onDeleteBookmark(b.id)}>
                        Remove
                      </Button>
                    }
                  >
                    <div className="rounded-md border border-border bg-surface-2/40 p-2">
                      {renderEvidenceCardContent(b)}
                    </div>
                    {b.payload_snapshot?.deep_link ? (
                      <div className="mt-3">
                        <a
                          href={String(b.payload_snapshot.deep_link)}
                          className="inline-flex h-8 items-center rounded-md border border-border bg-card px-3 text-[11.5px] font-semibold uppercase tracking-[0.08em] text-primary transition-colors hover:border-primary/40 hover:bg-muted"
                        >
                          Open source
                        </a>
                      </div>
                    ) : null}
                  </InvestigationListItem>
                ))}
              </div>
            </InvestigationSection>
          ) : null}

          {tab === "timeline" ? (
            <InvestigationSection title="Timeline" subtitle="Workspace activity feed with actor, target, and changed-field context.">
              <div className="space-y-2">
                {activity.length === 0 ? <EmptyState title="No activity" /> : null}
                {activity.map((a) => (
                  <InvestigationListItem
                    key={a.id}
                    title={a.summary}
                    badges={[{ label: activityLabel(a.activity_type), variant: activityVariant(a.activity_type) as any }]}
                    meta={[
                      { label: "time", value: fmtTs(a.created_at) },
                      { label: "actor", value: a.actor_username ? `by ${a.actor_username}` : "by system" },
                      ...(a.target_type ? [{ label: "target", value: `${a.target_type}${a.target_id ? ` #${a.target_id}` : ""}` }] : []),
                      ...(a.changed_fields?.length ? [{ label: "fields", value: a.changed_fields.slice(0, 4).join(", ") }] : []),
                    ]}
                  />
                ))}
              </div>
            </InvestigationSection>
          ) : null}
        </InvestigationShell>
      ) : null}
    </Drawer>
  );
}

export default function InvestigationsPage() {
  const [query, setQuery] = useUrlQueryState<InvestigationsQueryState>({
    parse: (sp) => ({
      status: parseStatusFilter(getStringParam(sp, "status", FILTER_DEFAULTS.status)),
      severity: parseSeverityFilter(getStringParam(sp, "severity", FILTER_DEFAULTS.severity)),
      priority: parsePriorityFilter(getStringParam(sp, "priority", FILTER_DEFAULTS.priority)),
      assignee: getStringParam(sp, "assignee", FILTER_DEFAULTS.assignee),
      agentId: getStringParam(sp, "agent_id", FILTER_DEFAULTS.agentId),
      linkedCaseId: getStringParam(sp, "linked_case_id", FILTER_DEFAULTS.linkedCaseId),
      search: getStringParam(sp, "search", FILTER_DEFAULTS.search),
      workspace_id: getIntParam(sp, "workspace_id", { min: 1, max: Number.MAX_SAFE_INTEGER, fallback: 0 }) || null,
    }),
    serialize: (state) => {
      const sp = new URLSearchParams();
      setOptionalParam(sp, "status", state.status === FILTER_DEFAULTS.status ? null : state.status);
      setOptionalParam(sp, "severity", state.severity === FILTER_DEFAULTS.severity ? null : state.severity);
      setOptionalParam(sp, "priority", state.priority === FILTER_DEFAULTS.priority ? null : state.priority);
      setOptionalParam(sp, "assignee", state.assignee || null);
      setOptionalParam(sp, "agent_id", state.agentId || null);
      setOptionalParam(sp, "linked_case_id", state.linkedCaseId || null);
      setOptionalParam(sp, "search", state.search || null);
      setOptionalParam(sp, "workspace_id", state.workspace_id);
      return sp;
    },
    replace: true,
  });

  const [filters, setFilters] = useState<Filters>({
    status: query.status || FILTER_DEFAULTS.status,
    severity: query.severity || FILTER_DEFAULTS.severity,
    priority: query.priority || FILTER_DEFAULTS.priority,
    assignee: query.assignee || FILTER_DEFAULTS.assignee,
    agentId: query.agentId || FILTER_DEFAULTS.agentId,
    linkedCaseId: query.linkedCaseId || FILTER_DEFAULTS.linkedCaseId,
    search: query.search || FILTER_DEFAULTS.search,
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

  useEffect(() => {
    const next: Filters = {
      status: query.status || FILTER_DEFAULTS.status,
      severity: query.severity || FILTER_DEFAULTS.severity,
      priority: query.priority || FILTER_DEFAULTS.priority,
      assignee: query.assignee || FILTER_DEFAULTS.assignee,
      agentId: query.agentId || FILTER_DEFAULTS.agentId,
      linkedCaseId: query.linkedCaseId || FILTER_DEFAULTS.linkedCaseId,
      search: query.search || FILTER_DEFAULTS.search,
    };
    setFilters((prev) => {
      if (
        prev.status === next.status &&
        prev.severity === next.severity &&
        prev.priority === next.priority &&
        prev.assignee === next.assignee &&
        prev.agentId === next.agentId &&
        prev.linkedCaseId === next.linkedCaseId &&
        prev.search === next.search
      ) {
        return prev;
      }
      return next;
    });
  }, [query.agentId, query.assignee, query.linkedCaseId, query.priority, query.search, query.severity, query.status]);

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

  function applyFilters() {
    setQuery((prev) => ({
      ...prev,
      status: filters.status,
      severity: filters.severity,
      priority: filters.priority,
      assignee: filters.assignee.trim(),
      agentId: filters.agentId.trim(),
      linkedCaseId: filters.linkedCaseId.trim(),
      search: filters.search.trim(),
    }));
    void fetchFirst();
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
    setRows((prev) => prev.map((row) => (row.id === patchId ? applyWorkspacePatch(row, patch as Record<string, any>) : row)));
  });

  usePortalRealtimeSubscription("ui.investigations.workspace.patch", (event) => {
    const patch = event.payload?.workspace_patch;
    const patchId = Number(patch?.id ?? event.payload?.workspace_id ?? 0);
    if (patchId <= 0) return;
    setRows((prev) => prev.map((row) => (row.id === patchId ? applyWorkspacePatch(row, patch as Record<string, any>) : row)));
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
    if (!query.workspace_id) return;
    setSelectedId(query.workspace_id);
    setDrawerOpen(true);
  }, [query.workspace_id]);

  const openWorkspaceDrawer = useCallback((workspaceId: number) => {
    setSelectedId(workspaceId);
    setDrawerOpen(true);
    setQuery((prev) => {
      if ((prev.workspace_id || null) === workspaceId) return prev;
      return { ...prev, workspace_id: workspaceId };
    });
  }, [setQuery]);

  const closeWorkspaceDrawer = useCallback(() => {
    setDrawerOpen(false);
    setSelectedId(null);
    setQuery((prev) => {
      if ((prev.workspace_id || null) === null) return prev;
      return { ...prev, workspace_id: null };
    });
  }, [setQuery]);

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

  const workspaceStats = useMemo(() => {
    const open = rows.filter((row) => row.status === "open").length;
    const criticalHigh = rows.filter((row) => row.severity === "critical" || row.severity === "high").length;
    const assigned = rows.filter((row) => Boolean((row.assignee || "").trim())).length;
    const evidence = rows.reduce((acc, row) => acc + (row.bookmarks_count || 0), 0);
    const notes = rows.reduce((acc, row) => acc + (row.notes_count || 0), 0);
    return { open, criticalHigh, assigned, evidence, notes };
  }, [rows]);

  const workspaceColumns: Column<InvestigationWorkspace>[] = [
    {
      key: "workspace",
      title: "Workspace",
      render: (ws) => (
        <div className="flex min-w-0 items-center gap-1.5">
          <StatusPill variant={statusPillVariant(ws.status)} withDot>{ws.status}</StatusPill>
          <SeverityPill variant={severityVariant(ws.severity)} withDot>{ws.severity}</SeverityPill>
          <Badge variant="neutral">{ws.priority}</Badge>
          <span className="min-w-0 truncate font-semibold" title={ws.title}>{ws.title}</span>
          <span className="shrink-0 max-w-[12rem] truncate font-mono text-[11px] text-muted-foreground" title={ws.workspace_key}>{ws.workspace_key}</span>
        </div>
      ),
    },
    {
      key: "assignment",
      title: "Assignment",
      render: (ws) => (
        <div className="flex min-w-0 items-center gap-1.5">
          <span className="min-w-0 truncate text-[12px]">{ws.assignee || <span className="text-muted-foreground">Unassigned</span>}</span>
          <span className="shrink-0 font-mono text-[11px] text-muted-foreground">
            {ws.linked_attack_chain_case_id ? `case #${ws.linked_attack_chain_case_id}` : "no linked case"}
          </span>
        </div>
      ),
    },
    {
      key: "activity",
      title: "Activity",
      render: (ws) => (
        <div className="flex items-center gap-1.5 whitespace-nowrap">
          <span className="font-mono text-[12px]">{fmtTs(ws.updated_at)}</span>
          <span className="text-[11px] text-muted-foreground">{ws.notes_count} notes · {ws.bookmarks_count} evidence</span>
        </div>
      ),
    },
    {
      key: "action",
      title: "Action",
      align: "right",
      render: (ws) => (
        <Button
          variant="subtle"
          size="sm"
          onClick={(e) => {
            e.stopPropagation();
            openWorkspaceDrawer(ws.id);
          }}
        >
          Open
        </Button>
      ),
    },
  ];

  return (
    <div className="space-y-5">
      <PageHeader
        title="Investigations"
        breadcrumb={["Detection", "Investigations"]}
        description="Persistent case workspaces with notes and pinned evidence."
      />

      <DetectionWorkflowRail compact />

      <DataViewToolbar
        left={
          <div className="text-xs text-muted-foreground">
            Move from alert and chain pivots into long-lived case workspaces with notes, evidence and timeline activity.
          </div>
        }
        right={
          <div className="flex items-center gap-2">
            <Button variant="subtle" size="md" onClick={() => fetchFirst()}>Refresh</Button>
            <Button variant={createOpen ? "secondary" : "primary"} size="md" onClick={() => setCreateOpen((v) => !v)}>
              {createOpen ? "Hide create" : "New workspace"}
            </Button>
          </div>
        }
      />

      <DataQueryStateBanner
        tone={error ? "danger" : "neutral"}
        message={error || summary}
        right={loading ? "loading" : "ready"}
      />

      <DataStatsStrip
        stats={[
          { label: "Loaded workspaces", value: rows.length },
          { label: "Open", value: workspaceStats.open },
          { label: "Critical/High", value: workspaceStats.criticalHigh },
          { label: "Assigned", value: workspaceStats.assigned },
          { label: "Notes", value: workspaceStats.notes },
          { label: "Evidence", value: workspaceStats.evidence },
          { label: "Selected", value: selectedId || "-" },
          { label: "Drawer", value: drawerOpen ? "open" : "closed" },
        ]}
      />

      <Panel
        title="Workspace filters"
        actions={<span className="text-[10.5px] text-muted-foreground">{createOpen ? "create form open" : "filters only"}</span>}
      >
        <div className="grid grid-cols-1 md:grid-cols-3 xl:grid-cols-6 gap-3">
          <SelectInput value={filters.status} onChange={(e) => setFilters((p) => ({ ...p, status: e.target.value as any }))}>
            <option value="all">All status</option>
            <option value="open">Open</option>
            <option value="contained">Contained</option>
            <option value="resolved">Resolved</option>
            <option value="closed">Closed</option>
          </SelectInput>

          <SelectInput value={filters.severity} onChange={(e) => setFilters((p) => ({ ...p, severity: e.target.value as any }))}>
            <option value="all">All severity</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </SelectInput>

          <SelectInput value={filters.priority} onChange={(e) => setFilters((p) => ({ ...p, priority: e.target.value as any }))}>
            <option value="all">All priority</option>
            <option value="p1">P1</option>
            <option value="p2">P2</option>
            <option value="p3">P3</option>
            <option value="p4">P4</option>
          </SelectInput>

          <TextInput value={filters.assignee} onChange={(e) => setFilters((p) => ({ ...p, assignee: e.target.value }))} placeholder="Assignee" />
          <TextInput value={filters.agentId} onChange={(e) => setFilters((p) => ({ ...p, agentId: e.target.value }))} placeholder="Primary agent" />
          <TextInput value={filters.linkedCaseId} onChange={(e) => setFilters((p) => ({ ...p, linkedCaseId: e.target.value }))} placeholder="Linked case ID" className="font-mono" />
        </div>

        <div className="flex items-center gap-3">
          <DebouncedSearchInput
            value={filters.search}
            onChange={(value) => setFilters((prev) => ({ ...prev, search: value }))}
            placeholder="Search title, workspace key, description..."
            className="h-9 flex-1"
          />
          <Button variant="primary" size="lg" onClick={applyFilters}>Apply</Button>
        </div>

        {createOpen ? (
          <div className="grid grid-cols-1 gap-3 rounded-md border border-border bg-surface-2/50 p-3 md:grid-cols-4">
            <TextInput value={newTitle} onChange={(e) => setNewTitle(e.target.value)} placeholder="Workspace title" className="md:col-span-2" />
            <SelectInput value={newSeverity} onChange={(e) => setNewSeverity(e.target.value as any)}>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </SelectInput>
            <SelectInput value={newPriority} onChange={(e) => setNewPriority(e.target.value as any)}>
              <option value="p1">P1</option>
              <option value="p2">P2</option>
              <option value="p3">P3</option>
              <option value="p4">P4</option>
            </SelectInput>
            <TextArea value={newDescription} onChange={(e) => setNewDescription(e.target.value)} rows={2} placeholder="Description" className="md:col-span-3" />
            <Button type="button" variant="primary" size="md" onClick={createWorkspaceInline}>Create</Button>
          </div>
        ) : null}
      </Panel>

      <Panel title="Workspaces" actions={<span className="text-[10.5px] text-muted-foreground">{summary}</span>} padded={false}>
          {loading && rows.length === 0 ? <div className="p-4"><Loading label="Loading workspaces" /></div> : null}
          {!loading && error ? <div className="p-4"><EmptyState title="Failed" hint={error} /></div> : null}
          {!loading && !error && rows.length === 0 ? <div className="p-4"><EmptyState title="No workspaces" hint="Create the first workspace to begin." /></div> : null}

          {rows.length > 0 ? (
            <div className="w-full">
              <Table
                className="!shadow-none !border-0 !bg-transparent !rounded-none"
                columns={workspaceColumns}
                rows={rows}
                rowKey={(ws) => String(ws.id)}
                selectedRowKey={selectedId != null ? String(selectedId) : null}
                rowClassName={() => "cursor-pointer"}
                onRowClick={(ws) => openWorkspaceDrawer(ws.id)}
              />
            </div>
          ) : null}

          {rows.length > 0 ? (
            <div className="p-4">
              <DataPaginationFooter
                totalCount={rows.length}
                pageSize={50}
                onPageSizeChange={() => {
                  // fixed backend page size
                }}
                pageSizeOptions={[50]}
                hasMore={hasMore}
                loadingMore={loading}
                onLoadMore={fetchMore}
                loadMoreLabel="Load older workspaces"
                error={error}
                onRetry={error ? () => fetchFirst() : undefined}
              />
            </div>
          ) : null}
      </Panel>

      <WorkspaceDrawer
        workspaceId={selectedId}
        open={drawerOpen}
        onClose={closeWorkspaceDrawer}
        onUpdated={(next) => {
          setRows((prev) => prev.map((x) => (x.id === next.id ? next : x)));
        }}
      />
    </div>
  );
}
