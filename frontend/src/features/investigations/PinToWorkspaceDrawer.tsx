import { useEffect, useMemo, useState } from "react";

import Drawer from "@/shared/components/Drawer";
import { cx } from "@/shared/lib/cx";

import { createInvestigationWorkspace, listInvestigationWorkspaces } from "./api";
import type {
  InvestigationPinOptions,
  InvestigationWorkspace,
  InvestigationWorkspacePriority,
  InvestigationWorkspaceSeverity,
  InvestigationWorkspaceStatus,
  InvestigationWorkspaceTriage,
} from "./types";

function parseTags(raw: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const token of raw.split(",")) {
    const s = token.trim();
    if (!s) continue;
    const k = s.toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(s);
  }
  return out;
}

export default function PinToWorkspaceDrawer({
  open,
  title,
  onClose,
  onPin,
  defaultWorkspaceTitle,
  workspaceDefaults,
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  onPin: (workspaceId: number, options: InvestigationPinOptions) => Promise<{ created: boolean; duplicate_of_id?: number | null }>;
  defaultWorkspaceTitle?: string;
  workspaceDefaults?: Partial<{
    status: InvestigationWorkspaceStatus;
    severity: InvestigationWorkspaceSeverity;
    priority: InvestigationWorkspacePriority;
    triage_state: InvestigationWorkspaceTriage;
    linked_attack_chain_case_id: number;
    primary_agent_id: string;
  }>;
}) {
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const [mode, setMode] = useState<"existing" | "create">("existing");
  const [workspaces, setWorkspaces] = useState<InvestigationWorkspace[]>([]);
  const [selectedWorkspaceId, setSelectedWorkspaceId] = useState<number | null>(null);

  const [newTitle, setNewTitle] = useState(defaultWorkspaceTitle || "");
  const [newDescription, setNewDescription] = useState("");
  const [newSeverity, setNewSeverity] = useState<InvestigationWorkspaceSeverity>(workspaceDefaults?.severity || "medium");
  const [newPriority, setNewPriority] = useState<InvestigationWorkspacePriority>(workspaceDefaults?.priority || "p3");
  const [newAssignee, setNewAssignee] = useState("");

  const [note, setNote] = useState("");
  const [tagsText, setTagsText] = useState("");

  useEffect(() => {
    if (!open) return;

    setLoading(true);
    setError(null);
    setSuccess(null);

    listInvestigationWorkspaces({ page_size: 100 })
      .then((out) => {
        const rows = out.items || [];
        setWorkspaces(rows);
        setSelectedWorkspaceId(rows[0]?.id ?? null);
        setMode(rows.length > 0 ? "existing" : "create");
      })
      .catch((e: any) => {
        setError(e?.message || "Failed to load workspaces");
        setWorkspaces([]);
        setSelectedWorkspaceId(null);
        setMode("create");
      })
      .finally(() => setLoading(false));
  }, [open]);

  useEffect(() => {
    setNewTitle(defaultWorkspaceTitle || "");
  }, [defaultWorkspaceTitle]);

  const existingOptions = useMemo(() => {
    return workspaces
      .slice()
      .sort((a, b) => {
        const ax = Date.parse(a.updated_at || "") || 0;
        const bx = Date.parse(b.updated_at || "") || 0;
        return bx - ax;
      });
  }, [workspaces]);

  async function submit() {
    setBusy(true);
    setError(null);
    setSuccess(null);

    try {
      const tags = parseTags(tagsText);
      let workspaceId = selectedWorkspaceId;

      if (mode === "create") {
        const title = newTitle.trim();
        if (!title) {
          setError("Workspace title is required.");
          return;
        }

        const created = await createInvestigationWorkspace({
          title,
          description: newDescription.trim() || undefined,
          severity: newSeverity,
          priority: newPriority,
          assignee: newAssignee.trim() || undefined,
          status: workspaceDefaults?.status || "open",
          triage_state: workspaceDefaults?.triage_state || "untriaged",
          linked_attack_chain_case_id: workspaceDefaults?.linked_attack_chain_case_id,
          primary_agent_id: workspaceDefaults?.primary_agent_id,
        });
        workspaceId = created.id;
      }

      if (!workspaceId) {
        setError("Select a workspace first.");
        return;
      }

      const result = await onPin(workspaceId, {
        note: note.trim() || undefined,
        tags,
      });

      if (result.created) {
        setSuccess("Evidence pinned to workspace.");
      } else {
        setSuccess("This evidence is already pinned in the selected workspace.");
      }

      setNote("");
      setTagsText("");
    } catch (e: any) {
      setError(e?.message || "Failed to pin evidence");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title="Pin to workspace"
      description={title}
      widthClassName="w-[620px]"
    >
      <div className="space-y-4">
        <div className="rounded-lg border border-border/60 bg-background/30 p-3">
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Destination</div>
          <div className="mt-3 flex items-center gap-3">
            <button
              type="button"
              onClick={() => setMode("existing")}
              className={cx(
                "rounded border px-3 py-2 text-[10px] font-mono uppercase tracking-widest",
                mode === "existing"
                  ? "border-primary/60 bg-primary/20 text-foreground"
                  : "border-border/60 bg-background/30 text-muted-foreground hover:text-foreground"
              )}
              disabled={existingOptions.length === 0}
            >
              Existing workspace
            </button>
            <button
              type="button"
              onClick={() => setMode("create")}
              className={cx(
                "rounded border px-3 py-2 text-[10px] font-mono uppercase tracking-widest",
                mode === "create"
                  ? "border-primary/60 bg-primary/20 text-foreground"
                  : "border-border/60 bg-background/30 text-muted-foreground hover:text-foreground"
              )}
            >
              Create new workspace
            </button>
          </div>

          {loading ? <div className="mt-3 text-sm text-muted-foreground">Loading workspaces...</div> : null}

          {mode === "existing" ? (
            <div className="mt-3">
              <select
                value={selectedWorkspaceId ? String(selectedWorkspaceId) : ""}
                onChange={(e) => setSelectedWorkspaceId(Number(e.target.value) || null)}
                className="w-full rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm"
              >
                <option value="">Select workspace</option>
                {existingOptions.map((ws) => (
                  <option key={ws.id} value={ws.id}>
                    {ws.title} · {ws.workspace_key}
                  </option>
                ))}
              </select>
            </div>
          ) : (
            <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="md:col-span-2">
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Title</div>
                <input
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="Investigation workspace title"
                  className="mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm"
                />
              </div>

              <div className="md:col-span-2">
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Description</div>
                <textarea
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                  rows={2}
                  className="mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm"
                />
              </div>

              <div>
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Severity</div>
                <select
                  value={newSeverity}
                  onChange={(e) => setNewSeverity(e.target.value as InvestigationWorkspaceSeverity)}
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
                  value={newPriority}
                  onChange={(e) => setNewPriority(e.target.value as InvestigationWorkspacePriority)}
                  className="mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm"
                >
                  <option value="p1">P1</option>
                  <option value="p2">P2</option>
                  <option value="p3">P3</option>
                  <option value="p4">P4</option>
                </select>
              </div>

              <div className="md:col-span-2">
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Assignee</div>
                <input
                  value={newAssignee}
                  onChange={(e) => setNewAssignee(e.target.value)}
                  placeholder="Optional"
                  className="mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm"
                />
              </div>
            </div>
          )}
        </div>

        <div className="rounded-lg border border-border/60 bg-background/30 p-3 space-y-3">
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Pin context</div>
          <div>
            <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Why this evidence matters (optional)</div>
            <textarea
              value={note}
              onChange={(e) => setNote(e.target.value)}
              rows={3}
              className="mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm"
            />
          </div>
          <div>
            <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Tags (comma separated)</div>
            <input
              value={tagsText}
              onChange={(e) => setTagsText(e.target.value)}
              placeholder="ioc, dns, suspicious"
              className="mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm"
            />
          </div>
        </div>

        {error ? <div className="text-sm text-danger">{error}</div> : null}
        {success ? <div className="text-sm text-success">{success}</div> : null}

        <div className="flex items-center justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border border-border/60 bg-background/30 px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground hover:text-foreground"
          >
            Close
          </button>
          <button
            type="button"
            onClick={submit}
            disabled={busy || loading}
            className={cx(
              "rounded-md border border-border/60 bg-background/40 px-3 py-2 text-xs font-mono uppercase tracking-widest",
              "hover:bg-muted/15 hover:text-foreground",
              (busy || loading) && "opacity-60 cursor-not-allowed"
            )}
          >
            {busy ? "Pinning..." : "Pin evidence"}
          </button>
        </div>
      </div>
    </Drawer>
  );
}
