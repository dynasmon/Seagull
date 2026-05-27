import { Button } from "@/shared/components/Button";
import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { Badge } from "@/shared/components/Badge";
import { cx } from "@/shared/lib/cx";

import { sevVariant } from "../lib/alertSeverity";
import type { RuleOut } from "../types";

interface AlertsRulesListProps {
  loading: boolean;
  filtered: RuleOut[];
  selectedId: string | null;
  onEdit: (rule: RuleOut) => void;
}

export function AlertsRulesList({ loading, filtered, selectedId, onEdit }: AlertsRulesListProps) {
  if (loading) return <Loading label="Loading rules…" />;

  if (filtered.length === 0) {
    return <EmptyState title="No rules" description="No rules match your current search." />;
  }

  return (
    <div className="space-y-2">
      {filtered.map((r) => {
        const isSel = selectedId === r.id;
        return (
          <div
            key={r.id}
            className={cx(
              "w-full rounded-lg border border-border/60 bg-background/20 px-3 py-2",
              "hover:bg-muted/30",
              isSel && "bg-muted/40",
            )}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <div className="font-mono text-[12px] truncate">{r.id}</div>
                  {!r.enabled ? (
                    <Badge variant="neutral">disabled</Badge>
                  ) : r.has_override ? (
                    <Badge variant="neutral">override</Badge>
                  ) : null}
                  <Badge variant={sevVariant(r.severity)}>{r.severity}</Badge>
                </div>

                <div className="mt-1 text-[11px] text-muted-foreground line-clamp-2">
                  {r.description || r.name || r.type || "(no description)"}
                </div>

                <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
                  <div>{r.type || "-"}</div>
                  <div className="font-mono">
                    {r.pack || "pack:-"} / {r.category || "cat:-"} · v{Number(r.rule_version || 1)}
                  </div>
                  <div className="font-mono">
                    {r.window || "-"} · cd {r.cooldown || "-"}
                  </div>
                  {r.source_file ? <div className="font-mono truncate">src: {r.source_file}</div> : null}
                </div>
              </div>

              <div className="shrink-0 flex items-center gap-2">
                <Button
                  variant="subtle"
                  size="sm"
                  onClick={(e) => {
                    e.stopPropagation();
                    onEdit(r);
                  }}
                  title="Open rule editor"
                >
                  Edit
                </Button>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
