import { EuiPanel } from "@elastic/eui";

import { Button } from "@/shared/components/Button";
import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { SeverityPill } from "@/shared/components/SeverityPill";
import { StatusPill } from "@/shared/components/StatusPill";

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
          <EuiPanel
            key={r.id}
            onClick={() => onEdit(r)}
            hasBorder
            hasShadow={false}
            paddingSize="s"
            borderRadius="m"
            color={isSel ? "primary" : "plain"}
            className="w-full text-left"
          >
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <div className="truncate font-mono text-[12.5px] text-foreground">{r.id}</div>
                  <SeverityPill variant={sevVariant(r.severity)} withDot>{r.severity}</SeverityPill>
                  {!r.enabled ? (
                    <StatusPill variant="neutral">disabled</StatusPill>
                  ) : r.has_override ? (
                    <StatusPill variant="info">override</StatusPill>
                  ) : (
                    <StatusPill variant="active">active</StatusPill>
                  )}
                </div>

                <div className="mt-1 line-clamp-2 text-[12px] text-muted-foreground">
                  {r.description || r.name || r.type || "(no description)"}
                </div>

                <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-muted-foreground">
                  <span>{r.type || "-"}</span>
                  <span className="font-mono">
                    {r.pack || "pack:-"} / {r.category || "cat:-"} · v{Number(r.rule_version || 1)}
                  </span>
                  <span className="font-mono">
                    {r.window || "-"} · cd {r.cooldown || "-"}
                  </span>
                  {r.source_file ? <span className="truncate font-mono">src: {r.source_file}</span> : null}
                </div>
              </div>

              <div className="flex shrink-0 items-center gap-2">
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
          </EuiPanel>
        );
      })}
    </div>
  );
}
