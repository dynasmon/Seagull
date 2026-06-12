import { useMemo, useState } from "react";
import { EuiIcon, EuiToolTip } from "@elastic/eui";

import { Badge } from "@/shared/components/Badge";
import EmptyState from "@/shared/components/EmptyState";
import { InlineAlert } from "@/shared/components/InlineAlert";
import { Panel } from "@/shared/components/Panel";
import { Tabs } from "@/shared/components/Tabs";
import { cx } from "@/shared/lib/cx";

import { categoryLabel, riskVariant } from "./lib";
import type { ActionTypeOut } from "./types";

interface ActionCatalogPanelProps {
  catalog: ActionTypeOut[];
  loading: boolean;
  error: string | null;
  selectedKey: string | null;
  onSelect: (key: string) => void;
}

type CategoryTab = "all" | "forensics" | "diagnostics" | "containment";

const CATEGORY_TABS: Array<{ key: CategoryTab; label: string }> = [
  { key: "all", label: "All" },
  { key: "forensics", label: "Forensics" },
  { key: "diagnostics", label: "Diagnostics" },
  { key: "containment", label: "Containment" },
];

export default function ActionCatalogPanel({ catalog, loading, error, selectedKey, onSelect }: ActionCatalogPanelProps) {
  const [category, setCategory] = useState<CategoryTab>("all");

  const visible = useMemo(() => {
    if (category === "all") return catalog;
    return catalog.filter((d) => d.category === category);
  }, [catalog, category]);

  return (
    <Panel title="Action catalog" subtitle="Server-defined response capabilities">
      <Tabs
        value={category}
        onChange={(next) => setCategory(next)}
        tabs={CATEGORY_TABS.map((t) => ({ key: t.key, label: t.label }))}
      />

      {error ? (
        <div className="mt-3">
          <InlineAlert tone="danger">{error}</InlineAlert>
        </div>
      ) : null}

      <div className="mt-3 space-y-2">
        {loading && catalog.length === 0 ? (
          <div className="text-[12px] text-muted-foreground">Loading catalog…</div>
        ) : visible.length === 0 ? (
          <EmptyState title="No action types" hint="No capabilities match this category." />
        ) : (
          visible.map((d) => {
            const active = d.key === selectedKey;
            return (
              <button
                key={d.key}
                type="button"
                onClick={() => onSelect(d.key)}
                aria-pressed={active}
                className={cx(
                  "w-full rounded-md border px-3 py-2 text-left transition-colors",
                  active
                    ? "border-primary/60 bg-primary/10"
                    : "border-border/60 bg-background/30 hover:border-primary/40 hover:bg-muted",
                )}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="truncate text-[12.5px] font-semibold text-foreground">{d.label}</div>
                  <Badge variant={riskVariant(d.risk_level)}>{d.risk_level}</Badge>
                </div>
                <div className="mt-1 line-clamp-2 text-[11px] text-muted-foreground">{d.description}</div>
                <div className="mt-2 flex items-center gap-3 text-[10.5px] text-muted-foreground">
                  <span className="font-mono uppercase tracking-[0.08em]">{categoryLabel(d.category)}</span>
                  <span>~{d.estimated_duration_seconds}s</span>
                  {d.reversible ? (
                    <EuiToolTip content="Reversible">
                      <EuiIcon type="editorUndo" size="s" color="success" />
                    </EuiToolTip>
                  ) : (
                    <EuiToolTip content="Not reversible">
                      <EuiIcon type="lock" size="s" color="danger" />
                    </EuiToolTip>
                  )}
                  {d.requires_confirmation ? (
                    <EuiToolTip content="Requires confirmation">
                      <EuiIcon type="alert" size="s" color="warning" />
                    </EuiToolTip>
                  ) : null}
                </div>
              </button>
            );
          })
        )}
      </div>
    </Panel>
  );
}
