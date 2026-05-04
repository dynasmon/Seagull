import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { Button } from "@/shared/components/Button";
import {
  DataQueryStateBanner,
  DataStatsStrip,
  DataViewToolbar,
  DebouncedSearchInput,
} from "@/shared/components/DataView";
import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { Panel } from "@/shared/components/Panel";
import { Table } from "@/shared/components/Table";

import {
  createCorrelationRule,
  deleteCorrelationRule,
  getCorrelationRules,
  updateCorrelationRule,
} from "../api";
import type { CorrelationRule, CorrelationRuleIn } from "../types";
import CorrelationRuleEditor from "../components/CorrelationRuleEditor";
import { CorrelationRiskBadge } from "../components/CorrelationRiskBadge";
import { correlationSeverityVariant } from "../components/correlationUtils";
import { SeverityPill } from "@/shared/components/SeverityPill";
import { StatusPill } from "@/shared/components/StatusPill";
import { formatInvestigationTimestamp } from "@/shared/components/investigation";

function strategyCount(rules: CorrelationRule[]) {
  const counts = new Map<string, number>();
  for (const rule of rules) {
    const key = String(rule.strategy || "unknown");
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1])
    .map(([label, value]) => `${label} (${value})`);
}

function configFlags(rule: CorrelationRule) {
  const flags: string[] = [];
  if ((rule.stages || []).length > 0) flags.push(`${rule.stages.length} stages`);
  if (rule.entity && Object.keys(rule.entity).length > 0) flags.push("entity");
  if (rule.strategy_config && Object.keys(rule.strategy_config).length > 0) flags.push("strategy");
  if (rule.risk_config && Object.keys(rule.risk_config).length > 0) flags.push("risk");
  if (rule.evidence_config && Object.keys(rule.evidence_config).length > 0) flags.push("evidence");
  if (rule.lifecycle_config && Object.keys(rule.lifecycle_config).length > 0) flags.push("lifecycle");
  return flags;
}

export default function CorrelationRulesPage() {
  const reqSeq = useRef(0);

  const [rules, setRules] = useState<CorrelationRule[]>([]);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [editorOpen, setEditorOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<CorrelationRule | null>(null);
  const [query, setQuery] = useState("");
  const [showDisabled, setShowDisabled] = useState(true);

  const loadRules = useCallback(async (signal?: AbortSignal) => {
    const mySeq = ++reqSeq.current;
    setLoading(true);
    setError(null);
    try {
      const nextRules = await getCorrelationRules({ signal });
      if (signal?.aborted || reqSeq.current !== mySeq) return;
      setRules(nextRules || []);
    } catch (cause: any) {
      if (signal?.aborted || reqSeq.current !== mySeq) return;
      setRules([]);
      setError(cause?.message || "Failed to load correlation rules");
    } finally {
      if (signal?.aborted || reqSeq.current !== mySeq) return;
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void loadRules(controller.signal);
    return () => controller.abort();
  }, [loadRules]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return rules.filter((rule) => {
      if (!showDisabled && !rule.enabled) return false;
      if (!needle) return true;
      const haystack = [
        rule.name,
        rule.description || "",
        rule.strategy,
        rule.group_by,
        ...(rule.include_patterns || []),
        ...(rule.exclude_patterns || []),
        ...configFlags(rule),
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(needle);
    });
  }, [query, rules, showDisabled]);

  const stats = useMemo(() => {
    const enabled = rules.filter((rule) => rule.enabled).length;
    const advanced = rules.filter((rule) => configFlags(rule).length > 0).length;
    const temporal = rules.filter((rule) => String(rule.strategy) === "temporal_join").length;
    const riskAware = rules.filter((rule) => String(rule.strategy) === "risk_aggregation").length;
    return { enabled, advanced, temporal, riskAware };
  }, [rules]);

  async function saveRule(payload: CorrelationRuleIn) {
    setSaving(true);
    setError(null);
    try {
      if (editingRule) {
        await updateCorrelationRule(editingRule.id, payload);
      } else {
        await createCorrelationRule(payload);
      }
      setEditorOpen(false);
      setEditingRule(null);
      await loadRules();
    } catch (cause: any) {
      setError(cause?.message || "Failed to save rule");
    } finally {
      setSaving(false);
    }
  }

  async function removeRule(rule: CorrelationRule) {
    if (!window.confirm(`Delete correlation rule "${rule.name}"?`)) return;
    setError(null);
    try {
      await deleteCorrelationRule(rule.id);
      await loadRules();
    } catch (cause: any) {
      setError(cause?.message || "Failed to delete rule");
    }
  }

  return (
    <div className="space-y-4">
      <DataViewToolbar
        left={
          <div>
            <h2 className="text-lg font-semibold">Correlation rules</h2>
            <div className="text-xs text-muted-foreground">
              Edit durable incident logic without discarding advanced strategy, evidence, or lifecycle config.
            </div>
          </div>
        }
        right={
          <div className="flex flex-wrap items-center gap-2">
            <DebouncedSearchInput
              value={query}
              onChange={setQuery}
              placeholder="Search rule, strategy, entity, config..."
              className="h-9 min-w-[280px]"
            />
            <label className="flex items-center gap-2 text-sm text-muted-foreground">
              <input
                type="checkbox"
                checked={showDisabled}
                onChange={(event) => setShowDisabled(event.target.checked)}
                className="h-4 w-4"
              />
              Show disabled
            </label>
            <Button variant="subtle" size="lg" onClick={() => void loadRules()}>
              Refresh
            </Button>
            <Button
              variant="primary"
              size="lg"
              onClick={() => {
                setEditingRule(null);
                setEditorOpen(true);
              }}
            >
              New rule
            </Button>
          </div>
        }
      />

      <DataQueryStateBanner
        tone={error ? "danger" : "neutral"}
        message={error || `${filtered.length} shown · ${rules.length} total`}
        right={loading ? "loading" : "ready"}
      />

      <DataStatsStrip
        stats={[
          { label: "Rules", value: rules.length },
          { label: "Enabled", value: stats.enabled },
          { label: "Advanced configs", value: stats.advanced },
          { label: "Temporal join", value: stats.temporal },
          { label: "Risk aggregation", value: stats.riskAware },
          { label: "Strategies", value: strategyCount(rules).slice(0, 3).join(" · ") || "-" },
        ]}
      />

      <Panel
        title="Rule catalog"
        subtitle="CRUD stays intact, but the editor now preserves backend-only fields instead of flattening them away."
        actions={<span className="text-[10px] font-mono text-muted-foreground">Click a row to edit</span>}
        className="min-h-[420px]"
      >
        {loading ? (
          <Loading label="Loading correlation rules..." />
        ) : filtered.length === 0 ? (
          <EmptyState title="No rules" description="Create a rule or widen the current filters." />
        ) : (
          <Table
            columns={[
              {
                key: "state",
                title: "State",
                render: (rule: CorrelationRule) => (
                  <div className="flex flex-wrap items-center gap-2">
                    <StatusPill variant={rule.enabled ? "active" : "inactive"}>
                      {rule.enabled ? "enabled" : "disabled"}
                    </StatusPill>
                    <SeverityPill variant={correlationSeverityVariant(rule.severity)}>{rule.severity}</SeverityPill>
                  </div>
                ),
              },
              {
                key: "name",
                title: "Rule",
                className: "min-w-[240px]",
                render: (rule: CorrelationRule) => (
                  <div className="space-y-1">
                    <div className="font-medium text-foreground">{rule.name}</div>
                    {rule.description ? <div className="text-[11px] text-muted-foreground">{rule.description}</div> : null}
                  </div>
                ),
              },
              {
                key: "strategy",
                title: "Strategy",
                className: "min-w-[180px]",
                render: (rule: CorrelationRule) => (
                  <div className="space-y-1">
                    <div className="font-mono text-[12px] text-foreground">{rule.strategy}</div>
                    <div className="text-[11px] text-muted-foreground">{rule.group_by}</div>
                  </div>
                ),
              },
              {
                key: "window",
                title: "Window",
                render: (rule: CorrelationRule) => (
                  <div className="space-y-1">
                    <div className="font-mono text-[12px] text-foreground">{rule.window_seconds}s</div>
                    <div className="text-[11px] text-muted-foreground">min alerts {rule.min_alerts}</div>
                  </div>
                ),
              },
              {
                key: "configs",
                title: "Configs",
                className: "min-w-[200px]",
                render: (rule: CorrelationRule) => (
                  <div className="flex flex-wrap gap-1.5">
                    {configFlags(rule).length > 0 ? configFlags(rule).map((item) => (
                      <span
                        key={item}
                        className="inline-flex items-center rounded-md border border-border/60 bg-background/35 px-1.5 py-0.5 text-[11px] font-mono"
                      >
                        {item}
                      </span>
                    )) : <span className="text-muted-foreground">-</span>}
                  </div>
                ),
              },
              {
                key: "patterns",
                title: "Patterns",
                className: "min-w-[220px]",
                render: (rule: CorrelationRule) => {
                  const preview = (rule.include_patterns || []).slice(0, 3);
                  return (
                    <div className="flex flex-wrap gap-1.5">
                      {preview.length > 0 ? preview.map((item) => (
                        <span
                          key={item}
                          className="inline-flex items-center rounded-md border border-border/60 bg-background/35 px-1.5 py-0.5 text-[11px] font-mono"
                        >
                          {item}
                        </span>
                      )) : <span className="text-muted-foreground">(all)</span>}
                      {(rule.include_patterns || []).length > preview.length ? (
                        <span className="text-[11px] text-muted-foreground">+{(rule.include_patterns || []).length - preview.length}</span>
                      ) : null}
                    </div>
                  );
                },
              },
              {
                key: "updated_at",
                title: "Updated",
                render: (rule: CorrelationRule) => formatInvestigationTimestamp(rule.updated_at),
              },
              {
                key: "risk",
                title: "Severity",
                render: (rule: CorrelationRule) => <CorrelationRiskBadge score={rule.risk_config?.threshold as number | null} label="Threshold" />,
              },
              {
                key: "actions",
                title: "Actions",
                align: "right",
                render: (rule: CorrelationRule) => (
                  <div className="flex justify-end gap-2">
                    <Button
                      variant="subtle"
                      size="sm"
                      onClick={(event) => {
                        event.stopPropagation();
                        setEditingRule(rule);
                        setEditorOpen(true);
                      }}
                    >
                      Edit
                    </Button>
                    <Button
                      variant="danger"
                      size="sm"
                      onClick={(event) => {
                        event.stopPropagation();
                        void removeRule(rule);
                      }}
                    >
                      Delete
                    </Button>
                  </div>
                ),
              },
            ]}
            rows={filtered}
            rowKey={(rule) => String(rule.id)}
            onRowClick={(rule) => {
              setEditingRule(rule);
              setEditorOpen(true);
            }}
          />
        )}
      </Panel>

      <CorrelationRuleEditor
        open={editorOpen}
        rule={editingRule}
        saving={saving}
        error={error}
        onClose={() => {
          setEditorOpen(false);
          setEditingRule(null);
        }}
        onSave={saveRule}
      />
    </div>
  );
}
