import { useEffect, useMemo, useState } from "react";

import Drawer from "@/shared/components/Drawer";
import { Button } from "@/shared/components/Button";
import { CheckboxField } from "@/shared/components/CheckboxField";
import { InlineAlert } from "@/shared/components/InlineAlert";
import { SelectInput } from "@/shared/components/SelectInput";
import { TextArea } from "@/shared/components/TextArea";
import { TextInput } from "@/shared/components/TextInput";
import { Toolbar } from "@/shared/components/Toolbar";

import type {
  CorrelationRule,
  CorrelationRuleIn,
  CorrelationRuleStrategy,
  CorrelationStage,
} from "../types";

const STRATEGY_OPTIONS: Array<{ value: CorrelationRuleStrategy; label: string }> = [
  { value: "threshold", label: "Threshold" },
  { value: "burst", label: "Burst (compatibility)" },
  { value: "sequence", label: "Sequence" },
  { value: "chain", label: "Chain (compatibility)" },
  { value: "cardinality", label: "Cardinality" },
  { value: "temporal_join", label: "Temporal join" },
  { value: "risk_aggregation", label: "Risk aggregation" },
  { value: "new_entity", label: "New entity" },
  { value: "rare_entity", label: "Rare entity" },
];

function normalizeCsv(value: string): string[] {
  const seen = new Set<string>();
  const items: string[] = [];
  for (const raw of value.split(",")) {
    const text = raw.trim();
    if (!text) continue;
    const key = text.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    items.push(text);
  }
  return items;
}

function prettyJson(value: unknown, fallback: string) {
  if (value === null || value === undefined) return fallback;
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return fallback;
  }
}

function parseObjectJson(label: string, value: string): { ok: true; value: Record<string, unknown> | null } | { ok: false; error: string } {
  const text = value.trim();
  if (!text) return { ok: true, value: null };
  try {
    const parsed = JSON.parse(text);
    if (parsed === null) return { ok: true, value: null };
    if (typeof parsed !== "object" || Array.isArray(parsed)) {
      return { ok: false, error: `${label} must be a JSON object.` };
    }
    return { ok: true, value: parsed as Record<string, unknown> };
  } catch {
    return { ok: false, error: `${label} must be valid JSON.` };
  }
}

function parseStagesJson(value: string): { ok: true; value: CorrelationStage[] } | { ok: false; error: string } {
  const text = value.trim();
  if (!text) return { ok: true, value: [] };
  try {
    const parsed = JSON.parse(text);
    if (!Array.isArray(parsed)) {
      return { ok: false, error: "Stages must be a JSON array." };
    }
    return { ok: true, value: parsed as CorrelationStage[] };
  } catch {
    return { ok: false, error: "Stages must be valid JSON." };
  }
}

export default function CorrelationRuleEditor({
  open,
  rule,
  saving,
  error,
  onClose,
  onSave,
}: {
  open: boolean;
  rule: CorrelationRule | null;
  saving: boolean;
  error?: string | null;
  onClose: () => void;
  onSave: (payload: CorrelationRuleIn) => Promise<void> | void;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [severity, setSeverity] = useState("high");
  const [strategy, setStrategy] = useState<CorrelationRuleStrategy>("threshold");
  const [groupBy, setGroupBy] = useState("src_ip");
  const [windowSeconds, setWindowSeconds] = useState("600");
  const [minAlerts, setMinAlerts] = useState("2");
  const [includeCsv, setIncludeCsv] = useState("");
  const [excludeCsv, setExcludeCsv] = useState("");
  const [stagesJson, setStagesJson] = useState("[]");
  const [entityJson, setEntityJson] = useState("{}");
  const [strategyConfigJson, setStrategyConfigJson] = useState("{}");
  const [riskConfigJson, setRiskConfigJson] = useState("{}");
  const [evidenceConfigJson, setEvidenceConfigJson] = useState("{}");
  const [lifecycleConfigJson, setLifecycleConfigJson] = useState("{}");
  const [localError, setLocalError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setLocalError(null);
    setName(rule?.name || "");
    setDescription(rule?.description || "");
    setEnabled(rule?.enabled ?? true);
    setSeverity(rule?.severity || "high");
    setStrategy(rule?.strategy || "threshold");
    setGroupBy(rule?.group_by || "src_ip");
    setWindowSeconds(String(rule?.window_seconds ?? 600));
    setMinAlerts(String(rule?.min_alerts ?? 2));
    setIncludeCsv((rule?.include_patterns || []).join(", "));
    setExcludeCsv((rule?.exclude_patterns || []).join(", "));
    setStagesJson(prettyJson(rule?.stages || [], "[]"));
    setEntityJson(prettyJson(rule?.entity ?? {}, "{}"));
    setStrategyConfigJson(prettyJson(rule?.strategy_config ?? {}, "{}"));
    setRiskConfigJson(prettyJson(rule?.risk_config ?? {}, "{}"));
    setEvidenceConfigJson(prettyJson(rule?.evidence_config ?? {}, "{}"));
    setLifecycleConfigJson(prettyJson(rule?.lifecycle_config ?? {}, "{}"));
  }, [open, rule]);

  const strategyOptions = useMemo(() => {
    const existing = String(strategy || "").trim();
    if (!existing || STRATEGY_OPTIONS.some((item) => item.value === existing)) return STRATEGY_OPTIONS;
    return [{ value: existing, label: `${existing} (current)` }, ...STRATEGY_OPTIONS];
  }, [strategy]);

  async function submit() {
    const trimmedName = name.trim();
    if (trimmedName.length < 2) {
      setLocalError("Rule name must be at least 2 characters.");
      return;
    }

    const nextWindowSeconds = Number(windowSeconds);
    const nextMinAlerts = Number(minAlerts);
    if (!Number.isFinite(nextWindowSeconds) || nextWindowSeconds < 30) {
      setLocalError("Window seconds must be at least 30.");
      return;
    }
    if (!Number.isFinite(nextMinAlerts) || nextMinAlerts < 1) {
      setLocalError("Min alerts must be at least 1.");
      return;
    }

    const stages = parseStagesJson(stagesJson);
    if (!stages.ok) {
      setLocalError(stages.error);
      return;
    }

    const entity = parseObjectJson("Entity config", entityJson);
    if (!entity.ok) {
      setLocalError(entity.error);
      return;
    }

    const strategyConfig = parseObjectJson("Strategy config", strategyConfigJson);
    if (!strategyConfig.ok) {
      setLocalError(strategyConfig.error);
      return;
    }

    const riskConfig = parseObjectJson("Risk config", riskConfigJson);
    if (!riskConfig.ok) {
      setLocalError(riskConfig.error);
      return;
    }

    const evidenceConfig = parseObjectJson("Evidence config", evidenceConfigJson);
    if (!evidenceConfig.ok) {
      setLocalError(evidenceConfig.error);
      return;
    }

    const lifecycleConfig = parseObjectJson("Lifecycle config", lifecycleConfigJson);
    if (!lifecycleConfig.ok) {
      setLocalError(lifecycleConfig.error);
      return;
    }

    setLocalError(null);
    await onSave({
      name: trimmedName,
      description: description.trim() ? description.trim() : null,
      enabled,
      severity: String(severity || "high").trim().toLowerCase(),
      strategy: String(strategy || "threshold").trim(),
      group_by: String(groupBy || "src_ip").trim(),
      window_seconds: Math.floor(nextWindowSeconds),
      min_alerts: Math.floor(nextMinAlerts),
      include_patterns: normalizeCsv(includeCsv),
      exclude_patterns: normalizeCsv(excludeCsv),
      stages: stages.value,
      entity: entity.value,
      strategy_config: strategyConfig.value,
      risk_config: riskConfig.value,
      evidence_config: evidenceConfig.value,
      lifecycle_config: lifecycleConfig.value,
    });
  }

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title={rule ? `Edit: ${rule.name}` : "New correlation rule"}
      description="Preserve advanced backend configuration while editing analyst-facing metadata."
      widthClassName="w-[920px]"
      headerLabel="Correlation rule"
      footer={
        <Toolbar
          right={
            <>
              <Button variant="subtle" size="lg" onClick={onClose} disabled={saving}>
                Cancel
              </Button>
              <Button variant="primary" size="lg" onClick={submit} disabled={saving}>
                {saving ? "Saving..." : "Save rule"}
              </Button>
            </>
          }
        />
      }
    >
      <div className="space-y-4">
        {error || localError ? <InlineAlert tone="danger">{error || localError}</InlineAlert> : null}

        <div className="grid gap-3 md:grid-cols-2">
          <label className="block">
            <div className="mb-1 text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">Name</div>
            <TextInput value={name} onChange={(event) => setName(event.target.value)} placeholder="Accepted SSH after brute force" />
          </label>

          <label className="block">
            <div className="mb-1 text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">Severity</div>
            <SelectInput value={severity} onChange={(event) => setSeverity(event.target.value)}>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
              <option value="unknown">Unknown</option>
            </SelectInput>
          </label>
        </div>

        <label className="block">
          <div className="mb-1 text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">Description</div>
          <TextInput
            value={description}
            onChange={(event) => setDescription(event.target.value)}
            placeholder="How this rule should be interpreted by analysts."
          />
        </label>

        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <label className="block">
            <div className="mb-1 text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">Strategy</div>
            <SelectInput value={String(strategy)} onChange={(event) => setStrategy(event.target.value)}>
              {strategyOptions.map((item) => (
                <option key={item.value} value={item.value}>
                  {item.label}
                </option>
              ))}
            </SelectInput>
          </label>

          <label className="block">
            <div className="mb-1 text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">Group by</div>
            <TextInput value={groupBy} onChange={(event) => setGroupBy(event.target.value)} placeholder="src_ip" />
          </label>

          <label className="block">
            <div className="mb-1 text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">Window seconds</div>
            <TextInput type="number" min={30} value={windowSeconds} onChange={(event) => setWindowSeconds(event.target.value)} />
          </label>

          <label className="block">
            <div className="mb-1 text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">Min alerts</div>
            <TextInput type="number" min={1} value={minAlerts} onChange={(event) => setMinAlerts(event.target.value)} />
          </label>
        </div>

        <CheckboxField
          label="Enabled"
          checked={enabled}
          onChange={(event) => setEnabled(event.target.checked)}
        />

        <div className="grid gap-3 md:grid-cols-2">
          <label className="block">
            <div className="mb-1 text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">Include patterns</div>
            <TextInput
              value={includeCsv}
              onChange={(event) => setIncludeCsv(event.target.value)}
              placeholder="ssh_* , port_scan_*"
            />
          </label>

          <label className="block">
            <div className="mb-1 text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">Exclude patterns</div>
            <TextInput
              value={excludeCsv}
              onChange={(event) => setExcludeCsv(event.target.value)}
              placeholder="test_*"
            />
          </label>
        </div>

        <div className="rounded-xl border border-border/60 bg-background/20 p-4">
          <div className="mb-3 text-sm font-semibold text-foreground">Advanced JSON</div>
          <div className="space-y-3">
            <label className="block">
              <div className="mb-1 text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">Stages JSON</div>
              <TextArea value={stagesJson} onChange={(event) => setStagesJson(event.target.value)} className="min-h-[160px] font-mono text-xs" />
            </label>

            <div className="grid gap-3 xl:grid-cols-2">
              <label className="block">
                <div className="mb-1 text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">Entity JSON</div>
                <TextArea value={entityJson} onChange={(event) => setEntityJson(event.target.value)} className="min-h-[120px] font-mono text-xs" />
              </label>

              <label className="block">
                <div className="mb-1 text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">Strategy config JSON</div>
                <TextArea
                  value={strategyConfigJson}
                  onChange={(event) => setStrategyConfigJson(event.target.value)}
                  className="min-h-[120px] font-mono text-xs"
                />
              </label>

              <label className="block">
                <div className="mb-1 text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">Risk config JSON</div>
                <TextArea value={riskConfigJson} onChange={(event) => setRiskConfigJson(event.target.value)} className="min-h-[120px] font-mono text-xs" />
              </label>

              <label className="block">
                <div className="mb-1 text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">Evidence config JSON</div>
                <TextArea
                  value={evidenceConfigJson}
                  onChange={(event) => setEvidenceConfigJson(event.target.value)}
                  className="min-h-[120px] font-mono text-xs"
                />
              </label>
            </div>

            <label className="block">
              <div className="mb-1 text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">Lifecycle config JSON</div>
              <TextArea
                value={lifecycleConfigJson}
                onChange={(event) => setLifecycleConfigJson(event.target.value)}
                className="min-h-[120px] font-mono text-xs"
              />
            </label>
          </div>
        </div>
      </div>
    </Drawer>
  );
}
