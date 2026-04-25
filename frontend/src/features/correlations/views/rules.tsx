import { useEffect, useMemo, useRef, useState } from "react";

import { Badge } from "@/shared/components/Badge";
import { Button } from "@/shared/components/Button";
import { DataQueryStateBanner, DataStatsStrip, DataViewToolbar, DebouncedSearchInput } from "@/shared/components/DataView";
import Drawer from "@/shared/components/Drawer";
import DraftNumberInput from "@/shared/components/DraftNumberInput";
import EmptyState from "@/shared/components/EmptyState";
import { InlineAlert } from "@/shared/components/InlineAlert";
import Loading from "@/shared/components/Loading";
import { Panel } from "@/shared/components/Panel";
import { SelectInput } from "@/shared/components/SelectInput";
import { TextInput } from "@/shared/components/TextInput";
import { cx } from "@/shared/lib/cx";

import { createCorrelationRule, deleteCorrelationRule, getCorrelationRules, updateCorrelationRule } from "../api";
import type { CorrelationRule, CorrelationRuleIn, CorrelationStage } from "../types";

function fmtSeconds(s: number) {
  if (!Number.isFinite(s) || s <= 0) return "-";
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const r = s % 60;
  return r ? `${m}m ${r}s` : `${m}m`;
}

function fmtWhen(iso?: string | null) {
  if (!iso) return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

function normalizeCsv(value: string): string[] {
  const raw = value
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);
  const out: string[] = [];
  const seen = new Set<string>();
  for (const t of raw) {
    const k = t.toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(t);
  }
  return out;
}

function sevVariant(sev: string) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "neutral";
}

function uid() {
  return `${Date.now()}_${Math.random().toString(16).slice(2)}`;
}

type StageDraft = { key: string; name: string; patternsCsv: string; min_count: number };

function toDraftStages(stages: CorrelationStage[] | undefined | null): StageDraft[] {
  return (stages || []).map((s) => ({
    key: uid(),
    name: s.name,
    patternsCsv: (s.patterns || []).join(", "),
    min_count: Number.isFinite(s.min_count) ? s.min_count : 1,
  }));
}

function fromDraftStages(drafts: StageDraft[]): CorrelationStage[] {
  return drafts
    .map((d) => ({
      name: (d.name || "").trim(),
      patterns: normalizeCsv(d.patternsCsv || ""),
      min_count: Math.max(1, Math.floor(Number(d.min_count) || 1)),
    }))
    .filter((s) => s.name && s.patterns.length > 0);
}

export default function CorrelationRulesPage() {
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [rules, setRules] = useState<CorrelationRule[]>([]);
  const [q, setQ] = useState("");
  const [showDisabled, setShowDisabled] = useState(true);

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [editing, setEditing] = useState<CorrelationRule | null>(null);

  // form
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [severity, setSeverity] = useState("high");
  const [strategy, setStrategy] = useState<"burst" | "chain">("burst");
  const [groupBy, setGroupBy] = useState("src_ip");
  const [windowSeconds, setWindowSeconds] = useState(600);
  const [minAlerts, setMinAlerts] = useState(2);
  const [includeCsv, setIncludeCsv] = useState("");
  const [excludeCsv, setExcludeCsv] = useState("");
  const [stages, setStages] = useState<StageDraft[]>([]);

  const reqSeq = useRef(0);

  async function load() {
    const mySeq = ++reqSeq.current;
    setLoading(true);
    setError(null);
    try {
      const out = await getCorrelationRules();
      if (reqSeq.current !== mySeq) return;
      setRules(out || []);
    } catch (e: any) {
      if (reqSeq.current !== mySeq) return;
      setError(e?.message || "Failed to load correlation rules");
      setRules([]);
    } finally {
      if (reqSeq.current !== mySeq) return;
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  const filtered = useMemo(() => {
    const qq = q.trim().toLowerCase();
    return (rules || []).filter((r) => {
      if (!showDisabled && !r.enabled) return false;
      if (!qq) return true;
      const hay = [
        r.name,
        r.description || "",
        r.strategy,
        r.group_by,
        ...(r.include_patterns || []),
        ...(r.exclude_patterns || []),
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return hay.includes(qq);
    });
  }, [rules, q, showDisabled]);

  const stats = useMemo(() => {
    const enabled = rules.filter((row) => row.enabled).length;
    const chain = rules.filter((row) => String(row.strategy || "").toLowerCase() === "chain").length;
    const criticalHigh = rules.filter((row) => {
      const sev = String(row.severity || "").toLowerCase();
      return sev === "critical" || sev === "high";
    }).length;
    return { enabled, chain, criticalHigh };
  }, [rules]);

  function resetForm() {
    setName("");
    setDescription("");
    setEnabled(true);
    setSeverity("high");
    setStrategy("burst");
    setGroupBy("src_ip");
    setWindowSeconds(600);
    setMinAlerts(2);
    setIncludeCsv("");
    setExcludeCsv("");
    setStages([]);
  }

  function openCreate() {
    setEditing(null);
    resetForm();
    setDrawerOpen(true);
  }

  function openEdit(r: CorrelationRule) {
    setEditing(r);
    setName(r.name || "");
    setDescription(r.description || "");
    setEnabled(Boolean(r.enabled));
    setSeverity(String(r.severity || "high"));
    setStrategy((String(r.strategy || "burst").toLowerCase() === "chain" ? "chain" : "burst") as any);
    setGroupBy(String(r.group_by || "src_ip"));
    setWindowSeconds(Number(r.window_seconds) || 600);
    setMinAlerts(Number(r.min_alerts) || 2);
    setIncludeCsv((r.include_patterns || []).join(", "));
    setExcludeCsv((r.exclude_patterns || []).join(", "));
    setStages(toDraftStages(r.stages));
    setDrawerOpen(true);
  }

  function buildPayload(): { ok: true; payload: CorrelationRuleIn } | { ok: false; error: string } {
    const nm = name.trim();
    if (nm.length < 2) return { ok: false, error: "Name must be at least 2 characters." };

    const ws = Math.max(30, Math.floor(Number(windowSeconds) || 0));
    const ma = Math.max(1, Math.floor(Number(minAlerts) || 0));
    if (!Number.isFinite(ws) || ws < 30) return { ok: false, error: "Window must be >= 30 seconds." };
    if (!Number.isFinite(ma) || ma < 1) return { ok: false, error: "Min alerts must be >= 1." };

    const inc = normalizeCsv(includeCsv);
    const exc = normalizeCsv(excludeCsv);
    const st = strategy === "chain" ? fromDraftStages(stages) : [];
    if (strategy === "chain" && st.length === 0) {
      return { ok: false, error: "Chain strategy requires at least one stage with patterns." };
    }

    const payload: CorrelationRuleIn = {
      name: nm,
      description: description.trim() ? description.trim() : null,
      enabled: Boolean(enabled),
      severity: String(severity || "high").toLowerCase(),
      strategy,
      group_by: String(groupBy || "src_ip"),
      window_seconds: ws,
      min_alerts: ma,
      include_patterns: inc,
      exclude_patterns: exc,
      stages: st,
    };
    return { ok: true, payload };
  }

  async function save() {
    const built = buildPayload();
    if (!built.ok) {
      setError(built.error);
      return;
    }

    setSaving(true);
    setError(null);
    try {
      if (editing) {
        await updateCorrelationRule(editing.id, built.payload);
      } else {
        await createCorrelationRule(built.payload);
      }
      setDrawerOpen(false);
      await load();
    } catch (e: any) {
      setError(e?.message || "Failed to save rule");
    } finally {
      setSaving(false);
    }
  }

  async function remove(r: CorrelationRule) {
    const ok = window.confirm(`Delete correlation rule "${r.name}"? This cannot be undone.`);
    if (!ok) return;

    setError(null);
    try {
      await deleteCorrelationRule(r.id);
      await load();
    } catch (e: any) {
      setError(e?.message || "Failed to delete rule");
    }
  }

  return (
    <div className="space-y-4">
      <DataViewToolbar
        left={
          <div>
            <h2 className="text-lg font-semibold">Correlation rules</h2>
            <div className="text-xs text-muted-foreground">
              Define burst and stage-chain logic to connect low-level detections into investigation-ready incidents.
            </div>
          </div>
        }
        right={
          <div className="flex flex-wrap items-center gap-2">
            <DebouncedSearchInput
              value={q}
              onChange={setQ}
              placeholder="Search rule name, strategy, patterns..."
              className="h-9 min-w-[240px]"
            />
            <label className="flex items-center gap-2 text-sm text-muted-foreground select-none">
              <input
                type="checkbox"
                checked={showDisabled}
                onChange={(e) => setShowDisabled(e.target.checked)}
                className="h-4 w-4"
              />
              Show disabled
            </label>
            <Button variant="subtle" size="lg" onClick={load}>Refresh</Button>
            <Button variant="primary" size="lg" onClick={openCreate}>New rule</Button>
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
          { label: "Filtered", value: filtered.length },
          { label: "Enabled", value: stats.enabled },
          { label: "Chain strategy", value: stats.chain },
          { label: "Critical/High", value: stats.criticalHigh },
          { label: "Show disabled", value: showDisabled ? "yes" : "no" },
          { label: "Editor", value: drawerOpen ? "open" : "closed" },
          { label: "Mode", value: editing ? "edit existing" : "create available" },
        ]}
      />

      <Panel
        title="Rules"
        actions={<span className="text-[10px] font-mono text-muted-foreground">{filtered.length} shown · {rules.length} total</span>}
        className="min-h-[360px]"
      >
          {loading ? (
              <Loading label="Loading rules…" />
          ) : filtered.length === 0 ? (
              <EmptyState
                title="No rules"
                description="Create a correlation rule to start grouping alerts into incidents."
              />
          ) : (
            <div className="w-full overflow-auto">
              <table className="w-full text-sm">
                <thead className="sticky top-0 bg-background/60 backdrop-blur z-10">
                  <tr className="border-b border-border/60 text-muted-foreground">
                    <th className="text-left font-medium px-3 py-2 w-[110px]">State</th>
                    <th className="text-left font-medium px-3 py-2 w-[220px]">Name</th>
                    <th className="text-left font-medium px-3 py-2 w-[110px]">Strategy</th>
                    <th className="text-left font-medium px-3 py-2 w-[140px]">Group by</th>
                    <th className="text-left font-medium px-3 py-2 w-[120px]">Window</th>
                    <th className="text-left font-medium px-3 py-2 w-[110px]">Min alerts</th>
                    <th className="text-left font-medium px-3 py-2">Patterns</th>
                    <th className="text-left font-medium px-3 py-2 w-[190px]">Updated</th>
                    <th className="text-right font-medium px-3 py-2 w-[170px]">Actions</th>
                  </tr>
                </thead>

                <tbody>
                  {filtered.map((r) => (
                    <tr key={r.id} className="border-b border-border/40 hover:bg-muted/30">
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-2">
                          <span
                            className={cx(
                              "inline-flex h-2 w-2 rounded-full",
                              r.enabled ? "bg-success" : "bg-muted-foreground/50"
                            )}
                            aria-hidden="true"
                          />
                          <Badge variant={sevVariant(String(r.severity || "unknown"))}>{String(r.severity || "unknown")}</Badge>
                        </div>
                      </td>

                      <td className="px-3 py-2">
                        <div className="font-mono text-[12px] truncate" title={r.name}>{r.name}</div>
                        {r.description ? <div className="text-[11px] text-muted-foreground truncate" title={r.description}>{r.description}</div> : null}
                      </td>

                      <td className="px-3 py-2 font-mono text-[12px]">{String(r.strategy || "burst")}</td>
                      <td className="px-3 py-2 font-mono text-[12px]">{String(r.group_by || "-")}</td>
                      <td className="px-3 py-2 font-mono text-[12px]">{fmtSeconds(Number(r.window_seconds) || 0)}</td>
                      <td className="px-3 py-2 font-mono text-[12px]">{Number(r.min_alerts) || 0}</td>

                      <td className="px-3 py-2">
                        <div className="flex flex-wrap gap-2">
                          {(r.include_patterns || []).slice(0, 3).map((p) => (
                            <span key={p} className="inline-flex items-center rounded-md border border-border/60 bg-background/30 px-2 py-0.5 text-[11px] font-mono" title={p}>
                              {p}
                            </span>
                          ))}
                          {(r.include_patterns || []).length > 3 ? (
                            <span className="text-[11px] text-muted-foreground">+{(r.include_patterns || []).length - 3}</span>
                          ) : null}
                          {(r.include_patterns || []).length === 0 ? <span className="text-[11px] text-muted-foreground">(all)</span> : null}
                        </div>
                      </td>

                      <td className="px-3 py-2 font-mono text-[12px] text-muted-foreground">{fmtWhen(r.updated_at)}</td>

                      <td className="px-3 py-2 text-right">
                        <div className="flex justify-end gap-2">
                          <Button variant="subtle" size="sm" onClick={() => openEdit(r)}>Edit</Button>
                          <Button variant="danger" size="sm" onClick={() => remove(r)}>Delete</Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
      </Panel>

      <Drawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        title={editing ? `Edit: ${editing.name}` : "New correlation rule"}
        description="Correlate related alerts using time windows, grouping, and optional stage chains."
        widthClassName="w-[820px]"
      >
        <div className="space-y-4">
          {error ? <InlineAlert tone="danger">{error}</InlineAlert> : null}

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[11px] font-mono uppercase tracking-widest text-muted-foreground">Name</label>
              <TextInput
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g., Recon + brute force"
                className="mt-1 h-10"
              />
            </div>

            <div>
              <label className="text-[11px] font-mono uppercase tracking-widest text-muted-foreground">Severity</label>
              <SelectInput
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
                className="mt-1 h-10"
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="unknown">Unknown</option>
              </SelectInput>
            </div>
          </div>

          <div>
            <label className="text-[11px] font-mono uppercase tracking-widest text-muted-foreground">Description</label>
            <TextInput
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="(optional) Analyst notes and intent"
              className="mt-1 h-10"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <label className="flex items-center gap-2 text-sm text-muted-foreground select-none">
              <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} className="h-4 w-4" />
              Enabled
            </label>

            <div className="text-[11px] text-muted-foreground">
              Patterns support wildcards, e.g. <span className="font-mono">ssh_* , *scan*</span>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[11px] font-mono uppercase tracking-widest text-muted-foreground">Strategy</label>
              <SelectInput
                value={strategy}
                onChange={(e) => setStrategy((e.target.value === "chain" ? "chain" : "burst") as any)}
                className="mt-1 h-10"
              >
                <option value="burst">Burst (count threshold)</option>
                <option value="chain">Chain (stage requirements)</option>
              </SelectInput>
            </div>

            <div>
              <label className="text-[11px] font-mono uppercase tracking-widest text-muted-foreground">Group by</label>
              <SelectInput
                value={groupBy}
                onChange={(e) => setGroupBy(e.target.value)}
                className="mt-1 h-10"
              >
                <option value="src_ip">Source IP</option>
                <option value="dst_ip">Destination IP</option>
                <option value="dst_port">Destination port</option>
                <option value="src_dst">Source → Destination</option>
                <option value="src_dst_port">Source → Destination:Port</option>
                <option value="none">All alerts</option>
              </SelectInput>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[11px] font-mono uppercase tracking-widest text-muted-foreground">Window (seconds)</label>
              <DraftNumberInput
                value={windowSeconds}
                min={30}
                fallback={600}
                onCommit={setWindowSeconds}
                className="ui-input mt-1 h-10"
                title="Correlation window in seconds"
              />
            </div>
            <div>
              <label className="text-[11px] font-mono uppercase tracking-widest text-muted-foreground">Min alerts</label>
              <DraftNumberInput
                value={minAlerts}
                min={1}
                fallback={2}
                onCommit={setMinAlerts}
                className="ui-input mt-1 h-10"
                title="Minimum alerts required"
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[11px] font-mono uppercase tracking-widest text-muted-foreground">Include patterns</label>
              <TextInput
                value={includeCsv}
                onChange={(e) => setIncludeCsv(e.target.value)}
                placeholder="(blank = all) e.g., ssh_* , port_scan_*"
                className="mt-1 h-10"
              />
            </div>
            <div>
              <label className="text-[11px] font-mono uppercase tracking-widest text-muted-foreground">Exclude patterns</label>
              <TextInput
                value={excludeCsv}
                onChange={(e) => setExcludeCsv(e.target.value)}
                placeholder="optional, e.g., test_*"
                className="mt-1 h-10"
              />
            </div>
          </div>

          {strategy === "chain" ? (
            <div className="rounded-xl border border-border/60 bg-background/20 p-3 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-sm font-semibold">Stages</div>
                  <div className="text-xs text-muted-foreground">
                    Each stage must match patterns at least <span className="font-mono">min_count</span> times in the incident.
                  </div>
                </div>
                <Button
                  variant="subtle"
                  size="md"
                  onClick={() => setStages((prev) => [...prev, { key: uid(), name: "", patternsCsv: "", min_count: 1 }])}
                >
                  Add stage
                </Button>
              </div>

              {stages.length === 0 ? (
                <div className="rounded-lg border border-border/60 bg-background/30 px-3 py-2 text-sm text-muted-foreground">
                  No stages yet.
                </div>
              ) : (
                <div className="space-y-3">
                  {stages.map((st, idx) => (
                    <div key={st.key} className="rounded-lg border border-border/60 bg-background/30 p-3">
                      <div className="flex items-center justify-between gap-3">
                        <div className="text-xs font-mono uppercase tracking-widest text-muted-foreground">Stage {idx + 1}</div>
                        <Button
                          variant="danger"
                          size="sm"
                          onClick={() => setStages((prev) => prev.filter((x) => x.key !== st.key))}
                        >
                          Remove
                        </Button>
                      </div>

                      <div className="mt-3 grid grid-cols-2 gap-3">
                        <div>
                          <label className="text-[11px] font-mono uppercase tracking-widest text-muted-foreground">Name</label>
                          <TextInput
                            value={st.name}
                            onChange={(e) => {
                              const v = e.target.value;
                              setStages((prev) => prev.map((x) => (x.key === st.key ? { ...x, name: v } : x)));
                            }}
                            placeholder="e.g., Recon"
                            className="mt-1 h-10"
                          />
                        </div>

                        <div>
                          <label className="text-[11px] font-mono uppercase tracking-widest text-muted-foreground">Min count</label>
                          <DraftNumberInput
                            value={st.min_count}
                            min={1}
                            fallback={1}
                            onCommit={(v) => {
                              setStages((prev) => prev.map((x) => (x.key === st.key ? { ...x, min_count: v } : x)));
                            }}
                            className="ui-input mt-1 h-10"
                            title="Minimum matches for this stage"
                          />
                        </div>
                      </div>

                      <div className="mt-3">
                        <label className="text-[11px] font-mono uppercase tracking-widest text-muted-foreground">Patterns</label>
                        <TextInput
                          value={st.patternsCsv}
                          onChange={(e) => {
                            const v = e.target.value;
                            setStages((prev) => prev.map((x) => (x.key === st.key ? { ...x, patternsCsv: v } : x)));
                          }}
                          placeholder="e.g., port_scan_* , horizontal_scan_*"
                          className="mt-1 h-10"
                        />
                        <div className="mt-1 text-xs text-muted-foreground">
                          Separate multiple patterns with commas.
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : null}

          <div className="flex items-center justify-end gap-2 pt-2">
            <Button variant="subtle" size="lg" onClick={() => setDrawerOpen(false)}>Cancel</Button>
            <Button variant="primary" size="lg" onClick={save} disabled={saving}>
              {saving ? "Saving…" : "Save"}
            </Button>
          </div>
        </div>
      </Drawer>
    </div>
  );
}
