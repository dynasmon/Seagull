import { Button } from "@/shared/components/Button";
import Drawer from "@/shared/components/Drawer";
import EmptyState from "@/shared/components/EmptyState";
import { InlineAlert } from "@/shared/components/InlineAlert";
import { Badge } from "@/shared/components/Badge";
import { SelectInput } from "@/shared/components/SelectInput";
import { TextArea } from "@/shared/components/TextArea";
import { TextInput } from "@/shared/components/TextInput";
import { cx } from "@/shared/lib/cx";

import { ALL_DAYS } from "../../constants";
import type { AlertRuleEditor } from "../../hooks/useAlertRuleEditor";
import type { AlertsRulesData } from "../../hooks/useAlertsRulesData";
import { safeJsonString } from "../../lib/alertRuleEditor";

interface AlertRuleDrawerProps {
  rulesData: AlertsRulesData;
  editor: AlertRuleEditor;
}

export function AlertRuleDrawer({ rulesData, editor }: AlertRuleDrawerProps) {
  const { selected, drawerOpen, closeDrawer } = rulesData;

  return (
    <Drawer
      open={drawerOpen}
      onClose={closeDrawer}
      title={selected ? `Edit: ${selected.id}` : "Rule editor"}
      description={
        selected
          ? `${selected.pack || "pack:-"} / ${selected.category || "cat:-"} · v${Number(selected.rule_version || 1)}${
              selected.source_file ? ` · src: ${selected.source_file}` : ""
            }`
          : "Select a rule"
      }
      widthClassName="w-[920px]"
    >
      {!selected ? (
        <EmptyState title="No selection" description="Select a rule using the Edit button in the catalog." />
      ) : (
        <div className="space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border/60 bg-background/20 px-4 py-3">
            <div className="min-w-0">
              <div className="text-sm font-semibold truncate">Rule override</div>
              <div className="text-[11px] text-muted-foreground">
                Changes here are persisted as overrides; baseline YAML remains unchanged.
              </div>
            </div>
            <div className="flex items-center gap-2">
              {selected.has_override ? (
                <Badge variant="neutral">override active</Badge>
              ) : (
                <Badge variant="neutral">baseline only</Badge>
              )}
              <Button variant="primary" size="lg" onClick={editor.handleSave} disabled={editor.saving}>
                {editor.saving ? "Saving…" : "Save"}
              </Button>
              <Button
                variant="subtle"
                size="lg"
                onClick={editor.handleReset}
                disabled={editor.saving || !selected.has_override}
                title="Remove overrides and revert to YAML"
              >
                Reset
              </Button>
            </div>
          </div>

          {editor.saveError && (
            <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
              {editor.saveError}
            </div>
          )}

          {editor.validationErrors.length > 0 && (
            <div className="rounded-xl border border-destructive/50 bg-destructive/5 p-4 space-y-2">
              <div className="text-sm font-semibold text-destructive">Validation errors — fix before saving</div>
              <ul className="space-y-1">
                {editor.validationErrors.map((e, i) => (
                  <li key={i} className="text-xs font-mono text-destructive leading-relaxed">
                    {e}
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="rounded-xl border border-border/60 bg-background/20 p-4 space-y-3">
            <div className="flex items-center justify-between gap-3">
              <div>
                <div className="text-sm font-semibold">Enabled</div>
                <div className="text-[11px] text-muted-foreground">Disable to stop generating alerts for this rule.</div>
              </div>
              <input
                type="checkbox"
                checked={editor.enabled}
                onChange={(e) => editor.setEnabled(e.target.checked)}
                className="h-4 w-4"
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="rounded-lg border border-border/60 bg-background/20 px-3 py-2">
                <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Severity</div>
                <SelectInput value={editor.severity} onChange={(e) => editor.setSeverity(e.target.value)} className="mt-1 h-9">
                  <option value="critical">critical</option>
                  <option value="high">high</option>
                  <option value="medium">medium</option>
                  <option value="low">low</option>
                  <option value="unknown">unknown</option>
                </SelectInput>
              </div>

              <div className="rounded-lg border border-border/60 bg-background/20 px-3 py-2">
                <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Lookback window</div>
                <TextInput
                  value={editor.window}
                  onChange={(e) => editor.setWindow(e.target.value)}
                  className="mt-1 h-9 font-mono"
                  placeholder="e.g. 5m, 30s, 1h"
                />
                <div className="mt-1 text-[11px] text-muted-foreground">Time range used to query events.</div>
              </div>

              <div className="rounded-lg border border-border/60 bg-background/20 px-3 py-2">
                <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Cooldown</div>
                <TextInput
                  value={editor.cooldown}
                  onChange={(e) => editor.setCooldown(e.target.value)}
                  className="mt-1 h-9 font-mono"
                  placeholder="e.g. 10m"
                />
                <div className="mt-1 text-[11px] text-muted-foreground">
                  Deduplicates alerts for the same target within the cooldown.
                </div>
              </div>

              <div className="rounded-lg border border-border/60 bg-background/20 px-3 py-2">
                <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Min events (guard)</div>
                <TextInput
                  value={editor.minEvents}
                  onChange={(e) => editor.setMinEvents(e.target.value)}
                  className="mt-1 h-9 font-mono"
                  placeholder="optional"
                />
                <div className="mt-1 text-[11px] text-muted-foreground">
                  Suppresses alerts until a minimum number of events exists.
                </div>
              </div>
            </div>
          </div>

          <div className="rounded-xl border border-border/60 bg-background/20 p-4 space-y-3">
            <div>
              <div className="text-sm font-semibold">Primary condition</div>
              <div className="text-[11px] text-muted-foreground">
                Optional post-filter condition. If set, rule only triggers when the aggregated value matches.
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="rounded-lg border border-border/60 bg-background/20 px-3 py-2">
                <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Operator</div>
                <SelectInput value={editor.condOp} onChange={(e) => editor.setCondOp(e.target.value)} className="mt-1 h-9 font-mono">
                  <option value=">=">{">="}</option>
                  <option value=">">{">"}</option>
                  <option value="==">{"=="}</option>
                  <option value="<">{"<"}</option>
                  <option value="<=">{"<="}</option>
                  <option value="!=">{"!="}</option>
                </SelectInput>
              </div>

              <div className="rounded-lg border border-border/60 bg-background/20 px-3 py-2 md:col-span-2">
                <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Value</div>
                <TextInput
                  value={editor.condValue}
                  onChange={(e) => editor.setCondValue(e.target.value)}
                  className="mt-1 h-9 font-mono"
                  placeholder="e.g. 10"
                />
                <div className="mt-1 text-[11px] text-muted-foreground">
                  Leave empty to disable (no post-filter condition).
                </div>
              </div>
            </div>
          </div>

          <div className="rounded-xl border border-border/60 bg-background/20 p-4 space-y-3">
            <div className="flex items-center justify-between gap-3">
              <div>
                <div className="text-sm font-semibold">Schedule</div>
                <div className="text-[11px] text-muted-foreground">
                  Optional time window to enable this rule (useful for "business hours only", etc).
                </div>
              </div>
              <label className="flex items-center gap-2 text-sm text-muted-foreground">
                <input
                  type="checkbox"
                  checked={editor.schedEnabled}
                  onChange={(e) => editor.setSchedEnabled(e.target.checked)}
                  className="h-4 w-4"
                />
                enabled
              </label>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="rounded-lg border border-border/60 bg-background/20 px-3 py-2">
                <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Timezone</div>
                <TextInput
                  value={editor.schedTz}
                  onChange={(e) => editor.setSchedTz(e.target.value)}
                  className="mt-1 h-9 font-mono"
                  placeholder="America/Fortaleza"
                />
              </div>

              <div className="rounded-lg border border-border/60 bg-background/20 px-3 py-2">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Start</div>
                    <TextInput
                      value={editor.schedStart}
                      onChange={(e) => editor.setSchedStart(e.target.value)}
                      className="mt-1 h-9 font-mono"
                      placeholder="22:00"
                    />
                  </div>
                  <div>
                    <div className="text-[10px] uppercase tracking-widest text-muted-foreground">End</div>
                    <TextInput
                      value={editor.schedEnd}
                      onChange={(e) => editor.setSchedEnd(e.target.value)}
                      className="mt-1 h-9 font-mono"
                      placeholder="06:00"
                    />
                  </div>
                </div>
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between">
                <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Days</div>
                <div className="flex items-center gap-2">
                  <button type="button" onClick={() => editor.setAllDays(true)} className="text-[11px] text-muted-foreground hover:text-foreground">
                    all
                  </button>
                  <span className="text-muted-foreground">·</span>
                  <button type="button" onClick={() => editor.setAllDays(false)} className="text-[11px] text-muted-foreground hover:text-foreground">
                    none
                  </button>
                </div>
              </div>

              <div className="mt-2 flex flex-wrap gap-2">
                {ALL_DAYS.map((d) => (
                  <button
                    key={d}
                    onClick={() => editor.toggleDay(d)}
                    className={cx(
                      "rounded-md border border-border/60 px-2 py-1 text-[11px] font-mono",
                      editor.schedDays[d] ? "bg-muted/40" : "bg-background/20 text-muted-foreground",
                    )}
                    type="button"
                    title="Toggle"
                  >
                    {d}
                  </button>
                ))}
              </div>

              <div className="mt-2 text-[11px] text-muted-foreground">
                Tip: if start is greater than end, the window crosses midnight (e.g., 22:00 → 06:00).
              </div>
            </div>
          </div>

          <div className="rounded-xl border border-border/60 bg-background/20 p-4 space-y-3">
            <div className="flex items-center justify-between gap-3">
              <div>
                <div className="text-sm font-semibold">Advanced patch (JSON)</div>
                <div className="text-[11px] text-muted-foreground">
                  Deep-merge applied last. Use to edit{" "}
                  <span className="font-mono">match</span>,{" "}
                  <span className="font-mono">distinct_conditions</span>, etc.
                </div>
              </div>
            </div>
            {editor.patchError ? <InlineAlert tone="danger" className="text-xs">{editor.patchError}</InlineAlert> : null}
            <TextArea
              value={editor.patchText}
              onChange={(e) => editor.setPatchText(e.target.value)}
              className="min-h-[180px] font-mono text-[11px] leading-relaxed"
              spellCheck={false}
            />
          </div>

          <div className="rounded-xl border border-border/60 bg-background/20 p-4 space-y-3">
            <div>
              <div className="text-sm font-semibold">Tuning (JSON object)</div>
              <div className="text-[11px] text-muted-foreground">
                Dedicated tuning payload stored outside generic patch (with audit trail).
              </div>
            </div>
            {editor.tuningError ? <InlineAlert tone="danger" className="text-xs">{editor.tuningError}</InlineAlert> : null}
            <TextArea
              value={editor.tuningText}
              onChange={(e) => editor.setTuningText(e.target.value)}
              className="min-h-[120px] font-mono text-[11px] leading-relaxed"
              spellCheck={false}
            />
          </div>

          <div className="rounded-xl border border-border/60 bg-background/20 p-4 space-y-3">
            <div>
              <div className="text-sm font-semibold">Suppressions (JSON array)</div>
              <div className="text-[11px] text-muted-foreground space-y-1">
                <div>
                  Each item requires <span className="font-mono">reason</span> (string) and either{" "}
                  <span className="font-mono">until</span> (ISO datetime) or{" "}
                  <span className="font-mono">permanent: true</span>.
                </div>
                <div>
                  Use <span className="font-mono">when</span> to scope by field (e.g.{" "}
                  <span className="font-mono">{`{"src_ip": "10.0.0.1"}`}</span>). Broad suppressions (no{" "}
                  <span className="font-mono">when</span>) on high/critical rules require{" "}
                  <span className="font-mono">confirm_high_risk: true</span>.
                </div>
              </div>
            </div>
            {editor.suppressionsError ? (
              <InlineAlert tone="danger" className="text-xs">{editor.suppressionsError}</InlineAlert>
            ) : null}
            {(selected.severity === "high" || selected.severity === "critical") && (
              <InlineAlert tone="warning" className="text-xs">
                This is a <strong>{selected.severity}</strong> rule. Broad suppressions (empty{" "}
                <span className="font-mono">when</span>) require{" "}
                <span className="font-mono">confirm_high_risk: true</span> on each item.
              </InlineAlert>
            )}
            <TextArea
              value={editor.suppressionsText}
              onChange={(e) => editor.setSuppressionsText(e.target.value)}
              className="min-h-[140px] font-mono text-[11px] leading-relaxed"
              spellCheck={false}
            />
          </div>

          <div className="rounded-xl border border-border/60 bg-background/20">
            <div className="flex items-center justify-between gap-3 px-4 py-3 border-b border-border/60">
              <div className="text-sm font-semibold">Governance history</div>
              <Button variant="subtle" size="sm" onClick={() => selected && rulesData.loadHistory(selected.id)}>
                Refresh
              </Button>
            </div>
            {rulesData.historyError ? (
              <div className="p-4 text-xs text-destructive">{rulesData.historyError}</div>
            ) : rulesData.historyLoading ? (
              <div className="p-4 text-xs text-muted-foreground">Loading history…</div>
            ) : rulesData.historyRows.length === 0 ? (
              <div className="p-4 text-xs text-muted-foreground">No governance history yet.</div>
            ) : (
              <div className="max-h-[220px] overflow-auto">
                <table className="w-full text-xs">
                  <thead className="bg-muted/20">
                    <tr>
                      <th className="px-3 py-2 text-left">When</th>
                      <th className="px-3 py-2 text-left">Kind</th>
                      <th className="px-3 py-2 text-left">Action</th>
                      <th className="px-3 py-2 text-left">Actor</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rulesData.historyRows.map((h) => (
                      <tr key={`${h.kind}-${h.id}`} className="border-t border-border/50">
                        <td className="px-3 py-2 whitespace-nowrap">{new Date(h.created_at).toLocaleString()}</td>
                        <td className="px-3 py-2 font-mono">{h.kind}</td>
                        <td className="px-3 py-2 font-mono">{h.action}</td>
                        <td className="px-3 py-2">{h.actor_username || "-"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="rounded-xl border border-border/60 bg-background/20">
            <div className="flex items-center justify-between gap-3 px-4 py-3 border-b border-border/60">
              <div className="text-sm font-semibold">Effective rule</div>
              <div className="flex items-center gap-2">
                <span className="text-[11px] text-muted-foreground">Show</span>
                <input
                  type="checkbox"
                  checked={editor.showEffective}
                  onChange={(e) => editor.setShowEffective(e.target.checked)}
                  className="h-4 w-4"
                />
              </div>
            </div>
            {editor.showEffective ? (
              <pre className="p-4 text-[11px] leading-relaxed overflow-auto">{safeJsonString(selected.effective)}</pre>
            ) : (
              <div className="p-4 text-xs text-muted-foreground">Hidden (toggle "Show" to display).</div>
            )}
          </div>
        </div>
      )}
    </Drawer>
  );
}
