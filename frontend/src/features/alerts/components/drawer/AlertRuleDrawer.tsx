import { Button } from "@/shared/components/Button";
import Drawer from "@/shared/components/Drawer";
import EmptyState from "@/shared/components/EmptyState";
import { InlineAlert } from "@/shared/components/InlineAlert";
import { SelectInput } from "@/shared/components/SelectInput";
import { StatusPill } from "@/shared/components/StatusPill";
import { TextArea } from "@/shared/components/TextArea";
import { TextInput } from "@/shared/components/TextInput";
import { InvestigationSection } from "@/shared/components/investigation";
import { cx } from "@/shared/lib/cx";

import { ALL_DAYS } from "../../constants";
import type { AlertRuleEditor } from "../../hooks/useAlertRuleEditor";
import type { AlertsRulesData } from "../../hooks/useAlertsRulesData";
import { safeJsonString } from "../../lib/alertRuleEditor";

interface AlertRuleDrawerProps {
  rulesData: AlertsRulesData;
  editor: AlertRuleEditor;
}

function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
      {children}
    </div>
  );
}

export function AlertRuleDrawer({ rulesData, editor }: AlertRuleDrawerProps) {
  const { selected, drawerOpen, closeDrawer } = rulesData;

  const headerActions = selected ? (
    <div className="flex items-center gap-2">
      <Button variant="primary" size="md" onClick={editor.handleSave} disabled={editor.saving}>
        {editor.saving ? "Saving…" : "Save"}
      </Button>
      <Button
        variant="subtle"
        size="md"
        onClick={editor.handleReset}
        disabled={editor.saving || !selected.has_override}
        title="Remove overrides and revert to YAML"
      >
        Reset
      </Button>
    </div>
  ) : null;

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
      widthClassName="w-[960px]"
      headerLabel="Rule"
      headerActions={headerActions}
    >
      {!selected ? (
        <EmptyState title="No selection" description="Select a rule using the Edit button in the catalog." />
      ) : (
        <div className="space-y-5">
          <InvestigationSection
            title="Override status"
            subtitle="Changes here are persisted as overrides; baseline YAML remains unchanged."
            right={
              selected.has_override ? (
                <StatusPill variant="info">override active</StatusPill>
              ) : (
                <StatusPill variant="neutral">baseline only</StatusPill>
              )
            }
          >
            {editor.saveError && (
              <div className="rounded-md border border-danger/45 bg-danger/10 px-3 py-2 text-xs text-danger">
                {editor.saveError}
              </div>
            )}

            {editor.validationErrors.length > 0 && (
              <div className="mt-2 rounded-md border border-danger/50 bg-danger/[0.06] p-3 space-y-1.5">
                <div className="text-sm font-semibold text-danger">Validation errors — fix before saving</div>
                <ul className="space-y-1">
                  {editor.validationErrors.map((e, i) => (
                    <li key={i} className="font-mono text-xs leading-relaxed text-danger">
                      {e}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </InvestigationSection>

          <InvestigationSection title="Activation">
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="text-sm font-semibold">Enabled</div>
                <div className="text-[11px] text-muted-foreground">Disable to stop generating alerts for this rule.</div>
              </div>
              <input
                type="checkbox"
                checked={editor.enabled}
                onChange={(e) => editor.setEnabled(e.target.checked)}
                className="h-4 w-4 cursor-pointer accent-primary"
              />
            </div>

            <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-2">
              <div>
                <FieldLabel>Severity</FieldLabel>
                <SelectInput value={editor.severity} onChange={(e) => editor.setSeverity(e.target.value)} className="mt-1">
                  <option value="critical">critical</option>
                  <option value="high">high</option>
                  <option value="medium">medium</option>
                  <option value="low">low</option>
                  <option value="unknown">unknown</option>
                </SelectInput>
              </div>

              <div>
                <FieldLabel>Lookback window</FieldLabel>
                <TextInput
                  value={editor.window}
                  onChange={(e) => editor.setWindow(e.target.value)}
                  className="mt-1 font-mono"
                  placeholder="e.g. 5m, 30s, 1h"
                />
                <div className="mt-1 text-[11px] text-muted-foreground">Time range used to query events.</div>
              </div>

              <div>
                <FieldLabel>Cooldown</FieldLabel>
                <TextInput
                  value={editor.cooldown}
                  onChange={(e) => editor.setCooldown(e.target.value)}
                  className="mt-1 font-mono"
                  placeholder="e.g. 10m"
                />
                <div className="mt-1 text-[11px] text-muted-foreground">
                  Deduplicates alerts for the same target within the cooldown.
                </div>
              </div>

              <div>
                <FieldLabel>Min events (guard)</FieldLabel>
                <TextInput
                  value={editor.minEvents}
                  onChange={(e) => editor.setMinEvents(e.target.value)}
                  className="mt-1 font-mono"
                  placeholder="optional"
                />
                <div className="mt-1 text-[11px] text-muted-foreground">
                  Suppresses alerts until a minimum number of events exists.
                </div>
              </div>
            </div>
          </InvestigationSection>

          <InvestigationSection
            title="Primary condition"
            subtitle="Optional post-filter condition. If set, the rule only triggers when the aggregated value matches."
          >
            <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
              <div>
                <FieldLabel>Operator</FieldLabel>
                <SelectInput value={editor.condOp} onChange={(e) => editor.setCondOp(e.target.value)} className="mt-1 font-mono">
                  <option value=">=">{">="}</option>
                  <option value=">">{">"}</option>
                  <option value="==">{"=="}</option>
                  <option value="<">{"<"}</option>
                  <option value="<=">{"<="}</option>
                  <option value="!=">{"!="}</option>
                </SelectInput>
              </div>

              <div className="md:col-span-2">
                <FieldLabel>Value</FieldLabel>
                <TextInput
                  value={editor.condValue}
                  onChange={(e) => editor.setCondValue(e.target.value)}
                  className="mt-1 font-mono"
                  placeholder="e.g. 10"
                />
                <div className="mt-1 text-[11px] text-muted-foreground">
                  Leave empty to disable (no post-filter condition).
                </div>
              </div>
            </div>
          </InvestigationSection>

          <InvestigationSection
            title="Schedule"
            subtitle='Optional time window to enable this rule (useful for "business hours only", etc).'
            right={
              <label className="flex items-center gap-2 text-xs text-muted-foreground">
                <input
                  type="checkbox"
                  checked={editor.schedEnabled}
                  onChange={(e) => editor.setSchedEnabled(e.target.checked)}
                  className="h-4 w-4 cursor-pointer accent-primary"
                />
                enabled
              </label>
            }
          >
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <div>
                <FieldLabel>Timezone</FieldLabel>
                <TextInput
                  value={editor.schedTz}
                  onChange={(e) => editor.setSchedTz(e.target.value)}
                  className="mt-1 font-mono"
                  placeholder="America/Fortaleza"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <FieldLabel>Start</FieldLabel>
                  <TextInput
                    value={editor.schedStart}
                    onChange={(e) => editor.setSchedStart(e.target.value)}
                    className="mt-1 font-mono"
                    placeholder="22:00"
                  />
                </div>
                <div>
                  <FieldLabel>End</FieldLabel>
                  <TextInput
                    value={editor.schedEnd}
                    onChange={(e) => editor.setSchedEnd(e.target.value)}
                    className="mt-1 font-mono"
                    placeholder="06:00"
                  />
                </div>
              </div>
            </div>

            <div className="mt-3">
              <div className="flex items-center justify-between">
                <FieldLabel>Days</FieldLabel>
                <div className="flex items-center gap-2">
                  <button type="button" onClick={() => editor.setAllDays(true)} className="text-[11px] text-muted-foreground hover:text-foreground">
                    all
                  </button>
                  <span className="text-muted-foreground/60">·</span>
                  <button type="button" onClick={() => editor.setAllDays(false)} className="text-[11px] text-muted-foreground hover:text-foreground">
                    none
                  </button>
                </div>
              </div>

              <div className="mt-2 flex flex-wrap gap-1.5">
                {ALL_DAYS.map((d) => (
                  <button
                    key={d}
                    onClick={() => editor.toggleDay(d)}
                    className={cx(
                      "h-7 rounded-md border px-2 font-mono text-[11px] transition-colors",
                      editor.schedDays[d]
                        ? "border-primary/45 bg-primary/12 text-primary"
                        : "border-border bg-card text-muted-foreground hover:border-primary/30 hover:bg-muted",
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
          </InvestigationSection>

          <InvestigationSection
            title="Advanced patch (JSON)"
            subtitle={
              <>
                Deep-merge applied last. Use to edit <span className="font-mono">match</span>,{" "}
                <span className="font-mono">distinct_conditions</span>, etc.
              </>
            }
          >
            {editor.patchError ? <InlineAlert tone="danger" className="text-xs">{editor.patchError}</InlineAlert> : null}
            <TextArea
              value={editor.patchText}
              onChange={(e) => editor.setPatchText(e.target.value)}
              className="mt-2 min-h-[180px] font-mono text-[11px] leading-relaxed"
              spellCheck={false}
            />
          </InvestigationSection>

          <InvestigationSection
            title="Tuning (JSON object)"
            subtitle="Dedicated tuning payload stored outside generic patch (with audit trail)."
          >
            {editor.tuningError ? <InlineAlert tone="danger" className="text-xs">{editor.tuningError}</InlineAlert> : null}
            <TextArea
              value={editor.tuningText}
              onChange={(e) => editor.setTuningText(e.target.value)}
              className="mt-2 min-h-[120px] font-mono text-[11px] leading-relaxed"
              spellCheck={false}
            />
          </InvestigationSection>

          <InvestigationSection
            title="Suppressions (JSON array)"
            subtitle={
              <>
                Each item requires <span className="font-mono">reason</span> and either{" "}
                <span className="font-mono">until</span> (ISO datetime) or <span className="font-mono">permanent: true</span>.
                Broad suppressions on high/critical rules require <span className="font-mono">confirm_high_risk: true</span>.
              </>
            }
          >
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
              className="mt-2 min-h-[140px] font-mono text-[11px] leading-relaxed"
              spellCheck={false}
            />
          </InvestigationSection>

          <InvestigationSection
            title="Governance history"
            right={
              <Button variant="subtle" size="sm" onClick={() => selected && rulesData.loadHistory(selected.id)}>
                Refresh
              </Button>
            }
            bodyClassName="p-0"
          >
            {rulesData.historyError ? (
              <div className="p-4 text-xs text-danger">{rulesData.historyError}</div>
            ) : rulesData.historyLoading ? (
              <div className="p-4 text-xs text-muted-foreground">Loading history…</div>
            ) : rulesData.historyRows.length === 0 ? (
              <div className="p-4 text-xs text-muted-foreground">No governance history yet.</div>
            ) : (
              <div className="max-h-[240px] overflow-auto">
                <table className="w-full text-xs">
                  <thead className="bg-surface-2/80">
                    <tr className="text-left text-[10px] font-semibold uppercase tracking-[0.08em] text-muted-foreground">
                      <th className="px-3 py-2">When</th>
                      <th className="px-3 py-2">Kind</th>
                      <th className="px-3 py-2">Action</th>
                      <th className="px-3 py-2">Actor</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rulesData.historyRows.map((h) => (
                      <tr key={`${h.kind}-${h.id}`} className="border-t border-border/55">
                        <td className="whitespace-nowrap px-3 py-2 font-mono text-muted-foreground">
                          {new Date(h.created_at).toLocaleString()}
                        </td>
                        <td className="px-3 py-2 font-mono">{h.kind}</td>
                        <td className="px-3 py-2 font-mono">{h.action}</td>
                        <td className="px-3 py-2">{h.actor_username || "-"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </InvestigationSection>

          <InvestigationSection
            title="Effective rule"
            right={
              <label className="flex items-center gap-2 text-[11px] text-muted-foreground">
                <span>Show</span>
                <input
                  type="checkbox"
                  checked={editor.showEffective}
                  onChange={(e) => editor.setShowEffective(e.target.checked)}
                  className="h-4 w-4 cursor-pointer accent-primary"
                />
              </label>
            }
            bodyClassName="p-0"
          >
            {editor.showEffective ? (
              <pre className="overflow-auto p-4 text-[11px] leading-relaxed">{safeJsonString(selected.effective)}</pre>
            ) : (
              <div className="p-4 text-xs text-muted-foreground">Hidden (toggle "Show" to display).</div>
            )}
          </InvestigationSection>
        </div>
      )}
    </Drawer>
  );
}
