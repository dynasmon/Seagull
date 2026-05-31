import { EuiButtonGroup } from "@elastic/eui";

import { Button } from "@/shared/components/Button";
import Drawer from "@/shared/components/Drawer";
import EmptyState from "@/shared/components/EmptyState";
import { InlineAlert } from "@/shared/components/InlineAlert";
import { JsonBlock } from "@/shared/components/JsonBlock";
import { SelectInput } from "@/shared/components/SelectInput";
import { StatusPill } from "@/shared/components/StatusPill";
import { Table, type Column } from "@/shared/components/Table";
import { TextArea } from "@/shared/components/TextArea";
import { TextInput } from "@/shared/components/TextInput";
import { ToggleSwitch } from "@/shared/components/ToggleSwitch";
import { InvestigationSection } from "@/shared/components/investigation";

import { ALL_DAYS } from "../../constants";
import type { AlertRuleEditor } from "../../hooks/useAlertRuleEditor";
import type { AlertsRulesData } from "../../hooks/useAlertsRulesData";
import type { RuleGovernanceHistory } from "../../types";

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

const HISTORY_COLUMNS: Array<Column<RuleGovernanceHistory>> = [
  {
    key: "when",
    title: "When",
    className: "whitespace-nowrap font-mono text-muted-foreground",
    render: (h) => new Date(h.created_at).toLocaleString(),
  },
  { key: "kind", title: "Kind", className: "font-mono", render: (h) => h.kind },
  { key: "action", title: "Action", className: "font-mono", render: (h) => h.action },
  { key: "actor", title: "Actor", render: (h) => h.actor_username || "-" },
];

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
            {editor.saveError ? (
              <InlineAlert tone="danger" className="text-xs">
                {editor.saveError}
              </InlineAlert>
            ) : null}

            {editor.validationErrors.length > 0 ? (
              <InlineAlert tone="danger" className="mt-2">
                <div className="text-sm font-semibold">Validation errors — fix before saving</div>
                <ul className="mt-1 space-y-1">
                  {editor.validationErrors.map((e, i) => (
                    <li key={i} className="font-mono text-xs leading-relaxed">
                      {e}
                    </li>
                  ))}
                </ul>
              </InlineAlert>
            ) : null}
          </InvestigationSection>

          <InvestigationSection title="Activation">
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="text-sm font-semibold">Enabled</div>
                <div className="text-[11px] text-muted-foreground">Disable to stop generating alerts for this rule.</div>
              </div>
              <ToggleSwitch checked={editor.enabled} onChange={(e) => editor.setEnabled(e.target.checked)} />
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
              <ToggleSwitch
                label="enabled"
                checked={editor.schedEnabled}
                onChange={(e) => editor.setSchedEnabled(e.target.checked)}
              />
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

              <div className="mt-2">
                <EuiButtonGroup
                  legend="Schedule days"
                  type="multi"
                  buttonSize="compressed"
                  options={ALL_DAYS.map((d) => ({ id: d, label: d }))}
                  idToSelectedMap={editor.schedDays}
                  onChange={(id) => editor.toggleDay(id)}
                />
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
                <Table
                  className="!rounded-none !border-0 !bg-transparent !shadow-none text-xs"
                  columns={HISTORY_COLUMNS}
                  rows={rulesData.historyRows}
                  rowKey={(h) => `${h.kind}-${h.id}`}
                />
              </div>
            )}
          </InvestigationSection>

          <InvestigationSection
            title="Effective rule"
            right={
              <ToggleSwitch
                label="Show"
                checked={editor.showEffective}
                onChange={(e) => editor.setShowEffective(e.target.checked)}
              />
            }
            bodyClassName="p-0"
          >
            {editor.showEffective ? (
              <div className="p-4">
                <JsonBlock value={selected.effective} maxHeight="320px" />
              </div>
            ) : (
              <div className="p-4 text-xs text-muted-foreground">Hidden (toggle "Show" to display).</div>
            )}
          </InvestigationSection>
        </div>
      )}
    </Drawer>
  );
}
