import { Button } from "@/shared/components/Button";
import { DataQueryStateBanner, DataStatsStrip, DataViewToolbar, DebouncedSearchInput } from "@/shared/components/DataView";
import { Panel } from "@/shared/components/Panel";
import { cx } from "@/shared/lib/cx";

import { useAlertRuleEditor } from "../hooks/useAlertRuleEditor";
import { useAlertsRulesData } from "../hooks/useAlertsRulesData";
import { AlertRuleDrawer } from "./drawer/AlertRuleDrawer";
import { AlertsRulesList } from "./AlertsRulesList";

export function AlertsRulesWorkspace() {
  const rulesData = useAlertsRulesData();
  const editor = useAlertRuleEditor(rulesData.selected, rulesData.reload, rulesData.loadHistory);

  const panelHeightClass = "h-[640px] xl:h-[calc(100vh-300px)]";
  const headerRight = rulesData.loading ? "Loading…" : `${rulesData.filtered.length} rules`;

  return (
    <div className="space-y-4">
      <DataViewToolbar
        left={
          <div>
            <h2 className="text-base font-semibold tracking-tight">Rules</h2>
            <div className="text-xs text-muted-foreground">
              Configure thresholds, lookback windows, cooldowns, schedules and severity with override safety.
            </div>
          </div>
        }
        right={
          <div className="flex flex-wrap items-center gap-2">
            <DebouncedSearchInput
              value={rulesData.q}
              onChange={rulesData.setQ}
              placeholder="Search rule, pack, category..."
              className="h-9 min-w-[240px]"
            />
            <Button variant="subtle" size="md" onClick={() => rulesData.reload()} disabled={rulesData.loading}>
              Refresh
            </Button>
          </div>
        }
      />

      <DataQueryStateBanner
        tone={rulesData.error ? "danger" : "neutral"}
        message={
          rulesData.error ||
          `${rulesData.filtered.length} filtered rules · ${rulesData.rules.length} total rules`
        }
        right={rulesData.loading ? "loading" : "ready"}
      />

      <DataStatsStrip
        stats={[
          { label: "Rules", value: rulesData.rules.length },
          { label: "Filtered", value: rulesData.filtered.length },
          { label: "Enabled", value: rulesData.ruleStats.enabled, tone: "success" },
          { label: "Overrides", value: rulesData.ruleStats.overrides, tone: "info" },
          {
            label: "Critical/High",
            value: rulesData.ruleStats.criticalHigh,
            tone: rulesData.ruleStats.criticalHigh > 0 ? "danger" : "default",
          },
        ]}
      />

      <Panel
        title="Rule catalog"
        actions={<span className="text-[10.5px] text-muted-foreground">{headerRight}</span>}
        scrollY
        className={cx(panelHeightClass)}
        padded={false}
      >
        <AlertsRulesList
          loading={rulesData.loading}
          filtered={rulesData.filtered}
          selectedId={rulesData.selectedId}
          onEdit={rulesData.openDrawerFor}
        />
      </Panel>

      <AlertRuleDrawer rulesData={rulesData} editor={editor} />
    </div>
  );
}
