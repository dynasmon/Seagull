import { useMemo } from "react";

import Drawer from "@/shared/components/Drawer";
import { JsonBlock } from "@/shared/components/JsonBlock";
import {
  InvestigationFactCard,
  InvestigationMetaStrip,
  InvestigationRawJsonPanel,
  InvestigationSection,
  InvestigationShell,
  InvestigationSummaryGrid,
  formatInvestigationTimestamp,
} from "@/shared/components/investigation";
import { cx } from "@/shared/lib/cx";

import { PhaseTimeline, ScanStats } from "./ActiveScanPanel";
import { LiveElapsedText } from "./LiveElapsedText";
import { fmtSec, fmtAge, scanLifecycleLabel, scanPhaseLabel, scanTriggerLabel, scanVariant } from "./scanUtils";
import type { VulnScan } from "./types";

function ScanDurationDisplay({ scan }: { scan: VulnScan }) {
  const isLive =
    !scan.finished_at &&
    (scan.lifecycle_state === "queued" ||
      scan.lifecycle_state === "acknowledged" ||
      scan.lifecycle_state === "running");
  const className = "font-mono text-sm text-foreground";

  if (typeof scan.duration_ms === "number" && Number.isFinite(scan.duration_ms)) {
    return <span className={className}>{fmtSec(scan.duration_ms / 1000)}</span>;
  }
  if (scan.started_at && scan.finished_at) {
    const ms = Date.parse(scan.finished_at) - Date.parse(scan.started_at);
    return (
      <span className={className}>
        {Number.isFinite(ms) ? fmtSec(Math.max(0, ms / 1000)) : "-"}
      </span>
    );
  }
  if (isLive && (scan.started_at || scan.queued_at)) {
    return (
      <LiveElapsedText
        startIso={scan.started_at ?? scan.queued_at}
        endIso={null}
        className={cx(className, "text-primary")}
      />
    );
  }
  return <span className={className}>-</span>;
}

export default function VulnScanDrawer({
  open,
  scan,
  onClose,
}: {
  open: boolean;
  scan: VulnScan | null;
  onClose: () => void;
}) {
  const queueWaitLabel = useMemo(() => {
    if (!scan?.queued_at) return "-";
    const queuedAt = Date.parse(scan.queued_at);
    const dequeuedAt = Date.parse(
      scan.acknowledged_at || scan.started_at || scan.finished_at || ""
    );
    if (Number.isNaN(queuedAt) || Number.isNaN(dequeuedAt)) return "-";
    return fmtSec(Math.max(0, (dequeuedAt - queuedAt) / 1000));
  }, [scan]);

  const hasTimeline = useMemo(
    () => Boolean(scan && Object.keys(scan.phase_timestamps ?? {}).length),
    [scan]
  );
  const hasStats = useMemo(
    () =>
      Boolean(
        scan &&
          Object.values(scan.stats ?? {}).some(
            (value) => typeof value === "number" && Number.isFinite(value)
          )
      ),
    [scan]
  );

  if (!scan) return null;

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title={`Scan #${scan.id}`}
      description={`${scan.tool}${scan.tool_version ? ` v${scan.tool_version}` : ""} · ${scan.scan_uuid}`}
      widthClassName="w-[1040px]"
      headerLabel="Vulnerability scan"
    >
      <InvestigationShell>
        <InvestigationMetaStrip
          items={[
            { label: "Lifecycle", value: scanLifecycleLabel(scan.lifecycle_state), variant: scanVariant(scan.lifecycle_state) },
            { label: "Phase", value: scanPhaseLabel(scan.current_phase), variant: "neutral" },
            { label: "Trigger", value: scanTriggerLabel(scan.trigger_source) },
            { label: "Tool", value: `${scan.tool}${scan.tool_version ? ` @ ${scan.tool_version}` : ""}` },
            { label: "Reporter", value: scan.reporter_agent_id || "-" },
            { label: "Target", value: scan.target || "-" },
          ]}
        />

        <InvestigationSection title="Execution overview" subtitle="Lifecycle state, timing, scope target, and collection profile.">
          <InvestigationSummaryGrid className="xl:grid-cols-4">
            <InvestigationFactCard label="Scan UUID" value={scan.scan_uuid} mono copyValue={scan.scan_uuid} />
            <InvestigationFactCard label="Reporter" value={scan.reporter_agent_id || "-"} mono />
            <InvestigationFactCard label="Target" value={scan.target || "-"} mono copyValue={scan.target || null} />
            <InvestigationFactCard label="Duration" value={<ScanDurationDisplay scan={scan} />} />
            <InvestigationFactCard label="Queue wait" value={queueWaitLabel} mono />
            <InvestigationFactCard label="Queued" value={formatInvestigationTimestamp(scan.queued_at)} mono />
            <InvestigationFactCard label="Acknowledged" value={formatInvestigationTimestamp(scan.acknowledged_at)} mono />
            <InvestigationFactCard label="Started" value={formatInvestigationTimestamp(scan.started_at)} mono />
            <InvestigationFactCard label="Finished" value={formatInvestigationTimestamp(scan.finished_at)} mono />
            <InvestigationFactCard
              label="Last progress"
              value={scan.last_progress_at ? `${formatInvestigationTimestamp(scan.last_progress_at)} · ${fmtAge(scan.last_progress_at)}` : "-"}
              mono
            />
            <InvestigationFactCard
              label="Profile"
              value={(scan.config as any)?.analysis_profile || (scan.scope as any)?.analysis_profile || "-"}
              mono
            />
          </InvestigationSummaryGrid>

          {scan.error_summary ? (
            <div className="mt-4 rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-sm text-danger">
              {scan.error_summary}
            </div>
          ) : null}
        </InvestigationSection>

        <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
          <InvestigationSection title="Execution timeline" className="xl:col-span-2">
            {hasTimeline ? (
              <PhaseTimeline scan={scan} />
            ) : (
              <div className="text-sm text-muted-foreground">
                No phase transitions have been recorded for this scan yet.
              </div>
            )}
          </InvestigationSection>

          <InvestigationSection title="Pipeline counters">
            {hasStats ? (
              <div className="space-y-4">
                <ScanStats stats={scan.stats} />
                <JsonBlock value={scan.stats} showControls={false} />
              </div>
            ) : (
              <div className="text-sm text-muted-foreground">
                No numeric pipeline counters were reported for this scan.
              </div>
            )}
          </InvestigationSection>
        </div>

        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          <InvestigationSection title="Scope">
            <JsonBlock value={scan.scope} showControls={false} />
          </InvestigationSection>
          <InvestigationSection title="Config">
            <JsonBlock value={scan.config} showControls={false} />
          </InvestigationSection>
        </div>

        <InvestigationRawJsonPanel value={scan} title="Raw scan JSON" />
      </InvestigationShell>
    </Drawer>
  );
}
