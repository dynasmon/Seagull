import { useMemo, useState } from "react";

import { Button } from "@/shared/components/Button";
import Drawer from "@/shared/components/Drawer";
import { InlineAlert } from "@/shared/components/InlineAlert";
import { JsonBlock } from "@/shared/components/JsonBlock";
import {
  InvestigationChipList,
  InvestigationFactCard,
  InvestigationMetaStrip,
  InvestigationSection,
  InvestigationShell,
  InvestigationSummaryGrid,
  formatInvestigationTimestamp,
} from "@/shared/components/investigation";

import { patchVulnFinding } from "./api";
import {
  dispositionVariant,
  findingAssetLabel,
  findingComponentLabel,
  findingDispositionLabel,
  findingExposureLabel,
  findingFixedVersion,
  findingInstalledVersion,
  findingObservationLabel,
  observationVariant,
  sevVariant,
} from "./findingUtils";
import type { VulnFinding, VulnFindingPatchIn } from "./types";

export default function VulnFindingDrawer(props: {
  open: boolean;
  finding: VulnFinding | null;
  onClose: () => void;
  onPatched: (next: VulnFinding) => void;
}) {
  const f = props.finding;
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const title = useMemo(() => {
    if (!f) return "Finding";
    const component = findingComponentLabel(f);
    const prefix = f.cve ? `${f.cve} · ${component}` : component;
    return prefix.length > 120 ? `${prefix.slice(0, 117)}...` : prefix;
  }, [f]);

  async function doPatch(patch: VulnFindingPatchIn) {
    if (!f || busy) return;
    setBusy(true);
    setErr(null);
    try {
      const next = await patchVulnFinding(f.id, patch);
      props.onPatched(next);
    } catch (e: any) {
      setErr(e?.message || "Failed to update");
    } finally {
      setBusy(false);
    }
  }

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    } catch {
    }
  }

  const installedVersion = f ? findingInstalledVersion(f) : null;
  const fixedVersion = f ? findingFixedVersion(f) : null;

  return (
    <Drawer
      open={props.open}
      title={title}
      description={f ? `Finding #${f.id} · ${findingAssetLabel(f)} · Last seen ${formatInvestigationTimestamp(f.last_seen_at)}` : ""}
      onClose={props.onClose}
      widthClassName="w-[920px]"
      headerLabel="Vulnerability"
    >
      {!f ? (
        <div className="text-sm text-muted-foreground">No finding selected.</div>
      ) : (
        <InvestigationShell>
          <InvestigationMetaStrip
            items={[
              { label: "Severity", value: f.severity, variant: sevVariant(f.severity) },
              { label: "Observation", value: findingObservationLabel(f), variant: observationVariant(f.observation_state) },
              { label: "Disposition", value: findingDispositionLabel(f), variant: dispositionVariant(f.operator_disposition) },
              { label: "Asset", value: findingAssetLabel(f) },
              { label: "Confidence", value: `${f.confidence}/100` },
              { label: "Priority", value: Number(f.priority?.score || 0).toFixed(1) },
            ]}
          />

          <div className="flex flex-wrap gap-2">
            <Button
              variant="secondary"
              size="sm"
              disabled={busy}
              onClick={() =>
                doPatch({
                  observation_state: f.observation_state === "awaiting_verification" ? "observed" : "awaiting_verification",
                })
              }
            >
              {f.observation_state === "awaiting_verification" ? "Mark Still Observed" : "Mark Pending Verification"}
            </Button>
            <Button
              variant="subtle"
              size="sm"
              disabled={busy}
              onClick={() =>
                doPatch({
                  operator_disposition: f.operator_disposition === "accepted_risk" ? "open" : "accepted_risk",
                })
              }
            >
              {f.operator_disposition === "accepted_risk" ? "Reopen Review" : "Accept Risk"}
            </Button>
            <Button
              variant={f.operator_disposition === "suppressed" ? "subtle" : "danger"}
              size="sm"
              disabled={busy}
              onClick={() =>
                doPatch({
                  operator_disposition: f.operator_disposition === "suppressed" ? "open" : "suppressed",
                })
              }
            >
              {f.operator_disposition === "suppressed" ? "Unsuppress" : "Suppress"}
            </Button>
            <Button
              variant="subtle"
              size="sm"
              disabled={!f.fingerprint}
              onClick={() => copy(f.fingerprint)}
            >
              {copied ? "Copied" : "Copy Fingerprint"}
            </Button>
          </div>

          <InlineAlert tone="info">
            Accepted and suppressed states record analyst disposition only. A finding moves to{" "}
            <span className="text-foreground">No longer observed</span> when a later scan stops seeing it.
          </InlineAlert>

          {err ? <InlineAlert tone="danger">{err}</InlineAlert> : null}

          <InvestigationSection title="Finding overview" subtitle="Dense component, exposure, observation, and identifier context in one place.">
            <InvestigationSummaryGrid className="xl:grid-cols-4">
              <InvestigationFactCard label="Affected component" value={findingComponentLabel(f)} mono />
              <InvestigationFactCard label="Component kind" value={f.component?.kind || "-"} mono />
              <InvestigationFactCard label="Installed version" value={installedVersion || "-"} mono copyValue={installedVersion || null} />
              <InvestigationFactCard label="Fixed version" value={fixedVersion || "-"} mono copyValue={fixedVersion || null} />
              <InvestigationFactCard label="Package manager" value={f.component?.manager || "-"} mono />
              <InvestigationFactCard label="Ecosystem" value={f.component?.ecosystem || "-"} mono />
              <InvestigationFactCard label="Asset" value={findingAssetLabel(f)} mono copyValue={findingAssetLabel(f)} />
              <InvestigationFactCard label="Exposure basis" value={findingExposureLabel(f)} />
              <InvestigationFactCard label="Externally exposed" value={f.exposure?.externally_exposed ? "yes" : "no"} mono />
              <InvestigationFactCard label="Surface score" value={String(f.exposure?.surface_score ?? 0)} mono />
              <InvestigationFactCard
                label="Exposed ports"
                value={f.exposure?.exposed_ports?.length ? f.exposure.exposed_ports.join(", ") : "-"}
                mono
              />
              <InvestigationFactCard
                label="Service hints"
                value={f.exposure?.service_hints?.length ? f.exposure.service_hints.join(", ") : "-"}
                mono
              />
              <InvestigationFactCard label="Observation" value={findingObservationLabel(f)} />
              <InvestigationFactCard label="Disposition" value={findingDispositionLabel(f)} />
              <InvestigationFactCard label="First seen" value={formatInvestigationTimestamp(f.first_seen_at)} mono />
              <InvestigationFactCard label="Last seen" value={formatInvestigationTimestamp(f.last_seen_at)} mono />
              <InvestigationFactCard label="Repeated observation" value={f.repeated_observation ? "yes" : "no"} mono />
              <InvestigationFactCard label="Total observations" value={String(f.occurrences)} mono />
              <InvestigationFactCard label="CVE" value={f.cve || "-"} mono copyValue={f.cve || null} />
              <InvestigationFactCard label="CWE" value={f.cwe || "-"} mono copyValue={f.cwe || null} />
              <InvestigationFactCard label="CVSS" value={f.cvss || "-"} mono />
              <InvestigationFactCard label="Source" value={f.source} mono />
              <InvestigationFactCard label="External ID" value={f.external_id || "-"} mono copyValue={f.external_id || null} />
              <InvestigationFactCard label="Fingerprint" value={f.fingerprint} mono copyValue={f.fingerprint} />
            </InvestigationSummaryGrid>

            {f.asset_context?.length ? (
              <div className="mt-4">
                <InvestigationChipList
                  title="Asset context"
                  chips={f.asset_context.map((item) => ({ label: item, variant: "neutral" as const }))}
                />
              </div>
            ) : null}

            {f.priority?.factors?.length ? (
              <div className="mt-4">
                <InvestigationChipList
                  title="Priority factors"
                  chips={f.priority.factors.map((factor) => ({ label: factor, variant: "neutral" as const }))}
                />
              </div>
            ) : null}
          </InvestigationSection>

          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            <InvestigationSection title="Why it matters">
              <div className="text-sm leading-6 text-foreground/90">
                {f.risk_summary || f.description || "No additional rationale was provided."}
              </div>
            </InvestigationSection>

            <InvestigationSection title="Remediation guidance">
              <div className="space-y-3">
                <div className="text-sm leading-6 text-foreground/90">
                  {f.remediation_guidance || "No concrete remediation guidance was provided."}
                </div>
                {fixedVersion ? (
                  <InlineAlert tone="success">
                    Fix version available: <span className="font-mono">{fixedVersion}</span>
                  </InlineAlert>
                ) : null}
              </div>
            </InvestigationSection>
          </div>

          {f.description ? (
            <InvestigationSection title="Scanner details">
              <div className="whitespace-pre-wrap text-sm leading-6 text-foreground/90">{f.description}</div>
            </InvestigationSection>
          ) : null}

          <InvestigationSection title="Evidence" subtitle="Backend evidence preserved as structured JSON.">
            <JsonBlock value={f.evidence} showControls={false} />
          </InvestigationSection>
        </InvestigationShell>
      )}
    </Drawer>
  );
}
