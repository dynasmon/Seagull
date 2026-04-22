import { useMemo, useState, type ReactNode } from "react";

import { Badge } from "@/shared/components/Badge";
import Drawer from "@/shared/components/Drawer";
import { cx } from "@/shared/lib/cx";

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
import { fmtWhen } from "./scanUtils";
import type { VulnFinding, VulnFindingPatchIn } from "./types";

function safeJson(v: any): string {
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}

function ActionButton(props: {
  label: string;
  onClick: () => void;
  disabled?: boolean;
  kind?: "primary" | "danger" | "neutral";
}) {
  const kind = props.kind ?? "neutral";
  const base =
    "inline-flex items-center justify-center rounded-md border border-border/60 bg-background/40 px-3 py-2 text-xs font-mono uppercase tracking-widest";
  const klass =
    kind === "primary"
      ? "text-foreground hover:bg-primary/15 focus:ring-primary/30"
      : kind === "danger"
        ? "text-red-400 hover:bg-red-500/10 focus:ring-red-500/30"
        : "text-muted-foreground hover:bg-muted/15 hover:text-foreground focus:ring-primary/30";

  return (
    <button
      type="button"
      disabled={props.disabled}
      onClick={props.onClick}
      className={cx(base, klass, "focus:outline-none focus:ring-2", props.disabled && "opacity-60")}
    >
      {props.label}
    </button>
  );
}

function Section({
  title,
  children,
  className,
}: {
  title: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={cx("rounded-xl border border-border/60 bg-background/60 p-4 backdrop-blur-md", className)}>
      <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">{title}</div>
      <div className="mt-3">{children}</div>
    </div>
  );
}

function MetaItem({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="mt-1 text-sm text-foreground">{value}</div>
    </div>
  );
}

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
      description={f ? `Finding #${f.id} · ${findingAssetLabel(f)} · Last seen ${fmtWhen(f.last_seen_at)}` : ""}
      onClose={props.onClose}
      widthClassName="w-[880px]"
    >
      {!f ? (
        <div className="text-sm text-muted-foreground">No finding selected.</div>
      ) : (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant={sevVariant(f.severity)}>{f.severity}</Badge>
            <Badge variant={observationVariant(f.observation_state)}>{findingObservationLabel(f)}</Badge>
            {f.operator_disposition !== "open" ? (
              <Badge variant={dispositionVariant(f.operator_disposition)}>{findingDispositionLabel(f)}</Badge>
            ) : null}
            <span className="text-xs text-muted-foreground">confidence {f.confidence}/100</span>
            <span className="text-xs text-muted-foreground">priority {Number(f.priority?.score || 0).toFixed(1)}</span>
          </div>

          <div className="flex flex-wrap gap-2">
            <ActionButton
              label={f.observation_state === "awaiting_verification" ? "Mark Still Observed" : "Mark Pending Verification"}
              kind="primary"
              disabled={busy}
              onClick={() =>
                doPatch({
                  observation_state: f.observation_state === "awaiting_verification" ? "observed" : "awaiting_verification",
                })
              }
            />
            <ActionButton
              label={f.operator_disposition === "accepted_risk" ? "Reopen Review" : "Accept Risk"}
              disabled={busy}
              onClick={() =>
                doPatch({
                  operator_disposition: f.operator_disposition === "accepted_risk" ? "open" : "accepted_risk",
                })
              }
            />
            <ActionButton
              label={f.operator_disposition === "suppressed" ? "Unsuppress" : "Suppress"}
              kind={f.operator_disposition === "suppressed" ? "neutral" : "danger"}
              disabled={busy}
              onClick={() =>
                doPatch({
                  operator_disposition: f.operator_disposition === "suppressed" ? "open" : "suppressed",
                })
              }
            />
            <ActionButton
              label={copied ? "Copied" : "Copy Fingerprint"}
              disabled={!f.fingerprint}
              onClick={() => copy(f.fingerprint)}
            />
          </div>

          <div className="rounded-lg border border-border/60 bg-muted/20 px-3 py-2 text-sm text-muted-foreground">
            Accepted and suppressed states record analyst disposition only. A finding moves to{" "}
            <span className="text-foreground">No longer observed</span> when a later scan stops seeing it.
          </div>

          {err ? (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-200">
              {err}
            </div>
          ) : null}

          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            <Section title="Why It Matters">
              <div className="space-y-3">
                <div className="text-sm leading-6 text-foreground/90">
                  {f.risk_summary || f.description || "No additional rationale was provided."}
                </div>
                {f.priority?.factors?.length ? (
                  <div className="flex flex-wrap gap-2">
                    {f.priority.factors.map((factor) => (
                      <span
                        key={factor}
                        className="inline-flex items-center rounded-md border border-border/60 bg-background/30 px-2 py-1 text-[11px] font-mono text-muted-foreground"
                      >
                        {factor}
                      </span>
                    ))}
                  </div>
                ) : null}
              </div>
            </Section>

            <Section title="Component">
              <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                <MetaItem label="Affected component" value={<span className="font-mono text-[12px]">{findingComponentLabel(f)}</span>} />
                <MetaItem label="Kind" value={<span className="font-mono text-[12px]">{f.component?.kind || "-"}</span>} />
                <MetaItem label="Installed version" value={<span className="font-mono text-[12px]">{installedVersion || "-"}</span>} />
                <MetaItem label="Fixed version" value={<span className="font-mono text-[12px]">{fixedVersion || "-"}</span>} />
                <MetaItem label="Package manager" value={<span className="font-mono text-[12px]">{f.component?.manager || "-"}</span>} />
                <MetaItem label="Ecosystem" value={<span className="font-mono text-[12px]">{f.component?.ecosystem || "-"}</span>} />
              </div>
            </Section>
          </div>

          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            <Section title="Exposure And Asset">
              <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                <MetaItem label="Asset" value={<span className="font-mono text-[12px] break-all">{findingAssetLabel(f)}</span>} />
                <MetaItem label="Exposure basis" value={<span className="text-sm">{findingExposureLabel(f)}</span>} />
                <MetaItem label="Externally exposed" value={<span className="font-mono text-[12px]">{f.exposure?.externally_exposed ? "yes" : "no"}</span>} />
                <MetaItem label="Surface score" value={<span className="font-mono text-[12px]">{f.exposure?.surface_score ?? 0}</span>} />
                <MetaItem
                  label="Exposed ports"
                  value={<span className="font-mono text-[12px]">{f.exposure?.exposed_ports?.length ? f.exposure.exposed_ports.join(", ") : "-"}</span>}
                />
                <MetaItem
                  label="Service hints"
                  value={<span className="font-mono text-[12px]">{f.exposure?.service_hints?.length ? f.exposure.service_hints.join(", ") : "-"}</span>}
                />
              </div>
              {f.asset_context?.length ? (
                <div className="mt-3 flex flex-wrap gap-2">
                  {f.asset_context.map((item) => (
                    <span
                      key={item}
                      className="inline-flex items-center rounded-md border border-border/60 bg-background/30 px-2 py-0.5 text-[11px] font-mono text-muted-foreground"
                    >
                      {item}
                    </span>
                  ))}
                </div>
              ) : null}
            </Section>

            <Section title="Observation State">
              <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                <MetaItem label="Observation" value={<span className="text-sm">{findingObservationLabel(f)}</span>} />
                <MetaItem label="Disposition" value={<span className="text-sm">{findingDispositionLabel(f)}</span>} />
                <MetaItem label="First seen" value={<span className="font-mono text-[12px]">{fmtWhen(f.first_seen_at)}</span>} />
                <MetaItem label="Last seen" value={<span className="font-mono text-[12px]">{fmtWhen(f.last_seen_at)}</span>} />
                <MetaItem label="Repeated observation" value={<span className="font-mono text-[12px]">{f.repeated_observation ? "yes" : "no"}</span>} />
                <MetaItem label="Total observations" value={<span className="font-mono text-[12px]">{f.occurrences}</span>} />
              </div>
            </Section>
          </div>

          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            <Section title="Remediation Guidance">
              <div className="space-y-3">
                <div className="text-sm leading-6 text-foreground/90">
                  {f.remediation_guidance || "No concrete remediation guidance was provided."}
                </div>
                {fixedVersion ? (
                  <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 px-3 py-2 text-sm text-emerald-200">
                    Fix version available: <span className="font-mono">{fixedVersion}</span>
                  </div>
                ) : null}
              </div>
            </Section>

            <Section title="Identifiers">
              <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                <MetaItem label="CVE" value={<span className="font-mono text-[12px] break-all">{f.cve || "-"}</span>} />
                <MetaItem label="CWE" value={<span className="font-mono text-[12px] break-all">{f.cwe || "-"}</span>} />
                <MetaItem label="CVSS" value={<span className="font-mono text-[12px] break-all">{f.cvss || "-"}</span>} />
                <MetaItem label="Source" value={<span className="font-mono text-[12px] break-all">{f.source}</span>} />
                <MetaItem label="External id" value={<span className="font-mono text-[12px] break-all">{f.external_id || "-"}</span>} />
                <MetaItem label="Fingerprint" value={<span className="font-mono text-[12px] break-all">{f.fingerprint}</span>} />
              </div>
            </Section>
          </div>

          {f.description ? (
            <Section title="Scanner Details">
              <div className="whitespace-pre-wrap text-sm leading-6 text-foreground/90">{f.description}</div>
            </Section>
          ) : null}

          <Section title="Evidence">
            <pre className="whitespace-pre-wrap break-words text-xs text-muted-foreground">{safeJson(f.evidence)}</pre>
          </Section>
        </div>
      )}
    </Drawer>
  );
}
