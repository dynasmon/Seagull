import AgentTag from "@/features/agents/components/AgentTag";
import { Badge } from "@/shared/components/Badge";
import { IpAddressPill } from "@/shared/components/IpAddressPill";
import {
  InvestigationFactCard,
  InvestigationSection,
  InvestigationSummaryGrid,
} from "@/shared/components/investigation";

import { alertIpContext, formatScoreDelta, riskBreakdown } from "../../lib/alertPresenters";
import { sevVariant } from "../../lib/alertSeverity";
import type { Alert } from "../../types";

export function AlertDrawerSummaryTab({ selected }: { selected: Alert }) {
  const breakdown = riskBreakdown(selected);
  return (
    <InvestigationSection title="Alert summary" subtitle="Highest-value triage facts first.">
      <InvestigationSummaryGrid>
        <InvestigationFactCard label="Rule ID" value={selected.rule_id} mono />
        <InvestigationFactCard
          label="Agent"
          value={<AgentTag agentId={selected.agent_id ?? (selected.details?.agent_id as string | undefined)} />}
          copyValue={selected.agent_id ?? undefined}
        />
        <InvestigationFactCard
          label="Severity"
          value={
            <Badge variant={sevVariant(String(selected.severity || "unknown"))}>
              {String(selected.severity || "unknown")}
            </Badge>
          }
        />
        <InvestigationFactCard
          label="Confidence"
          value={typeof selected.confidence === "number" ? String(selected.confidence) : "-"}
          mono
        />
        <InvestigationFactCard
          label="Risk score"
          value={typeof selected.risk_score === "number" ? String(selected.risk_score) : "-"}
          mono
        />
        <InvestigationFactCard
          label="Source IP"
          value={<IpAddressPill ip={selected.src_ip} ipContext={alertIpContext(selected, "src")} compact />}
        />
        <InvestigationFactCard
          label="Destination"
          value={
            <span className="inline-flex max-w-full flex-wrap items-center gap-0.5">
              <IpAddressPill ip={selected.dst_ip} ipContext={alertIpContext(selected, "dst")} compact />
              {typeof selected.dst_port === "number" ? (
                <span className="text-muted-foreground">:{selected.dst_port}</span>
              ) : null}
            </span>
          }
        />
        <InvestigationFactCard
          label="ATT&CK"
          value={
            selected.mitre_technique || selected.mitre_technique_id || selected.mitre_tactic
              ? `${selected.mitre_tactic || "-"}${selected.mitre_technique_id ? ` · ${selected.mitre_technique_id}` : ""}${selected.mitre_technique ? ` · ${selected.mitre_technique}` : ""}`
              : "-"
          }
          mono
        />
      </InvestigationSummaryGrid>
      <div className="mt-4 rounded-lg border border-border/60 bg-background/35 px-3 py-2">
        <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Description</div>
        <div className="mt-1 text-sm leading-relaxed">{selected.description || "No description."}</div>
      </div>
      {breakdown.length > 0 ? (
        <div className="mt-4 rounded-lg border border-border/60 bg-background/35 px-3 py-2">
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
            Why this fired
          </div>
          <ul className="mt-2 space-y-1">
            {breakdown.map((factor, index) => (
              <li key={`${factor.factor}-${index}`} className="flex items-baseline gap-2 text-sm">
                <span
                  className={`min-w-[2.75rem] text-right font-mono text-xs ${
                    factor.factor === "base" || factor.riskDelta === 0
                      ? "text-muted-foreground"
                      : factor.riskDelta > 0
                        ? "text-rose-400"
                        : "text-emerald-400"
                  }`}
                >
                  {formatScoreDelta(factor)}
                </span>
                <span className="leading-snug">{factor.detail}</span>
              </li>
            ))}
          </ul>
          <div className="mt-2 text-[10px] text-muted-foreground">
            Final risk {typeof selected.risk_score === "number" ? selected.risk_score : "-"} · confidence{" "}
            {typeof selected.confidence === "number" ? selected.confidence : "-"}
          </div>
        </div>
      ) : null}
    </InvestigationSection>
  );
}
