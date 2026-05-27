import { Badge } from "@/shared/components/Badge";
import { IpAddressPill } from "@/shared/components/IpAddressPill";
import {
  InvestigationFactCard,
  InvestigationSection,
  InvestigationSummaryGrid,
} from "@/shared/components/investigation";

import { alertIpContext } from "../../lib/alertPresenters";
import { sevVariant } from "../../lib/alertSeverity";
import type { Alert } from "../../types";

export function AlertDrawerSummaryTab({ selected }: { selected: Alert }) {
  return (
    <InvestigationSection title="Alert summary" subtitle="Highest-value triage facts first.">
      <InvestigationSummaryGrid>
        <InvestigationFactCard label="Rule ID" value={selected.rule_id} mono />
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
    </InvestigationSection>
  );
}
