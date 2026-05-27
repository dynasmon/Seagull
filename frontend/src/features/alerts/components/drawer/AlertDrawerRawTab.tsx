import { InvestigationRawJsonPanel } from "@/shared/components/investigation";

import { safeJson } from "../../lib/alertFormatters";
import type { Alert } from "../../types";

export function AlertDrawerRawTab({ selected, initialWrap }: { selected: Alert; initialWrap: boolean }) {
  const json = safeJson({
    id: selected.id,
    severity: selected.severity,
    rule_id: selected.rule_id,
    src_ip: selected.src_ip,
    dst_ip: selected.dst_ip,
    dst_port: selected.dst_port,
    confidence: selected.confidence,
    mitre_tactic: selected.mitre_tactic,
    mitre_technique_id: selected.mitre_technique_id,
    mitre_technique: selected.mitre_technique,
    created_at: selected.created_at,
    description: selected.description,
    details: selected.details,
  });

  return <InvestigationRawJsonPanel value={json} title="Raw alert payload" initialWrap={initialWrap} />;
}
