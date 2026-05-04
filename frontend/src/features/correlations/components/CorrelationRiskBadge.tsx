import { SeverityPill } from "@/shared/components/SeverityPill";
import { StatusPill } from "@/shared/components/StatusPill";

import type {
  CorrelationConfidence,
  CorrelationLifecycleStatus,
  CorrelationRiskScore,
} from "../types";
import {
  correlationConfidenceVariant,
  correlationRiskVariant,
  correlationStatusVariant,
  formatCorrelationConfidenceLabel,
  formatCorrelationScoreLabel,
} from "./correlationUtils";

export function CorrelationRiskBadge({
  score,
  label = "Risk",
  className,
}: {
  score: CorrelationRiskScore;
  label?: string;
  className?: string;
}) {
  return (
    <SeverityPill variant={correlationRiskVariant(score)} className={className}>
      {formatCorrelationScoreLabel(score, label)}
    </SeverityPill>
  );
}

export function CorrelationConfidenceBadge({
  confidence,
  className,
}: {
  confidence: CorrelationConfidence;
  className?: string;
}) {
  return (
    <SeverityPill variant={correlationConfidenceVariant(confidence)} className={className}>
      {formatCorrelationConfidenceLabel(confidence)}
    </SeverityPill>
  );
}

export function CorrelationStatusBadge({
  status,
  className,
}: {
  status: CorrelationLifecycleStatus | string;
  className?: string;
}) {
  return (
    <StatusPill variant={correlationStatusVariant(status)} className={className}>
      {String(status || "unknown")}
    </StatusPill>
  );
}
