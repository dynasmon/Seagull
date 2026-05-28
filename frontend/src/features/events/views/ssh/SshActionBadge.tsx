import { SeverityPill } from "@/shared/components/SeverityPill";
import type { SeverityVariant } from "@/shared/components/SeverityPill";

function variantFor(action?: string | null): SeverityVariant {
  switch ((action ?? "").trim()) {
    case "accepted":
      return "low";
    case "failed_password":
      return "high";
    case "invalid_user":
      return "medium";
    default:
      return "neutral";
  }
}

function labelFor(action?: string | null) {
  switch ((action ?? "").trim()) {
    case "accepted":
      return "accepted";
    case "failed_password":
      return "failed password";
    case "invalid_user":
      return "invalid user";
    default:
      return action || "-";
  }
}

export function SshActionBadge({ action, withDot = true }: { action?: string | null; withDot?: boolean }) {
  return (
    <SeverityPill variant={variantFor(action)} withDot={withDot}>
      {labelFor(action)}
    </SeverityPill>
  );
}
