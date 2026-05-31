import { Badge, type BadgeVariant } from "@/shared/components/Badge";
import {
  ipClassificationTitle,
  resolveIpClassification,
  type IpContextInput,
  type IpDisplayLabel,
} from "@/shared/lib/ipClassification";
import { cx } from "@/shared/lib/cx";

const badgeVariantByLabel: Record<IpDisplayLabel, BadgeVariant> = {
  Public: "info",
  Internal: "low",
  Private: "neutral",
  Loopback: "neutral",
  "Link-local": "neutral",
  CGNAT: "medium",
  "Reserved/Test": "medium",
  Invalid: "critical",
  Unknown: "neutral",
};

export function IpAddressPill({
  ip,
  ipContext,
  compact = false,
  className,
}: {
  ip?: string | null;
  ipContext?: IpContextInput;
  compact?: boolean;
  className?: string;
}) {
  const classification = resolveIpClassification(ip, ipContext);
  const displayIp = classification.ip || "-";

  return (
    <span
      className={cx(
        "inline-flex max-w-full flex-wrap items-center gap-1.5 align-middle",
        compact && "min-w-0 flex-nowrap gap-1",
        className,
      )}
      title={ipClassificationTitle(classification)}
      aria-label={`${displayIp} ${classification.label}`}
      data-ip-scope={classification.scope}
      data-ip-label={classification.label}
    >
      <span
        className={cx(
          "break-all font-mono text-[12px] leading-5 text-foreground",
          compact && "min-w-0 truncate text-[11px] leading-4",
          !classification.ip && "text-muted-foreground",
        )}
      >
        {displayIp}
      </span>
      <Badge
        variant={badgeVariantByLabel[classification.label]}
        className={cx("shrink-0", compact && "px-1.5 py-0 text-[9px] tracking-[0.05em]")}
      >
        {classification.label}
      </Badge>
    </span>
  );
}

export default IpAddressPill;
