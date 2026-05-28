import { Badge } from "@/shared/components/Badge";
import type { BadgeVariant } from "@/shared/components/Badge";

type GeoFields = {
  geo_country?: string | null;
  geo_org?: string | null;
  asn?: string | null;
  asn_org?: string | null;
};

export function SshGeoCell({
  row,
  fallbackLabel,
  countryVariant = "info",
}: {
  row: GeoFields;
  fallbackLabel: string;
  countryVariant?: BadgeVariant;
}) {
  const country = (row.geo_country ?? "").trim();
  const org = (row.geo_org ?? "").trim();
  const asn = (row.asn ?? "").trim();
  const asnOrg = (row.asn_org ?? "").trim();

  return (
    <div className="min-w-0">
      <div className="flex items-center gap-2">
        {country ? (
          <Badge variant={countryVariant}>{country}</Badge>
        ) : (
          <Badge variant="neutral">{fallbackLabel}</Badge>
        )}
      </div>
      <div className="mt-1 truncate text-[11px] text-muted-foreground">{org || "-"}</div>
      <div className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground">
        {asn ? `${asn}${asnOrg ? ` • ${asnOrg}` : ""}` : "-"}
      </div>
    </div>
  );
}
