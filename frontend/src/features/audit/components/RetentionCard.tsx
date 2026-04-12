import { Card } from "@/shared/components/Card";
import { Badge } from "@/shared/components/Badge";

function present(value: unknown): string {
  if (value === null || value === undefined || value === "") return "-";
  if (typeof value === "boolean") return value ? "yes" : "no";
  return String(value);
}

type RuntimeFact = {
  label: string;
  value: string;
  variant?: "critical" | "high" | "medium" | "low" | "info" | "neutral";
};

export default function RetentionCard({
  loading,
  error,
  security,
}: {
  loading: boolean;
  error: string | null;
  security: Record<string, any>;
}) {
  const runtimeFacts: RuntimeFact[] = [
    { label: "Enabled", value: security.audit_retention_enabled ? "yes" : "no", variant: security.audit_retention_enabled ? "low" : "critical" },
    { label: "Audit events", value: `${present(security.audit_retention_days)}d` },
    { label: "Login evidence", value: `${present(security.login_audit_retention_days)}d` },
    { label: "Governance history", value: `${present(security.governance_retention_days)}d` },
    { label: "Session idle timeout", value: security.session_idle_timeout_minutes ? `${security.session_idle_timeout_minutes}m` : "-" },
    { label: "Password min length", value: present(security.password_min_length) },
    { label: "MFA required", value: present(security.require_mfa), variant: security.require_mfa ? "low" : "neutral" },
  ];

  return (
    <Card title="Evidence Retention & Runtime Controls" right="/api/admin/runtime-config">
      {error ? <div className="text-sm text-red-400">{error}</div> : null}
      {loading ? (
        <div className="text-sm text-muted-foreground">Loading retention policy...</div>
      ) : (
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3 text-sm lg:grid-cols-4 xl:grid-cols-7">
            {runtimeFacts.map((fact) => (
              <div key={fact.label} className="rounded-md border border-border/60 bg-background/30 px-3 py-2">
                <div className="text-[11px] text-muted-foreground">{fact.label}</div>
                <div className="mt-1 flex items-center gap-2">
                  <div className="text-base font-semibold font-mono">{fact.value}</div>
                  {fact.variant ? <Badge variant={fact.variant}>{fact.value}</Badge> : null}
                </div>
              </div>
            ))}
          </div>

          <div className="rounded-md border border-border/60 bg-muted/25 px-3 py-2 text-xs text-muted-foreground">
            Retention TTL policy is enforced server-side. Records can leave UI visibility once purge windows are reached.
            Redacted evidence remains masked and is never reconstructed in the frontend.
          </div>
        </div>
      )}
    </Card>
  );
}
