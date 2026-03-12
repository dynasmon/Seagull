import { Card } from "@/shared/components/Card";

export default function RetentionCard({
  loading,
  error,
  security,
}: {
  loading: boolean;
  error: string | null;
  security: Record<string, any>;
}) {
  return (
    <Card title="Evidence Retention" right="runtime policy">
      {error ? <div className="text-sm text-red-400">{error}</div> : null}
      {loading ? (
        <div className="text-sm text-muted-foreground">Loading retention policy...</div>
      ) : (
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-3 text-sm">
          <div className="rounded-md border border-border/60 bg-background/30 px-3 py-2">
            <div className="text-xs text-muted-foreground">Enabled</div>
            <div className="text-lg font-semibold">{security.audit_retention_enabled ? "yes" : "no"}</div>
          </div>
          <div className="rounded-md border border-border/60 bg-background/30 px-3 py-2">
            <div className="text-xs text-muted-foreground">Audit events</div>
            <div className="text-lg font-semibold">{security.audit_retention_days ?? "-"}d</div>
          </div>
          <div className="rounded-md border border-border/60 bg-background/30 px-3 py-2">
            <div className="text-xs text-muted-foreground">Login evidence</div>
            <div className="text-lg font-semibold">{security.login_audit_retention_days ?? "-"}d</div>
          </div>
          <div className="rounded-md border border-border/60 bg-background/30 px-3 py-2">
            <div className="text-xs text-muted-foreground">Governance history</div>
            <div className="text-lg font-semibold">{security.governance_retention_days ?? "-"}d</div>
          </div>
          <div className="rounded-md border border-border/60 bg-background/30 px-3 py-2">
            <div className="text-xs text-muted-foreground">Window note</div>
            <div className="text-xs text-muted-foreground">
              Records may leave visibility window after TTL purge policy.
            </div>
          </div>
        </div>
      )}
    </Card>
  );
}
