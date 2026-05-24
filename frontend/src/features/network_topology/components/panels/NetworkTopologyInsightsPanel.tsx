import type { ReactNode } from "react";

import type { BadgeVariant } from "@/shared/components/Badge";
import { Badge } from "@/shared/components/Badge";
import { Panel } from "@/shared/components/Panel";
import { cx } from "@/shared/lib/cx";

import { formatTopologyTimestamp } from "../../lib/presentation/labels";
import type { TopologyInsight, TopologyInsightSeverity, TopologyVisibility } from "../../types";

const SEVERITY_DOT: Record<TopologyInsightSeverity, string> = {
  critical: "bg-[hsl(var(--color-danger))]",
  high: "bg-[hsl(var(--color-danger)/0.7)]",
  medium: "bg-[hsl(var(--color-warning))]",
  low: "bg-[hsl(var(--color-warning)/0.5)]",
  info: "bg-[hsl(var(--color-info)/0.6)]",
  ok: "bg-[hsl(var(--color-success)/0.7)]",
};

const SEVERITY_BADGE_VARIANT: Record<TopologyInsightSeverity, BadgeVariant> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
  ok: "neutral",
};

function InsightCard({ insight }: { insight: TopologyInsight }) {
  return (
    <div className="flex items-start gap-3 rounded-lg border border-border/60 bg-background/35 px-4 py-3">
      <span
        className={cx("mt-1.5 h-2 w-2 shrink-0 rounded-full", SEVERITY_DOT[insight.severity] ?? "bg-muted")}
        aria-hidden="true"
      />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-medium text-foreground">{insight.title}</span>
          {insight.severity !== "ok" && insight.severity !== "info" && (
            <Badge variant={SEVERITY_BADGE_VARIANT[insight.severity]}>
              {insight.severity}
            </Badge>
          )}
        </div>
        <p className="mt-0.5 text-xs text-muted-foreground">{insight.detail}</p>
      </div>
      {insight.count != null && insight.count > 0 && (
        <span className="shrink-0 rounded-md border border-border/60 bg-background/40 px-2 py-0.5 font-mono text-xs text-muted-foreground">
          {new Intl.NumberFormat().format(insight.count)}
        </span>
      )}
    </div>
  );
}

function GroupSection({
  title,
  subtitle,
  children,
  empty,
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
  empty?: ReactNode;
}) {
  return (
    <div>
      <div className="mb-2 flex items-baseline gap-2">
        <span className="text-[11px] font-semibold uppercase tracking-[0.1em] text-muted-foreground">{title}</span>
        {subtitle ? <span className="text-[11px] text-muted-foreground/60">{subtitle}</span> : null}
      </div>
      <div className="space-y-2">{children ?? empty}</div>
    </div>
  );
}

function DataSourcePill({ label, active, detail }: { label: string; active: boolean; detail?: string }) {
  return (
    <span
      title={detail}
      className={cx(
        "inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs",
        active
          ? "border-success/40 bg-success/10 text-success"
          : "border-border/50 bg-background/30 text-muted-foreground/50",
      )}
    >
      <span className={cx("h-1.5 w-1.5 rounded-full", active ? "bg-success" : "bg-muted-foreground/30")} />
      {label}
    </span>
  );
}

function IpScopeGlossary() {
  const entries: Array<{ label: string; description: string; tone: string }> = [
    { label: "Internal observed", description: "Private or internal addresses seen in traffic or inventory", tone: "text-info" },
    { label: "Private address", description: "RFC 1918 space (10.x, 172.16–31.x, 192.168.x)", tone: "text-info" },
    { label: "Public internet", description: "Globally routable IPs; always treated as external", tone: "text-warning" },
    { label: "Loopback", description: "127.x or ::1; traffic stays on the local host", tone: "text-muted-foreground" },
    { label: "Link-local", description: "169.254.x or fe80::/10; not routed beyond the local segment", tone: "text-muted-foreground" },
    { label: "Docker/container", description: "172.17.x default bridge range; may only reflect container-local context", tone: "text-muted-foreground" },
    { label: "Unknown", description: "Could not be classified; inspect the raw IP in node details", tone: "text-muted-foreground/60" },
  ];

  return (
    <div className="rounded-lg border border-border/50 bg-background/25 p-4">
      <div className="mb-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-muted-foreground">IP Address Types</div>
      <div className="grid gap-1.5 sm:grid-cols-2">
        {entries.map((e) => (
          <div key={e.label} className="flex items-start gap-2">
            <span className={cx("mt-0.5 shrink-0 text-xs font-semibold", e.tone)}>{e.label}</span>
            <span className="text-xs text-muted-foreground">{e.description}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function NetworkTopologyInsightsPanel({
  insights,
  visibility,
  loading,
}: {
  insights: TopologyInsight[];
  visibility: TopologyVisibility | null;
  loading?: boolean;
}) {
  const attentionItems = insights.filter((i) => i.group === "needs_attention");
  const normalItems = insights.filter((i) => i.group === "normal_activity");
  const gapItems = insights.filter((i) => i.group === "visibility_gaps");

  const lastInventory = visibility?.last_inventory_at
    ? formatTopologyTimestamp(visibility.last_inventory_at)
    : null;
  const lastEvent = visibility?.last_event_at
    ? formatTopologyTimestamp(visibility.last_event_at)
    : null;
  const lastAlert = visibility?.last_alert_at
    ? formatTopologyTimestamp(visibility.last_alert_at)
    : null;

  return (
    <Panel
      title="Network Situation"
      subtitle="What is happening on this network right now."
    >
      {loading ? (
        <div className="space-y-2">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-14 animate-pulse rounded-lg bg-muted/40" />
          ))}
        </div>
      ) : (
        <div className="space-y-6">
          {attentionItems.length > 0 && (
            <GroupSection
              title="Needs Attention"
              subtitle={`${attentionItems.length} item${attentionItems.length !== 1 ? "s" : ""}`}
            >
              {attentionItems.map((item) => (
                <InsightCard key={item.id} insight={item} />
              ))}
            </GroupSection>
          )}

          {normalItems.length > 0 && (
            <GroupSection title="Normal Activity">
              {normalItems.map((item) => (
                <InsightCard key={item.id} insight={item} />
              ))}
            </GroupSection>
          )}

          {gapItems.length > 0 && (
            <GroupSection
              title="Visibility Gaps"
              subtitle="What this topology map cannot see"
            >
              {gapItems.map((item) => (
                <InsightCard key={item.id} insight={item} />
              ))}
              {(visibility?.known_limitations?.length ?? 0) > 0 && (
                <div className="rounded-lg border border-border/40 bg-background/20 px-4 py-3">
                  <div className="mb-2 text-[10px] font-semibold uppercase tracking-[0.1em] text-muted-foreground/70">
                    Known limitations
                  </div>
                  <ul className="space-y-1.5">
                    {visibility!.known_limitations.map((limitation, i) => (
                      <li key={i} className="flex items-start gap-2 text-xs text-muted-foreground">
                        <span className="mt-1 h-1 w-1 shrink-0 rounded-full bg-muted-foreground/40" />
                        {limitation}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </GroupSection>
          )}

          <div>
            <div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.1em] text-muted-foreground">
              Data Sources
            </div>
            <div className="flex flex-wrap gap-2">
              <DataSourcePill
                label="Agent Inventory"
                active={visibility?.inventory_coverage != null && visibility.inventory_coverage > 0}
                detail={lastInventory ? `Last seen: ${lastInventory}` : "No inventory data"}
              />
              <DataSourcePill
                label="Network Flows"
                active={visibility?.flow_coverage ?? false}
                detail={lastEvent ? `Last event: ${lastEvent}` : "No flow data"}
              />
              <DataSourcePill
                label="Alerts"
                active={visibility?.alert_coverage ?? false}
                detail={lastAlert ? `Last alert edge: ${lastAlert}` : "No alert coverage"}
              />
              <DataSourcePill
                label="App Protocols"
                active={visibility?.protocol_coverage ?? false}
                detail="Application-layer protocol identification from flow data"
              />
              <DataSourcePill
                label="Exposure"
                active={visibility?.exposure_coverage ?? false}
                detail="Exposure findings linked to topology nodes"
              />
            </div>
            {visibility && (
              <div className="mt-2 text-[11px] text-muted-foreground/60">
                Inventory coverage:{" "}
                <span className="font-semibold text-muted-foreground">
                  {Math.round(visibility.inventory_coverage * 100)}%
                </span>{" "}
                of agents reported host inventory.
              </div>
            )}
          </div>

          <IpScopeGlossary />
        </div>
      )}
    </Panel>
  );
}
