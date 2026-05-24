import { useMemo, useState } from "react";

import { Panel } from "@/shared/components/Panel";
import { cx } from "@/shared/lib/cx";

import { formatTopologyTimestamp } from "../../lib/presentation/labels";
import {
  CATEGORY_ORDER,
  SERVICE_CATEGORY_META,
  fmtFlows,
  resolveServiceInfo,
} from "../../lib/details/services";
import type { TopologyGraph, TopologyNode } from "../../types";

// ─── Category SVG icons (14 × 14, drawn at center 7,7) ───────────────────────

function WebIcon({ color }: { color: string }) {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden>
      <circle cx="7" cy="7" r="5.5" stroke={color} strokeWidth="1.2" />
      <ellipse cx="7" cy="7" rx="2.4" ry="5.5" stroke={color} strokeWidth="1" />
      <line x1="1.5" y1="5" x2="12.5" y2="5" stroke={color} strokeWidth="0.9" />
      <line x1="1.5" y1="9" x2="12.5" y2="9" stroke={color} strokeWidth="0.9" />
    </svg>
  );
}

function DatabaseIcon({ color }: { color: string }) {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden>
      <ellipse cx="7" cy="3.5" rx="4.5" ry="1.8" stroke={color} strokeWidth="1.2" />
      <path d="M2.5 3.5 v7 Q2.5 13 7 13 Q11.5 13 11.5 10.5 V3.5" stroke={color} strokeWidth="1.2" />
      <path d="M2.5 7 Q2.5 8.8 7 8.8 Q11.5 8.8 11.5 7" stroke={color} strokeWidth="1" />
    </svg>
  );
}

function RemoteIcon({ color }: { color: string }) {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden>
      <rect x="1.5" y="2" width="11" height="7.5" rx="1.5" stroke={color} strokeWidth="1.2" />
      <line x1="5" y1="12" x2="9" y2="12" stroke={color} strokeWidth="1.2" />
      <line x1="7" y1="9.5" x2="7" y2="12" stroke={color} strokeWidth="1.2" />
      <line x1="3.5" y1="5.5" x2="5.5" y2="5.5" stroke={color} strokeWidth="1" />
      <line x1="3.5" y1="7" x2="4.5" y2="7" stroke={color} strokeWidth="1" />
    </svg>
  );
}

function InfraIcon({ color }: { color: string }) {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden>
      <circle cx="7" cy="7" r="2.2" stroke={color} strokeWidth="1.2" />
      <circle cx="7" cy="7" r="5.5" stroke={color} strokeWidth="1" strokeDasharray="2.5 1.8" />
    </svg>
  );
}

function MailIcon({ color }: { color: string }) {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden>
      <rect x="1.5" y="3.5" width="11" height="7.5" rx="1.2" stroke={color} strokeWidth="1.2" />
      <path d="M1.5 4.5 L7 8.5 L12.5 4.5" stroke={color} strokeWidth="1.1" />
    </svg>
  );
}

function FileIcon({ color }: { color: string }) {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden>
      <path d="M3 2 h5 l3 3 v8 H3 z" stroke={color} strokeWidth="1.2" strokeLinejoin="round" />
      <path d="M8 2 v3 h3" stroke={color} strokeWidth="1.1" />
      <line x1="5" y1="7.5" x2="9" y2="7.5" stroke={color} strokeWidth="1" />
      <line x1="5" y1="9.5" x2="8" y2="9.5" stroke={color} strokeWidth="1" />
    </svg>
  );
}

function MonitorIcon({ color }: { color: string }) {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden>
      <polyline points="1.5,9 4,5.5 6.5,7.5 9,3.5 12.5,7" stroke={color} strokeWidth="1.2" strokeLinejoin="round" />
      <circle cx="9" cy="3.5" r="1.2" fill={color} />
    </svg>
  );
}

function ShieldIcon({ color }: { color: string }) {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden>
      <path d="M7 1.5 L12 3.5 V7.5 Q12 11 7 12.5 Q2 11 2 7.5 V3.5 Z" stroke={color} strokeWidth="1.2" strokeLinejoin="round" />
      <path d="M4.5 7 L6.5 9 L9.5 5.5" stroke={color} strokeWidth="1.2" strokeLinecap="round" />
    </svg>
  );
}

function MsgIcon({ color }: { color: string }) {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden>
      <path d="M1.5 2.5 h11 a1 1 0 0 1 1 1 v6 a1 1 0 0 1-1 1 H4.5 L1.5 12.5 V3.5 a1 1 0 0 1 1-1 Z" stroke={color} strokeWidth="1.2" strokeLinejoin="round" />
    </svg>
  );
}

function ContainerIcon2({ color }: { color: string }) {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden>
      <rect x="2" y="3" width="10" height="8" rx="1.5" stroke={color} strokeWidth="1.2" />
      <line x1="5" y1="3" x2="5" y2="11" stroke={color} strokeWidth="1" />
      <line x1="9" y1="3" x2="9" y2="11" stroke={color} strokeWidth="1" />
      <line x1="2" y1="7" x2="12" y2="7" stroke={color} strokeWidth="1" />
    </svg>
  );
}

function OtherIcon({ color }: { color: string }) {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden>
      <rect x="2" y="4" width="10" height="3.5" rx="1" stroke={color} strokeWidth="1.2" />
      <rect x="2" y="9" width="10" height="2.5" rx="1" stroke={color} strokeWidth="1.1" />
      <circle cx="10.5" cy="5.75" r="1" fill={color} />
      <circle cx="10.5" cy="10.25" r="0.85" fill={color} opacity="0.6" />
    </svg>
  );
}

function CategoryIcon({ category, color }: { category: string; color: string }) {
  switch (category) {
    case "web":            return <WebIcon color={color} />;
    case "database":       return <DatabaseIcon color={color} />;
    case "remote":         return <RemoteIcon color={color} />;
    case "infrastructure": return <InfraIcon color={color} />;
    case "mail":           return <MailIcon color={color} />;
    case "file":           return <FileIcon color={color} />;
    case "monitoring":     return <MonitorIcon color={color} />;
    case "security":       return <ShieldIcon color={color} />;
    case "messaging":      return <MsgIcon color={color} />;
    case "container":      return <ContainerIcon2 color={color} />;
    default:               return <OtherIcon color={color} />;
  }
}

// ─── Data extraction helpers ──────────────────────────────────────────────────

type HostGroup = {
  hostIp: string;
  hostLabel: string;
  host: TopologyNode | null;
  services: TopologyNode[];
  totalFlows: number;
  totalAlerts: number;
};

type CategoryGroup = {
  category: string;
  services: TopologyNode[];
  totalFlows: number;
};

function buildHostGroups(graph: TopologyGraph): HostGroup[] {
  const serviceNodes = graph.nodes.filter((n) => n.node_type === "service");
  if (serviceNodes.length === 0) return [];

  const nodeMap = new Map(graph.nodes.map((n) => [n.node_key, n]));

  // Prefer inventory host nodes (have agent_id + hostname label)
  const bestHostByIp = new Map<string, TopologyNode>();
  for (const n of graph.nodes) {
    if ((n.node_type === "host" || n.node_type === "interface") && n.ip) {
      const existing = bestHostByIp.get(n.ip);
      if (!existing || (n.agent_id && !existing.agent_id)) {
        bestHostByIp.set(n.ip, n);
      }
    }
  }

  const hostForService = new Map<string, TopologyNode | null>();
  for (const edge of graph.edges) {
    if (edge.edge_type === "listens_on") {
      const src = nodeMap.get(edge.source_node_key);
      const best = src?.ip ? (bestHostByIp.get(src.ip) ?? src) : (src ?? null);
      hostForService.set(edge.target_node_key, best);
    }
  }

  const byIp = new Map<string, HostGroup>();
  for (const svc of serviceNodes) {
    const host = hostForService.get(svc.node_key) ?? null;
    const ip = host?.ip ?? (svc.metadata?.dst_ip as string | undefined) ?? svc.ip ?? "__unknown__";
    const existing = byIp.get(ip);
    if (!existing) {
      byIp.set(ip, {
        hostIp: ip,
        hostLabel: host?.label ?? ip,
        host,
        services: [svc],
        totalFlows: Number(svc.event_count || 0),
        totalAlerts: Number(svc.alert_count || 0),
      });
    } else {
      if (host && (!existing.host || (host.agent_id && !existing.host.agent_id))) {
        existing.host = host;
        existing.hostLabel = host.label ?? ip;
      }
      existing.services.push(svc);
      existing.totalFlows += Number(svc.event_count || 0);
      existing.totalAlerts += Number(svc.alert_count || 0);
    }
  }

  return [...byIp.values()]
    .sort((a, b) => {
      if (a.totalAlerts !== b.totalAlerts) return b.totalAlerts - a.totalAlerts;
      return b.totalFlows - a.totalFlows;
    })
    .map((g) => ({
      ...g,
      services: [...g.services].sort(
        (a, b) => Number(b.event_count || 0) - Number(a.event_count || 0),
      ),
    }));
}

function buildCategoryGroups(graph: TopologyGraph): CategoryGroup[] {
  const serviceNodes = graph.nodes.filter((n) => n.node_type === "service");
  const byCategory = new Map<string, TopologyNode[]>();

  for (const svc of serviceNodes) {
    const info = resolveServiceInfo(svc.port, svc.protocol, svc.metadata);
    const cat = info.category;
    const bucket = byCategory.get(cat) ?? [];
    bucket.push(svc);
    byCategory.set(cat, bucket);
  }

  return CATEGORY_ORDER.filter((cat) => byCategory.has(cat)).map((cat) => ({
    category: cat,
    services: [...(byCategory.get(cat) ?? [])].sort(
      (a, b) => Number(b.event_count || 0) - Number(a.event_count || 0),
    ),
    totalFlows: (byCategory.get(cat) ?? []).reduce(
      (s, n) => s + Number(n.event_count || 0),
      0,
    ),
  }));
}

// ─── Sub-components ───────────────────────────────────────────────────────────

const ROWS_COLLAPSED = 5;

function FlowBar({
  flows,
  maxFlows,
  color,
}: {
  flows: number;
  maxFlows: number;
  color: string;
}) {
  const pct = maxFlows > 0 ? Math.min(100, (flows / maxFlows) * 100) : 0;
  return (
    <div className="h-1.5 w-20 shrink-0 overflow-hidden rounded-full bg-border/30">
      <div
        className="h-full rounded-full transition-[width] duration-300"
        style={{ width: `${pct}%`, backgroundColor: color, opacity: 0.7 }}
      />
    </div>
  );
}

function ServiceRow({
  node,
  maxFlows,
  onSelect,
  isSelected,
}: {
  node: TopologyNode;
  maxFlows: number;
  onSelect: (node: TopologyNode) => void;
  isSelected: boolean;
}) {
  const info = resolveServiceInfo(node.port, node.protocol, node.metadata);
  const meta = SERVICE_CATEGORY_META[info.category];
  const flows = Number(node.event_count || 0);
  const alerts = Number(node.alert_count || 0);
  const proto = (node.protocol ?? "tcp").toUpperCase();

  return (
    <button
      type="button"
      onClick={() => onSelect(node)}
      className={cx(
        "group flex w-full items-center gap-3 rounded px-3 py-1.5 text-left transition-colors",
        isSelected
          ? "bg-primary/10 ring-1 ring-inset ring-primary/30"
          : "hover:bg-surface-2/50",
      )}
    >
      {/* Category dot */}
      <span
        className="h-2 w-2 shrink-0 rounded-full"
        style={{ backgroundColor: meta.color }}
        title={meta.label}
      />

      {/* Service name */}
      <span className="w-28 shrink-0 truncate text-[12.5px] font-semibold text-foreground">
        {info.name}
      </span>

      {/* Port / protocol */}
      <code
        className="w-[76px] shrink-0 font-mono text-[11px] text-muted-foreground"
        title={`${String(node.metadata?.dst_ip ?? node.ip ?? "")}:${node.port ?? "?"}`}
      >
        :{node.port ?? "?"}/{proto}
      </code>

      {/* Activity bar */}
      <FlowBar flows={flows} maxFlows={maxFlows} color={meta.color} />

      {/* Flow count */}
      <span className="w-14 shrink-0 text-right font-mono text-[11px] tabular-nums text-muted-foreground">
        {fmtFlows(flows)}
      </span>

      {/* Last seen */}
      <span className="w-[52px] shrink-0 text-right text-[10.5px] text-muted-foreground/55">
        {formatTopologyTimestamp(node.last_seen_at)}
      </span>

      {/* Alert badge */}
      <span className="w-12 shrink-0 text-right">
        {alerts > 0 ? (
          <span className="inline-flex items-center gap-0.5 rounded-full bg-[#F87171]/15 px-1.5 py-0.5 text-[10px] font-bold text-[#F87171]">
            ⚠ {alerts}
          </span>
        ) : (
          <span className="text-[10px] text-muted-foreground/30">—</span>
        )}
      </span>
    </button>
  );
}

function HostGroupCard({
  group,
  maxFlows,
  selectedKey,
  onSelect,
}: {
  group: HostGroup;
  maxFlows: number;
  selectedKey: string | null;
  onSelect: (node: TopologyNode) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const shown = expanded ? group.services : group.services.slice(0, ROWS_COLLAPSED);
  const hidden = group.services.length - ROWS_COLLAPSED;

  // Collect unique categories for the host header badges
  const cats = [
    ...new Set(
      group.services.map(
        (s) => resolveServiceInfo(s.port, s.protocol, s.metadata).category,
      ),
    ),
  ].slice(0, 5);

  return (
    <div className="overflow-hidden rounded-lg border border-border/60 bg-background/30">
      {/* Host header */}
      <div className="flex items-center justify-between gap-3 border-b border-border/50 bg-surface-2/70 px-3 py-2.5">
        <div className="flex min-w-0 items-center gap-2.5">
          <div className="flex shrink-0 gap-1">
            {cats.map((cat) => {
              const m = SERVICE_CATEGORY_META[cat as keyof typeof SERVICE_CATEGORY_META] ?? SERVICE_CATEGORY_META.other;
              return (
                <span
                  key={cat}
                  className="shrink-0"
                  title={m.label}
                  style={{ color: m.color }}
                >
                  <CategoryIcon category={cat} color={m.color} />
                </span>
              );
            })}
          </div>
          <span className="min-w-0 truncate text-[13px] font-semibold text-foreground">
            {group.hostLabel !== group.hostIp ? group.hostLabel : ""}
          </span>
          <code className="shrink-0 font-mono text-[11px] text-muted-foreground">
            {group.hostIp === "__unknown__" ? "unknown host" : group.hostIp}
          </code>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {group.totalAlerts > 0 && (
            <span className="rounded-full bg-[#F87171]/15 px-2 py-0.5 text-[10.5px] font-bold text-[#F87171]">
              ⚠ {group.totalAlerts} alert{group.totalAlerts !== 1 ? "s" : ""}
            </span>
          )}
          <span className="text-[11px] text-muted-foreground">
            {group.services.length} service{group.services.length !== 1 ? "s" : ""}
          </span>
        </div>
      </div>

      {/* Table header */}
      <div className="flex items-center gap-3 border-b border-border/30 px-3 py-1 text-[10px] uppercase tracking-[0.08em] text-muted-foreground/50">
        <span className="w-2 shrink-0" />
        <span className="w-28 shrink-0">Service</span>
        <span className="w-[76px] shrink-0">Port</span>
        <span className="w-20 shrink-0">Activity</span>
        <span className="w-14 shrink-0 text-right">Flows</span>
        <span className="w-[52px] shrink-0 text-right">Seen</span>
        <span className="w-12 shrink-0 text-right">Alerts</span>
      </div>

      {/* Service rows */}
      <div className="py-0.5">
        {shown.map((svc) => (
          <ServiceRow
            key={svc.node_key}
            node={svc}
            maxFlows={maxFlows}
            onSelect={onSelect}
            isSelected={selectedKey === svc.node_key}
          />
        ))}
      </div>

      {/* Expand/collapse */}
      {group.services.length > ROWS_COLLAPSED && (
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          className="flex w-full items-center justify-center gap-1 border-t border-border/30 py-1.5 text-[11px] text-muted-foreground/60 transition-colors hover:bg-surface-2/40 hover:text-muted-foreground"
        >
          {expanded ? (
            <>
              <span>▲</span> Show less
            </>
          ) : (
            <>
              <span>▼</span> {hidden} more service{hidden !== 1 ? "s" : ""}
            </>
          )}
        </button>
      )}
    </div>
  );
}

function CategoryGroupCard({
  group,
  maxFlows,
  selectedKey,
  onSelect,
}: {
  group: CategoryGroup;
  maxFlows: number;
  selectedKey: string | null;
  onSelect: (node: TopologyNode) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const meta = SERVICE_CATEGORY_META[group.category as keyof typeof SERVICE_CATEGORY_META] ?? SERVICE_CATEGORY_META.other;
  const shown = expanded ? group.services : group.services.slice(0, ROWS_COLLAPSED);
  const hidden = group.services.length - ROWS_COLLAPSED;

  return (
    <div className="overflow-hidden rounded-lg border border-border/60 bg-background/30"
      style={{ borderLeftColor: meta.color, borderLeftWidth: 2 }}>
      {/* Category header */}
      <div
        className="flex items-center justify-between gap-3 border-b px-3 py-2.5"
        style={{ borderColor: "rgba(0,0,0,0)", backgroundColor: meta.bg }}
      >
        <div className="flex items-center gap-2">
          <span style={{ color: meta.color }}>
            <CategoryIcon category={group.category} color={meta.color} />
          </span>
          <span className="text-[13px] font-bold" style={{ color: meta.color }}>
            {meta.label}
          </span>
        </div>
        <div className="flex items-center gap-3 text-[11px] text-muted-foreground">
          <span className="tabular-nums">{fmtFlows(group.totalFlows)} flows</span>
          <span>{group.services.length} service{group.services.length !== 1 ? "s" : ""}</span>
        </div>
      </div>

      {/* Table header */}
      <div className="flex items-center gap-3 border-b border-border/30 px-3 py-1 text-[10px] uppercase tracking-[0.08em] text-muted-foreground/50">
        <span className="w-2 shrink-0" />
        <span className="w-28 shrink-0">Service</span>
        <span className="w-[76px] shrink-0">Port</span>
        <span className="w-20 shrink-0">Activity</span>
        <span className="w-14 shrink-0 text-right">Flows</span>
        <span className="w-[52px] shrink-0 text-right">Seen</span>
        <span className="w-12 shrink-0 text-right">Alerts</span>
      </div>

      <div className="py-0.5">
        {shown.map((svc) => (
          <ServiceRow
            key={svc.node_key}
            node={svc}
            maxFlows={maxFlows}
            onSelect={onSelect}
            isSelected={selectedKey === svc.node_key}
          />
        ))}
      </div>

      {group.services.length > ROWS_COLLAPSED && (
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          className="flex w-full items-center justify-center gap-1 border-t border-border/30 py-1.5 text-[11px] text-muted-foreground/60 transition-colors hover:bg-surface-2/40 hover:text-muted-foreground"
        >
          {expanded ? (
            <><span>▲</span> Show less</>
          ) : (
            <><span>▼</span> {hidden} more</>
          )}
        </button>
      )}
    </div>
  );
}

// ─── Summary stats strip ──────────────────────────────────────────────────────

function SummaryStrip({ graph }: { graph: TopologyGraph }) {
  const services = graph.nodes.filter((n) => n.node_type === "service");
  const active = services.filter((s) => !s.is_stale).length;
  const withAlerts = services.filter((s) => Number(s.alert_count || 0) > 0).length;
  const catCount = new Set(
    services.map((s) => resolveServiceInfo(s.port, s.protocol, s.metadata).category),
  ).size;
  const totalFlows = services.reduce((s, n) => s + Number(n.event_count || 0), 0);

  const stats = [
    { label: "Services", value: services.length },
    { label: "Active", value: active },
    { label: "Categories", value: catCount },
    { label: "Total Flows", value: fmtFlows(totalFlows) },
    withAlerts > 0 ? { label: "With Alerts", value: withAlerts, warn: true } : null,
  ].filter(Boolean) as { label: string; value: string | number; warn?: boolean }[];

  return (
    <div className="flex flex-wrap gap-4 border-b border-border/50 px-4 py-2.5 text-[11px]">
      {stats.map((s) => (
        <div key={s.label} className="flex items-baseline gap-1.5">
          <span className={cx("tabular-nums font-bold text-sm", s.warn ? "text-[#F87171]" : "text-foreground")}>
            {s.value}
          </span>
          <span className="text-muted-foreground">{s.label}</span>
        </div>
      ))}
    </div>
  );
}

// ─── Main panel ───────────────────────────────────────────────────────────────

export function NetworkTopologyServicesPanel({
  graph,
  loading,
  selectedKey,
  onSelectService,
}: {
  graph: TopologyGraph | null;
  loading?: boolean;
  selectedKey?: string | null;
  onSelectService: (node: TopologyNode) => void;
}) {
  const [view, setView] = useState<"host" | "category">("host");
  const [search, setSearch] = useState("");

  const hostGroups = useMemo(
    () => (graph ? buildHostGroups(graph) : []),
    [graph],
  );
  const categoryGroups = useMemo(
    () => (graph ? buildCategoryGroups(graph) : []),
    [graph],
  );

  const allServices = graph?.nodes.filter((n) => n.node_type === "service") ?? [];
  const maxFlows = Math.max(1, ...allServices.map((s) => Number(s.event_count || 0)));

  const q = search.toLowerCase().trim();

  const filteredHostGroups = useMemo(() => {
    if (!q) return hostGroups;
    return hostGroups
      .map((g) => ({
        ...g,
        services: g.services.filter((s) => {
          const info = resolveServiceInfo(s.port, s.protocol, s.metadata);
          return (
            info.name.toLowerCase().includes(q) ||
            info.category.toLowerCase().includes(q) ||
            String(s.port ?? "").includes(q) ||
            (s.ip ?? "").includes(q) ||
            (g.hostIp).includes(q) ||
            (g.hostLabel).toLowerCase().includes(q)
          );
        }),
      }))
      .filter((g) => g.services.length > 0);
  }, [hostGroups, q]);

  const filteredCategoryGroups = useMemo(() => {
    if (!q) return categoryGroups;
    return categoryGroups
      .map((g) => ({
        ...g,
        services: g.services.filter((s) => {
          const info = resolveServiceInfo(s.port, s.protocol, s.metadata);
          return (
            info.name.toLowerCase().includes(q) ||
            String(s.port ?? "").includes(q) ||
            (s.ip ?? "").includes(q)
          );
        }),
      }))
      .filter((g) => g.services.length > 0);
  }, [categoryGroups, q]);

  const totalServices = allServices.length;

  return (
    <Panel
      title="Services"
      subtitle="Observed listening services, identified by port, DPI, and flow patterns."
      className="min-w-0"
    >
      {/* Summary strip */}
      {graph && !loading && <SummaryStrip graph={graph} />}

      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-3 border-b border-border/50 px-4 py-2.5">
        {/* View toggle */}
        <div className="flex overflow-hidden rounded-md border border-border/60 text-[12px]">
          {(["host", "category"] as const).map((v) => (
            <button
              key={v}
              type="button"
              onClick={() => setView(v)}
              className={cx(
                "px-3 py-1 transition-colors",
                view === v
                  ? "bg-primary/15 text-primary"
                  : "text-muted-foreground hover:bg-surface-2/60",
              )}
            >
              {v === "host" ? "By Host" : "By Category"}
            </button>
          ))}
        </div>

        {/* Search */}
        <input
          type="search"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Filter by name, port, IP…"
          className="h-7 min-w-[180px] rounded-md border border-border/60 bg-background/50 px-2.5 text-[12px] text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-1 focus:ring-primary/40"
        />

        {/* Category legend */}
        {view === "category" && (
          <div className="ml-auto flex flex-wrap gap-3">
            {categoryGroups.map((g) => {
              const meta = SERVICE_CATEGORY_META[g.category as keyof typeof SERVICE_CATEGORY_META] ?? SERVICE_CATEGORY_META.other;
              return (
                <div key={g.category} className="flex items-center gap-1 text-[11px] text-muted-foreground">
                  <span style={{ color: meta.color }}><CategoryIcon category={g.category} color={meta.color} /></span>
                  <span>{meta.label}</span>
                  <span className="tabular-nums text-muted-foreground/50">·{g.services.length}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Content */}
      <div className="max-h-[640px] overflow-y-auto p-4">
        {loading && totalServices === 0 ? (
          <div className="flex items-center justify-center py-12 text-sm text-muted-foreground">
            Loading services…
          </div>
        ) : totalServices === 0 ? (
          <div className="flex flex-col items-center justify-center gap-2 py-12 text-sm text-muted-foreground">
            <span className="text-2xl opacity-30">⬡</span>
            <span>No services detected in the current topology window.</span>
            <span className="text-[12px] opacity-60">Services are inferred from inbound flows to internal hosts with known ports.</span>
          </div>
        ) : view === "host" ? (
          <div className="space-y-3">
            {filteredHostGroups.length === 0 ? (
              <div className="py-6 text-center text-sm text-muted-foreground">
                No services match &ldquo;{search}&rdquo;
              </div>
            ) : (
              filteredHostGroups.map((g) => (
                <HostGroupCard
                  key={g.hostIp}
                  group={g}
                  maxFlows={maxFlows}
                  selectedKey={selectedKey ?? null}
                  onSelect={onSelectService}
                />
              ))
            )}
          </div>
        ) : (
          <div className="space-y-3">
            {filteredCategoryGroups.length === 0 ? (
              <div className="py-6 text-center text-sm text-muted-foreground">
                No services match &ldquo;{search}&rdquo;
              </div>
            ) : (
              filteredCategoryGroups.map((g) => (
                <CategoryGroupCard
                  key={g.category}
                  group={g}
                  maxFlows={maxFlows}
                  selectedKey={selectedKey ?? null}
                  onSelect={onSelectService}
                />
              ))
            )}
          </div>
        )}
      </div>
    </Panel>
  );
}
