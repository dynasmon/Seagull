export type AppNavIcon =
  | "overview"
  | "events"
  | "protocol"
  | "ssh"
  | "ddos"
  | "alerts"
  | "attack_chain"
  | "correlations"
  | "ueba"
  | "investigations"
  | "agents"
  | "inventory"
  | "vulnerabilities"
  | "exposure"
  | "network_topology"
  | "audit"
  | "settings"
  | "internal"
  | "response_center";

export type AppNavItem = {
  id: string;
  label: string;
  to: string;
  icon: AppNavIcon;
  exact?: boolean;
};

export type AppNavGroup = {
  id: string;
  label: string;
  items: AppNavItem[];
};

export type RouteBreadcrumb = {
  label: string;
  to?: string;
};

export type RouteMeta = {
  title: string;
  subtitle: string;
  breadcrumbs: RouteBreadcrumb[];
};

export const SOC_NAV_GROUPS: AppNavGroup[] = [
  {
    id: "security-overview",
    label: "Security Overview",
    items: [{ id: "overview", label: "Overview", to: "/overview", icon: "overview" }],
  },
  {
    id: "alerts-triage",
    label: "Alerts & Triage",
    items: [
      { id: "alerts", label: "Alerts", to: "/alerts", icon: "alerts" },
      { id: "correlations", label: "Correlations", to: "/correlations", icon: "correlations" },
      { id: "ueba", label: "Anomaly Detection", to: "/ueba", icon: "ueba" },
      { id: "response-center", label: "Response Center", to: "/response-center", icon: "response_center" },
    ],
  },
  {
    id: "events-hunt",
    label: "Events & Hunt",
    items: [{ id: "events", label: "Events", to: "/events", icon: "events" }],
  },
  {
    id: "entities",
    label: "Entities",
    items: [
      { id: "agents", label: "Agents", to: "/agents", icon: "agents" },
      { id: "inventory", label: "Inventory", to: "/inventory", icon: "inventory" },
    ],
  },
  {
    id: "network",
    label: "Network",
    items: [{ id: "network-topology", label: "Network Topology", to: "/network-topology", icon: "network_topology" }],
  },
  {
    id: "exposure-vulnerabilities",
    label: "Exposure & Vulnerabilities",
    items: [
      { id: "vulnerabilities", label: "Vulnerabilities", to: "/vulnerabilities", icon: "vulnerabilities" },
      { id: "exposure", label: "Exposure Graph", to: "/exposure", icon: "exposure" },
    ],
  },
  {
    id: "investigations-cases",
    label: "Investigations & Cases",
    items: [
      { id: "investigations", label: "Investigations", to: "/investigations", icon: "investigations" },
      { id: "attack-chain", label: "Attack Chains", to: "/attack-chain", icon: "attack_chain" },
    ],
  },
  {
    id: "governance-platform",
    label: "Governance & Platform",
    items: [
      { id: "audit", label: "Audit", to: "/audit", icon: "audit" },
      { id: "internal", label: "Internal", to: "/internal", icon: "internal" },
    ],
  },
  {
    id: "settings",
    label: "Settings",
    items: [{ id: "settings", label: "Settings", to: "/settings", icon: "settings" }],
  },
];

type RouteMetaEntry = {
  path: string;
  exact?: boolean;
  meta: RouteMeta;
};

const ROUTE_META_ENTRIES: RouteMetaEntry[] = [
  {
    path: "/overview",
    exact: true,
    meta: {
      title: "Overview",
      subtitle: "Realtime operational summary with health and backlog posture.",
      breadcrumbs: [{ label: "Security Overview", to: "/overview" }],
    },
  },
  {
    path: "/events/ddos",
    meta: {
      title: "DDoS",
      subtitle: "Volumetric and application-layer denial telemetry.",
      breadcrumbs: [
        { label: "Events & Hunt", to: "/events" },
        { label: "DDoS", to: "/events/ddos" },
      ],
    },
  },
  {
    path: "/events/network",
    meta: {
      title: "Protocol Intel",
      subtitle: "Protocol-level indicators and network evidence pivots.",
      breadcrumbs: [
        { label: "Events & Hunt", to: "/events" },
        { label: "Protocol Intel", to: "/events/network" },
      ],
    },
  },
  {
    path: "/events/ssh",
    meta: {
      title: "SSH Insights",
      subtitle: "Authentication outcomes, source distribution, and brute-force context.",
      breadcrumbs: [
        { label: "Events & Hunt", to: "/events" },
        { label: "SSH Insights", to: "/events/ssh" },
      ],
    },
  },
  {
    path: "/events",
    meta: {
      title: "Events",
      subtitle: "Primary telemetry stream with filterable investigation pivots.",
      breadcrumbs: [
        { label: "Events & Hunt", to: "/events" },
      ],
    },
  },
  {
    path: "/alerts/rules",
    meta: {
      title: "Alert Rules",
      subtitle: "Operational rule catalog and runtime status.",
      breadcrumbs: [
        { label: "Alerts & Triage" },
        { label: "Alerts", to: "/alerts/queue" },
        { label: "Rules", to: "/alerts/rules" },
      ],
    },
  },
  {
    path: "/alerts",
    meta: {
      title: "Alerts",
      subtitle: "Triage queue and lifecycle tracking for detections.",
      breadcrumbs: [
        { label: "Alerts & Triage" },
        { label: "Alerts", to: "/alerts/queue" },
      ],
    },
  },
  {
    path: "/correlations/rules",
    meta: {
      title: "Correlation Rules",
      subtitle: "Rule definitions and signal-composition controls.",
      breadcrumbs: [
        { label: "Alerts & Triage" },
        { label: "Correlations", to: "/correlations/incidents" },
        { label: "Rules", to: "/correlations/rules" },
      ],
    },
  },
  {
    path: "/correlations/incidents",
    meta: {
      title: "Correlation Incidents",
      subtitle: "Durable incident queue with lifecycle, evidence, and MITRE context.",
      breadcrumbs: [
        { label: "Alerts & Triage" },
        { label: "Correlations", to: "/correlations/incidents" },
      ],
    },
  },
  {
    path: "/correlations",
    meta: {
      title: "Correlations",
      subtitle: "Durable incident investigations across detections and telemetry sources.",
      breadcrumbs: [
        { label: "Alerts & Triage" },
        { label: "Correlations", to: "/correlations/incidents" },
      ],
    },
  },
  {
    path: "/ueba/detectors",
    meta: {
      title: "Detector Health",
      subtitle: "Behavioral detector status, run history, and baseline maturity.",
      breadcrumbs: [
        { label: "Alerts & Triage" },
        { label: "Anomaly Detection", to: "/ueba/findings" },
        { label: "Detector Health", to: "/ueba/detectors" },
      ],
    },
  },
  {
    path: "/ueba",
    meta: {
      title: "Anomaly Detection",
      subtitle: "Behavioral baselines and statistical anomaly detection across user and entity activity.",
      breadcrumbs: [
        { label: "Alerts & Triage" },
        { label: "Anomaly Detection", to: "/ueba/findings" },
      ],
    },
  },
  {
    path: "/attack-chain",
    meta: {
      title: "Attack Chains",
      subtitle: "Kill-chain progression and contextual stage evidence.",
      breadcrumbs: [
        { label: "Investigations & Cases" },
        { label: "Attack Chains", to: "/attack-chain" },
      ],
    },
  },
  {
    path: "/investigations",
    meta: {
      title: "Investigations",
      subtitle: "Workspace-centric case management and evidence timelines.",
      breadcrumbs: [
        { label: "Investigations & Cases" },
        { label: "Investigations", to: "/investigations" },
      ],
    },
  },
  {
    path: "/vulnerabilities/scans",
    meta: {
      title: "Vulnerability Scans",
      subtitle: "Scan execution history and pipeline outcomes.",
      breadcrumbs: [
        { label: "Exposure & Vulnerabilities" },
        { label: "Vulnerabilities", to: "/vulnerabilities" },
        { label: "Scans", to: "/vulnerabilities/scans" },
      ],
    },
  },
  {
    path: "/vulnerabilities",
    meta: {
      title: "Vulnerabilities",
      subtitle: "Exposure inventory with package, host, and severity context.",
      breadcrumbs: [
        { label: "Exposure & Vulnerabilities" },
        { label: "Vulnerabilities", to: "/vulnerabilities" },
      ],
    },
  },
  {
    path: "/exposure",
    meta: {
      title: "Exposure Graph",
      subtitle: "Asset risk, evidence relationships, and attack-path prioritization.",
      breadcrumbs: [
        { label: "Exposure & Vulnerabilities" },
        { label: "Exposure Graph", to: "/exposure" },
      ],
    },
  },
  {
    path: "/network-topology",
    meta: {
      title: "Network Topology",
      subtitle: "Internal network map, observed flows, services, and security context.",
      breadcrumbs: [
        { label: "Network" },
        { label: "Network Topology", to: "/network-topology" },
      ],
    },
  },
  {
    path: "/agents",
    meta: {
      title: "Agents",
      subtitle: "Endpoint health, heartbeat, and control-plane status.",
      breadcrumbs: [
        { label: "Entities" },
        { label: "Agents", to: "/agents" },
      ],
    },
  },
  {
    path: "/response-center",
    meta: {
      title: "Response Center",
      subtitle: "Dispatch and track audited agent-side response actions.",
      breadcrumbs: [
        { label: "Alerts & Triage" },
        { label: "Response Center", to: "/response-center" },
      ],
    },
  },
  {
    path: "/inventory",
    meta: {
      title: "Inventory",
      subtitle: "Fleet software, host, and metadata inventory.",
      breadcrumbs: [
        { label: "Entities" },
        { label: "Inventory", to: "/inventory" },
      ],
    },
  },
  {
    path: "/audit/logins",
    meta: {
      title: "Audit Logins",
      subtitle: "Authentication timeline and portal access events.",
      breadcrumbs: [
        { label: "Governance & Platform" },
        { label: "Audit", to: "/audit/admin-actions" },
        { label: "Logins", to: "/audit/logins" },
      ],
    },
  },
  {
    path: "/audit/changes",
    meta: {
      title: "Audit Changes",
      subtitle: "Configuration and state-change audit records.",
      breadcrumbs: [
        { label: "Governance & Platform" },
        { label: "Audit", to: "/audit/admin-actions" },
        { label: "Changes", to: "/audit/changes" },
      ],
    },
  },
  {
    path: "/audit/timeline",
    meta: {
      title: "Audit Timeline",
      subtitle: "Chronological audit overview across platform events.",
      breadcrumbs: [
        { label: "Governance & Platform" },
        { label: "Audit", to: "/audit/admin-actions" },
        { label: "Timeline", to: "/audit/timeline" },
      ],
    },
  },
  {
    path: "/audit",
    meta: {
      title: "Audit",
      subtitle: "Administrative and authentication governance evidence.",
      breadcrumbs: [
        { label: "Governance & Platform" },
        { label: "Audit", to: "/audit/admin-actions" },
      ],
    },
  },
  {
    path: "/settings",
    meta: {
      title: "Settings",
      subtitle: "Portal and platform configuration controls.",
      breadcrumbs: [
        { label: "Settings", to: "/settings" },
      ],
    },
  },
  {
    path: "/internal/observability",
    meta: {
      title: "Observability",
      subtitle: "Prometheus-derived platform metrics: HTTP, ingest, detection, alerts, and workers.",
      breadcrumbs: [
        { label: "Governance & Platform" },
        { label: "Internal", to: "/internal/debug" },
        { label: "Observability", to: "/internal/observability" },
      ],
    },
  },
  {
    path: "/internal/health",
    meta: {
      title: "Internal Health",
      subtitle: "Operational diagnostics and service-level health views.",
      breadcrumbs: [
        { label: "Governance & Platform" },
        { label: "Internal", to: "/internal/debug" },
        { label: "Health", to: "/internal/health" },
      ],
    },
  },
  {
    path: "/internal/agents",
    meta: {
      title: "Internal Agents",
      subtitle: "Agent inspector and troubleshooting diagnostics.",
      breadcrumbs: [
        { label: "Governance & Platform" },
        { label: "Internal", to: "/internal/debug" },
        { label: "Agents", to: "/internal/agents" },
      ],
    },
  },
  {
    path: "/internal",
    meta: {
      title: "Internal",
      subtitle: "Engineering diagnostics and platform internals.",
      breadcrumbs: [
        { label: "Governance & Platform" },
        { label: "Internal", to: "/internal/debug" },
      ],
    },
  },
  {
    path: "/",
    exact: true,
    meta: {
      title: "Overview",
      subtitle: "Realtime operational summary with health and backlog posture.",
      breadcrumbs: [{ label: "Security Overview", to: "/overview" }],
    },
  },
];

const DEFAULT_ROUTE_META: RouteMeta = {
  title: "Seagull",
  subtitle: "Security operations portal",
  breadcrumbs: [{ label: "Security Overview", to: "/overview" }],
};

function matchesPath(pathname: string, entry: RouteMetaEntry): boolean {
  if (entry.exact) return pathname === entry.path;
  return pathname === entry.path || pathname.startsWith(`${entry.path}/`);
}

const ROUTE_META_BY_PRIORITY = [...ROUTE_META_ENTRIES].sort((a, b) => b.path.length - a.path.length);

export function resolveRouteMeta(pathname: string): RouteMeta {
  const safePath = (pathname || "/").trim() || "/";
  const found = ROUTE_META_BY_PRIORITY.find((entry) => matchesPath(safePath, entry));
  return found?.meta ?? DEFAULT_ROUTE_META;
}
