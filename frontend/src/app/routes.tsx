import { lazy, Suspense, useEffect } from "react";
import { Navigate, Route, Routes as RRRoutes } from "react-router-dom";

const loadLoginPage = () => import("@/features/auth/login");
const loadProtectedLayout = () => import("@/app/ProtectedLayout");

const loadOverviewPage = () => import("@/features/overview/page");
const loadAgentsPage = () => import("@/features/agents/page");
const loadEventsLayout = () => import("@/features/events/page");
const loadEventsStreamPage = () => import("@/features/events/views/stream/page");
const loadSshInsightsPage = () => import("@/features/events/views/ssh/page");
const loadProtocolIntelPage = () => import("@/features/events/views/network/page");
const loadDdosPage = () => import("@/features/events/views/ddos/page");

const loadAlertsLayout = () => import("@/features/alerts/page");
const loadAlertsQueuePage = () => import("@/features/alerts/views/queue");
const loadAlertsRulesPage = () => import("@/features/alerts/views/rules");

const loadCorrelationsLayout = () => import("@/features/correlations/page");
const loadCorrelationFindingsPage = () => import("@/features/correlations/views/findings");
const loadCorrelationRulesPage = () => import("@/features/correlations/views/rules");

const loadAttackChainPage = () => import("@/features/attack_chain/page");
const loadInvestigationsPage = () => import("@/features/investigations/page");

const loadVulnerabilitiesPage = () => import("@/features/vulnerabilities/page");
const loadVulnerabilityScansPage = () => import("@/features/vulnerabilities/scans");

const loadInventoryPage = () => import("@/features/inventory/page");
const loadSettingsPage = () => import("@/features/settings/page");
const loadAuditLayout = () => import("@/features/audit/page");
const loadAuditAdminActionsPage = () => import("@/features/audit/views/admin-actions");
const loadAuditLoginsPage = () => import("@/features/audit/views/logins");
const loadAuditChangesPage = () => import("@/features/audit/views/changes");
const loadAuditTimelinePage = () => import("@/features/audit/views/timeline");
const loadInternalLayout = () => import("@/features/internal/page");
const loadInternalDebugPage = () => import("@/features/internal/views/debug");
const loadInternalAgentsPage = () => import("@/features/internal/views/agents");
const loadInternalHealthPage = () => import("@/features/internal/views/health");

const LoginPage = lazy(loadLoginPage);
const ProtectedLayout = lazy(loadProtectedLayout);

const OverviewPage = lazy(loadOverviewPage);
const AgentsPage = lazy(loadAgentsPage);
const EventsLayout = lazy(loadEventsLayout);
const EventsStreamPage = lazy(loadEventsStreamPage);
const SshInsightsPage = lazy(loadSshInsightsPage);
const ProtocolIntelPage = lazy(loadProtocolIntelPage);
const DdosPage = lazy(loadDdosPage);

const AlertsLayout = lazy(loadAlertsLayout);
const AlertsQueuePage = lazy(loadAlertsQueuePage);
const AlertsRulesPage = lazy(loadAlertsRulesPage);

const CorrelationsLayout = lazy(loadCorrelationsLayout);
const CorrelationFindingsPage = lazy(loadCorrelationFindingsPage);
const CorrelationRulesPage = lazy(loadCorrelationRulesPage);

const AttackChainPage = lazy(loadAttackChainPage);
const InvestigationsPage = lazy(loadInvestigationsPage);

const VulnerabilitiesPage = lazy(loadVulnerabilitiesPage);
const VulnerabilityScansPage = lazy(loadVulnerabilityScansPage);

const InventoryPage = lazy(loadInventoryPage);
const SettingsPage = lazy(loadSettingsPage);
const AuditLayout = lazy(loadAuditLayout);
const AuditAdminActionsPage = lazy(loadAuditAdminActionsPage);
const AuditLoginsPage = lazy(loadAuditLoginsPage);
const AuditChangesPage = lazy(loadAuditChangesPage);
const AuditTimelinePage = lazy(loadAuditTimelinePage);
const InternalLayout = lazy(loadInternalLayout);
const InternalDebugPage = lazy(loadInternalDebugPage);
const InternalAgentsPage = lazy(loadInternalAgentsPage);
const InternalHealthPage = lazy(loadInternalHealthPage);

const routeWarmers: Array<() => Promise<unknown>> = [
  loadOverviewPage,
  loadEventsLayout,
  loadEventsStreamPage,
  loadDdosPage,
  loadAlertsLayout,
  loadVulnerabilitiesPage,
  loadInventoryPage,
  loadAuditLayout,
  loadAuditAdminActionsPage,
  loadAuditLoginsPage,
  loadAuditChangesPage,
  loadAuditTimelinePage,
  loadInternalLayout,
  loadInternalDebugPage,
  loadInternalHealthPage,
];

function Fallback() {
  return <div className="p-4 text-sm text-muted-foreground">Loading…</div>;
}

export function Routes() {
  useEffect(() => {
    let canceled = false;
    const run = () => {
      if (canceled) return;
      for (const warm of routeWarmers) {
        warm().catch(() => undefined);
      }
    };

    const w = window as Window & {
      requestIdleCallback?: (cb: () => void, opts?: { timeout: number }) => number;
      cancelIdleCallback?: (id: number) => void;
    };

    if (typeof w.requestIdleCallback === "function") {
      const id = w.requestIdleCallback(run, { timeout: 1500 });
      return () => {
        canceled = true;
        w.cancelIdleCallback?.(id);
      };
    }

    const t = window.setTimeout(run, 600);
    return () => {
      canceled = true;
      window.clearTimeout(t);
    };
  }, []);

  return (
    <Suspense fallback={<Fallback />}>
      <RRRoutes>
        <Route path="/login" element={<LoginPage />} />

        <Route element={<ProtectedLayout />}>
          <Route path="/" element={<Navigate to="/overview" replace />} />
          <Route path="/overview" element={<OverviewPage />} />
          <Route path="/agents" element={<AgentsPage />} />
          <Route path="/events" element={<EventsLayout />}>
            <Route index element={<EventsStreamPage />} />
            <Route path="ssh" element={<SshInsightsPage />} />
            <Route path="network" element={<ProtocolIntelPage />} />
            <Route path="ddos" element={<DdosPage />} />
          </Route>

          <Route path="/alerts" element={<AlertsLayout />}>
            <Route index element={<Navigate to="/alerts/queue" replace />} />
            <Route path="queue" element={<AlertsQueuePage />} />
            <Route path="rules" element={<AlertsRulesPage />} />
          </Route>

          <Route path="/correlations" element={<CorrelationsLayout />}>
            <Route index element={<Navigate to="/correlations/findings" replace />} />
            <Route path="findings" element={<CorrelationFindingsPage />} />
            <Route path="rules" element={<CorrelationRulesPage />} />
          </Route>

          <Route path="/attack-chain" element={<AttackChainPage />} />
          <Route path="/investigations" element={<InvestigationsPage />} />

          <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
          <Route path="/vulnerabilities/scans" element={<VulnerabilityScansPage />} />

          <Route path="/inventory" element={<InventoryPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="/audit" element={<AuditLayout />}>
            <Route index element={<Navigate to="/audit/admin-actions" replace />} />
            <Route path="admin-actions" element={<AuditAdminActionsPage />} />
            <Route path="logins" element={<AuditLoginsPage />} />
            <Route path="changes" element={<AuditChangesPage />} />
            <Route path="timeline" element={<AuditTimelinePage />} />
          </Route>
          <Route path="/internal" element={<InternalLayout />}>
            <Route index element={<Navigate to="/internal/debug" replace />} />
            <Route path="debug" element={<InternalDebugPage />} />
            <Route path="agents" element={<InternalAgentsPage />} />
            <Route path="health" element={<InternalHealthPage />} />
          </Route>
          <Route path="*" element={<Navigate to="/overview" replace />} />
        </Route>
      </RRRoutes>
    </Suspense>
  );
}
