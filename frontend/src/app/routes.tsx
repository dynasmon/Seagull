import { lazy, Suspense } from "react";
import { Navigate, Route, Routes as RRRoutes } from "react-router-dom";

const LoginPage = lazy(() => import("@/features/auth/login"));
const ProtectedLayout = lazy(() => import("@/app/ProtectedLayout"));

const OverviewPage = lazy(() => import("@/features/overview/page"));
const AgentsPage = lazy(() => import("@/features/agents/page"));
const EventsPage = lazy(() => import("@/features/events/page"));

const AlertsLayout = lazy(() => import("@/features/alerts/page"));
const AlertsQueuePage = lazy(() => import("@/features/alerts/views/queue"));
const AlertsRulesPage = lazy(() => import("@/features/alerts/views/rules"));

const CorrelationsLayout = lazy(() => import("@/features/correlations/page"));
const CorrelationFindingsPage = lazy(() => import("@/features/correlations/views/findings"));
const CorrelationRulesPage = lazy(() => import("@/features/correlations/views/rules"));

const InventoryPage = lazy(() => import("@/features/inventory/page"));
const SettingsPage = lazy(() => import("@/features/settings/page"));

function Fallback() {
  return <div className="p-4 text-sm text-muted-foreground">Loading…</div>;
}

export function Routes() {
  return (
    <Suspense fallback={<Fallback />}>
      <RRRoutes>
        <Route path="/login" element={<LoginPage />} />

        <Route element={<ProtectedLayout />}>
          <Route path="/" element={<Navigate to="/overview" replace />} />
          <Route path="/overview" element={<OverviewPage />} />
          <Route path="/agents" element={<AgentsPage />} />
          <Route path="/events" element={<EventsPage />} />
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
          <Route path="/inventory" element={<InventoryPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/overview" replace />} />
        </Route>
      </RRRoutes>
    </Suspense>
  );
}
