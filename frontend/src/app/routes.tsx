import { Navigate, Route, Routes as RRRoutes } from "react-router-dom";

import OverviewPage from "@/features/overview/page";
import AgentsPage from "@/features/agents/page";
import EventsPage from "@/features/events/page";

import AlertsLayout from "@/features/alerts/page";
import AlertsQueuePage from "@/features/alerts/views/queue";
import AlertsRulesPage from "@/features/alerts/views/rules";
import InventoryPage from "@/features/inventory/page";
import SettingsPage from "@/features/settings/page";

export function Routes() {
  return (
    <RRRoutes>
      <Route path="/" element={<Navigate to="/overview" replace />} />
      <Route path="/overview" element={<OverviewPage />} />
      <Route path="/agents" element={<AgentsPage />} />
      <Route path="/events" element={<EventsPage />} />
      <Route path="/alerts" element={<AlertsPage />} />
      <Route path="/alerts" element={<AlertsLayout />}>
        <Route index element={<Navigate to="/alerts/queue" replace />} />
        <Route path="queue" element={<AlertsQueuePage />} />
        <Route path="rules" element={<AlertsRulesPage />} />
      </Route>
      <Route path="/inventory" element={<InventoryPage />} />
      <Route path="/settings" element={<SettingsPage />} />
      <Route path="*" element={<Navigate to="/overview" replace />} />
    </RRRoutes>
  );
}
