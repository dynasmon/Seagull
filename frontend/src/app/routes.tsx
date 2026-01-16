import { Navigate, Route, Routes as RRRoutes } from "react-router-dom";

import OverviewPage from "@/features/overview/page";
import AgentsPage from "@/features/agents/page";
import EventsPage from "@/features/events/page";
import AlertsPage from "@/features/alerts/page";
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
      <Route path="/inventory" element={<InventoryPage />} />
      <Route path="/settings" element={<SettingsPage />} />
      <Route path="*" element={<Navigate to="/overview" replace />} />
    </RRRoutes>
  );
}
