import { Outlet } from "react-router-dom";

import PageHeader from "@/shared/components/PageHeader";

export default function InternalLayout() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Internal UX"
        breadcrumb={["Admin"]}
        description="Internal operations for technical diagnostics, agent inspection, and platform status."
        tabs={[
          { label: "Debug Dashboards", to: "/internal/debug" },
          { label: "Agent Inspector", to: "/internal/agents" },
          { label: "Health / Status", to: "/internal/health" }
        ]}
      />

      <Outlet />
    </div>
  );
}
