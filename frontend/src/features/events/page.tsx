import { Outlet } from "react-router-dom";

import PageHeader from "@/shared/components/PageHeader";

export default function EventsLayout() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Events"
        breadcrumb={["Telemetry"]}
        description="Fleet telemetry views: stream, SSH auth insights, and protocol intelligence derived from network evidence."
        tabs={[
          { label: "Event Stream", to: "/events" },
          { label: "SSH Insights", to: "/events/ssh" },
          { label: "Protocol Intel", to: "/events/network" }
        ]}
      />

      <Outlet />
    </div>
  );
}
