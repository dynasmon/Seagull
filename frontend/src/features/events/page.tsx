import { Outlet } from "react-router-dom";

import PageHeader from "@/shared/components/PageHeader";

export default function EventsLayout() {
  return (
    <div className="space-y-4">
      <PageHeader
        title="Events"
        breadcrumb={["Threat Monitoring"]}
        description="Operational telemetry modules for stream triage, SSH authentication intelligence, protocol evidence, and DDoS posture."
        tabs={[
          { label: "Event Stream", to: "/events" },
          { label: "SSH Insights", to: "/events/ssh" },
          { label: "Protocol Intel", to: "/events/network" },
          { label: "DDoS", to: "/events/ddos" },
        ]}
      />

      <Outlet />
    </div>
  );
}
