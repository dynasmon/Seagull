import { Outlet } from "react-router-dom";

import PageHeader from "@/shared/components/PageHeader";
import DetectionWorkflowRail from "@/shared/components/DetectionWorkflow";

export default function CorrelationsLayout() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Correlations"
        breadcrumb={["Detection"]}
        description="Durable incident investigations built from related detections, evidence, and lifecycle state."
        tabs={[
          { label: "Incidents", to: "/correlations/incidents" },
          { label: "Rules", to: "/correlations/rules" },
        ]}
      />

      <DetectionWorkflowRail compact />

      <Outlet />
    </div>
  );
}
