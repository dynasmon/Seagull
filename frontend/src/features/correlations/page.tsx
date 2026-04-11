import { Outlet } from "react-router-dom";

import PageHeader from "@/shared/components/PageHeader";
import DetectionWorkflowRail from "@/shared/components/DetectionWorkflow";

export default function CorrelationsLayout() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Correlations"
        breadcrumb={["Detection"]}
        description={
          "Correlate multiple low-level alerts into higher-level incidents (multi-step attack analysis)."
        }
        tabs={[
          { label: "Findings", to: "/correlations/findings" },
          { label: "Rules", to: "/correlations/rules" },
        ]}
      />

      <DetectionWorkflowRail compact />

      <Outlet />
    </div>
  );
}
