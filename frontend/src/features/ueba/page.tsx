import { Outlet } from "react-router-dom";

import PageHeader from "@/shared/components/PageHeader";

export default function UebaLayout() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Anomaly Detection"
        breadcrumb={["Detection & Investigation"]}
        description="Behavioral baselines and statistical anomaly detection across user and entity activity."
        tabs={[
          { label: "Anomalies", to: "/ueba/findings" },
          { label: "Detector Health", to: "/ueba/detectors" },
        ]}
      />
      <Outlet />
    </div>
  );
}
