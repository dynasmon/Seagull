import { useAlertsPageModel } from "../hooks/useAlertsPageModel";
import { AlertsWorkspace } from "../components/AlertsWorkspace";

export default function AlertsQueuePage() {
  const model = useAlertsPageModel();
  return <AlertsWorkspace model={model} />;
}
