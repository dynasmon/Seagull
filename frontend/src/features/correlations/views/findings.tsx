import { Navigate } from "react-router-dom";

export default function CorrelationFindingsRedirect() {
  return <Navigate to="/correlations/incidents" replace />;
}
