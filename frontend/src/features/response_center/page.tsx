import { useAuth } from "@/features/auth/context";
import { Button } from "@/shared/components/Button";
import EmptyState from "@/shared/components/EmptyState";
import { PageHeader } from "@/shared/components/PageHeader";

import ActiveExecutionsTable from "./ActiveExecutionsTable";
import DispatchFlyout from "./DispatchFlyout";
import ExecutionDetailDrawer from "./ExecutionDetailDrawer";
import ResponseStatsStrip from "./ResponseStatsStrip";
import { useResponseCenter } from "./hooks/useResponseCenter";

export default function ResponseCenterPage() {
  const { user } = useAuth();
  const isAdmin = String(user?.role || "").toLowerCase() === "admin";
  const model = useResponseCenter({ enabled: isAdmin });

  return (
    <div className="space-y-4">
      <PageHeader
        title="Response Center"
        breadcrumb={["Alerts & Triage", "Response Center"]}
        description="Dispatch and track audited agent-side response actions."
        toolbarRight={
          isAdmin ? (
            <Button variant="primary" size="sm" onClick={model.openDispatch}>
              Dispatch action
            </Button>
          ) : null
        }
      />

      {!isAdmin ? (
        <EmptyState title="Access denied" hint="Only administrators can dispatch response actions." />
      ) : (
        <>
          <ResponseStatsStrip
            stats={model.stats}
            activeStatuses={model.filters.statuses}
            onSelect={(statuses) => model.setFilters((prev) => ({ ...prev, statuses }))}
          />

          <ActiveExecutionsTable
            executions={model.executions}
            agents={model.agents}
            catalog={model.catalog}
            filters={model.filters}
            setFilters={model.setFilters}
            refreshState={model.refreshState}
            error={model.executionsError}
            onRowClick={model.openDetail}
            onDispatch={model.openDispatch}
          />

          <DispatchFlyout
            open={model.dispatchOpen}
            onClose={model.closeDispatch}
            catalog={model.catalog}
            agents={model.agents}
            selectedActionKey={model.selectedActionKey}
            setSelectedActionKey={model.setSelectedActionKey}
            defaultAgentId={model.dispatchAgentId}
            prefillPayload={model.prefillPayload}
            onDispatched={model.reload}
            onOpenAction={(actionId) => {
              model.closeDispatch();
              model.openDetail(actionId);
            }}
          />

          <ExecutionDetailDrawer
            detailId={model.detailId}
            onClose={model.closeDetail}
            onChanged={model.reload}
            onPivot={(input) => {
              model.closeDetail();
              model.openDispatchWith(input);
            }}
          />
        </>
      )}
    </div>
  );
}
