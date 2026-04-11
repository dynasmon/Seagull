import { useEffect, useMemo, useState } from "react";
import { Navigate, Outlet } from "react-router-dom";

import { useAuth } from "@/features/auth/context";
import EmptyState from "@/shared/components/EmptyState";
import PageHeader from "@/shared/components/PageHeader";

import { getRuntimeConfig } from "./api";
import RetentionCard from "./components/RetentionCard";
import { canViewAudit } from "./lib";

export default function AuditLayout() {
  const { user } = useAuth();
  const isAdmin = canViewAudit(user?.role);

  const [runtimeLoading, setRuntimeLoading] = useState(false);
  const [runtimeError, setRuntimeError] = useState<string | null>(null);
  const [runtimeConfig, setRuntimeConfig] = useState<Record<string, any> | null>(null);

  async function loadRuntime() {
    setRuntimeLoading(true);
    setRuntimeError(null);
    try {
      const out = await getRuntimeConfig();
      setRuntimeConfig(out?.config || null);
    } catch (e: any) {
      setRuntimeError(e?.message || "Failed to load runtime config");
      setRuntimeConfig(null);
    } finally {
      setRuntimeLoading(false);
    }
  }

  useEffect(() => {
    if (!isAdmin) return;
    loadRuntime();
  }, [isAdmin]);

  const security = useMemo(() => {
    return (runtimeConfig?.security || {}) as Record<string, any>;
  }, [runtimeConfig]);

  if (!user) return <Navigate to="/login" replace />;

  if (!isAdmin) {
    return (
      <div className="space-y-4">
        <PageHeader
          title="Audit & Governance"
          breadcrumb={["Admin"]}
          description="Administrative evidence is restricted to privileged users."
        />
        <div className="h-[50vh]">
          <EmptyState
            title="Access denied"
            hint="Your account does not have permission to access administrative audit evidence."
          />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Audit & Governance"
        breadcrumb={["Admin"]}
        description="Investigate administrative actions, authentication evidence and governance timeline."
        tabs={[
          { label: "Admin Actions", to: "/audit/admin-actions" },
          { label: "Logins", to: "/audit/logins" },
          { label: "Changes", to: "/audit/changes" },
          { label: "Timeline", to: "/audit/timeline" },
        ]}
      />

      <RetentionCard loading={runtimeLoading} error={runtimeError} security={security} />

      <Outlet context={{ security }} />
    </div>
  );
}
